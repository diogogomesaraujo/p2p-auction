use crate::{
    behaviour::MyBehaviour,
    gossip::{OverlayMetadata, Topic},
    rpc::{LISTEN_ON, Rpc},
    runtime::Runtime,
    state::State,
};
use async_trait::async_trait;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, SwarmBuilder, identify,
    identity::Keypair,
    kad::{
        self, Caching, Config, K_VALUE, KBucketKey, Mode, Quorum, Record, RecordKey,
        store::MemoryStore,
    },
    noise, ping, tcp, yamux,
};
use libp2p_gossipsub::{
    self as gossipsub, IdentTopic, MessageAuthenticity, MessageId, ValidationMode,
};
use serde_json::to_vec;
use std::{
    collections::hash_map::DefaultHasher,
    error::Error,
    hash::{Hash, Hasher},
    num::NonZeroUsize,
    str::SplitWhitespace,
    time::Duration,
};
use tracing::info;

pub struct Node {
    pub bootstrap_nodes: Vec<(Multiaddr, PeerId)>,
}

pub enum RpcAction {
    Ping,
    Store,
    FindNode,
    FindValue,
    StartProviding,
    FindProviders,
    RoutingTable,
    ConnectedPeers,
    Metadata,
}

impl Node {
    pub fn new(bootstrap_nodes: Vec<(Multiaddr, PeerId)>) -> Self {
        Self { bootstrap_nodes }
    }
}

#[async_trait]
impl Rpc for Node {
    type RpcAction = RpcAction;

    fn action_from_str(action_text: &str) -> Option<Self::RpcAction> {
        match action_text {
            "PING" => Some(RpcAction::Ping),
            "STORE" => Some(RpcAction::Store),
            "FIND_VALUE" => Some(RpcAction::FindValue),
            "FIND_NODE" => Some(RpcAction::FindNode),
            "START_PROVIDING" => Some(RpcAction::StartProviding),
            "FIND_PROVIDERS" => Some(RpcAction::FindProviders),
            "ROUTING_TABLE" => Some(RpcAction::RoutingTable),
            "CONNECTED_PEERS" => Some(RpcAction::ConnectedPeers),
            "GOSSIP_META" => Some(RpcAction::Metadata),
            _ => None,
        }
    }

    async fn init(
        self,
        ipfs_proto_name: StreamProtocol,
        key: Keypair,
    ) -> Result<Runtime, Box<dyn Error + Send + Sync>> {
        let state = State::load()?;

        let mut swarm = SwarmBuilder::with_existing_identity(key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_dns()?
            .with_behaviour(|key| {
                let local_id = key.public().to_peer_id();

                let mut kad_cfg = Config::new(ipfs_proto_name.clone());
                kad_cfg.set_query_timeout(Duration::from_secs(60));
                kad_cfg.set_periodic_bootstrap_interval(Some(Duration::from_secs(300)));
                kad_cfg.set_record_ttl(Some(Duration::from_secs(36 * 60 * 60)));
                kad_cfg.set_replication_interval(Some(Duration::from_secs(60 * 60)));
                kad_cfg.set_publication_interval(Some(Duration::from_secs(24 * 60 * 60)));
                kad_cfg.set_replication_factor(K_VALUE);
                kad_cfg.disjoint_query_paths(true);
                kad_cfg.set_provider_record_ttl(Some(Duration::from_secs(48 * 60 * 60)));
                kad_cfg.set_provider_publication_interval(Some(Duration::from_secs(12 * 60 * 60)));
                kad_cfg.set_caching(Caching::Enabled { max_peers: 1 });

                let store = MemoryStore::new(local_id);
                let kad = kad::Behaviour::with_config(local_id, store, kad_cfg);

                let ping = ping::Behaviour::new(
                    ping::Config::new()
                        .with_interval(Duration::from_secs(10))
                        .with_timeout(Duration::from_secs(3)),
                );

                let identify = identify::Behaviour::new(identify::Config::new(
                    ipfs_proto_name.to_string(),
                    key.public(),
                ));

                let message_id_fn = |message: &gossipsub::Message| {
                    let mut hasher = DefaultHasher::new();
                    message.data.hash(&mut hasher);
                    MessageId::from(hasher.finish().to_string())
                };

                let gossip_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(10))
                    .validation_mode(ValidationMode::Strict)
                    .message_id_fn(message_id_fn)
                    .build()?;

                let mut gossip = gossipsub::Behaviour::new(
                    MessageAuthenticity::Signed(key.clone()),
                    gossip_config,
                )?;

                gossip.subscribe(&IdentTopic::new(Topic::TRANSACTIONS))?;
                gossip.subscribe(&IdentTopic::new(Topic::BLOCKS))?;
                gossip.subscribe(&IdentTopic::new(Topic::OVERLAY_META))?;
                gossip.subscribe(&IdentTopic::new(Topic::PEER_REPUTATION))?;
                gossip.subscribe(&IdentTopic::new(Topic::SUSPICIOUS_PEERS))?;
                gossip.subscribe(&IdentTopic::new(Topic::LIVENESS))?;

                Ok(MyBehaviour {
                    kad,
                    ping,
                    identify,
                    gossip,
                })
            })?
            .build();

        for (bootstrap_addr, bootstrap_id) in &self.bootstrap_nodes {
            swarm
                .behaviour_mut()
                .kad
                .add_address(bootstrap_id, bootstrap_addr.clone());
            swarm.dial(*bootstrap_id)?;
        }

        swarm.behaviour_mut().kad.set_mode(Some(Mode::Server));
        swarm.listen_on(LISTEN_ON.parse()?)?;

        let mut runtime = Runtime::new(swarm, state);
        runtime.restore_persistent_state()?;

        Ok(runtime)
    }

    fn match_action(
        args: &mut SplitWhitespace,
        runtime: &mut Runtime,
        rpc: RpcAction,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        match rpc {
            RpcAction::Ping => {
                let address = Self::arg_parse(args)?.parse::<Multiaddr>()?;
                runtime.swarm.dial(address)?;
            }

            RpcAction::Store => {
                let key_text = Self::arg_parse(args)?;
                let value_text = Self::remaining_args(args)?;
                let key = RecordKey::new(&key_text);
                let value = value_text.as_bytes().to_vec();

                // let quorum = 3usize;
                let quorum = 1usize; // for now we are using low quorum for testing

                let record = Record {
                    key: key.clone(),
                    value: value.clone(),
                    publisher: None,
                    expires: None,
                };

                runtime.swarm.behaviour_mut().kad.put_record(
                    record,
                    Quorum::N(NonZeroUsize::new(quorum).ok_or("Quorum must be greater than zero")?),
                )?;

                runtime
                    .state
                    .persistent
                    .remember_value_record(key.to_vec(), value, quorum);
                runtime.state.persistent.save()?;
            }

            RpcAction::FindNode => {
                let peer = Self::arg_parse(args)?.parse::<PeerId>()?;
                runtime.swarm.behaviour_mut().kad.get_closest_peers(peer);
            }

            RpcAction::FindValue => {
                let key = RecordKey::new(&Self::arg_parse(args)?);
                runtime.swarm.behaviour_mut().kad.get_record(key);
            }

            RpcAction::StartProviding => {
                let key = RecordKey::new(&Self::arg_parse(args)?);
                runtime
                    .swarm
                    .behaviour_mut()
                    .kad
                    .start_providing(key.clone())?;

                runtime
                    .state
                    .persistent
                    .remember_provider_record(key.to_vec());
                runtime.state.persistent.save()?;
            }

            RpcAction::FindProviders => {
                let key = RecordKey::new(&Self::arg_parse(args)?);
                runtime.swarm.behaviour_mut().kad.get_providers(key);
            }

            RpcAction::ConnectedPeers => {
                info!(
                    "Peers currently connected: {:?}",
                    runtime.swarm.connected_peers().collect::<Vec<&PeerId>>(),
                );
            }

            RpcAction::RoutingTable => {
                let local_key = KBucketKey::from(*runtime.swarm.local_peer_id());

                for bucket in runtime.swarm.behaviour_mut().kad.kbuckets() {
                    for entry in bucket.iter() {
                        println!(
                            "Peer ID: {:?}, Distance {:?}",
                            entry.node.key.preimage(),
                            entry.node.key.distance(&local_key),
                        );
                    }
                }
            }

            RpcAction::Metadata => {
                let payload = OverlayMetadata {
                    peer_id: runtime.swarm.local_peer_id().to_string(),
                    role: Self::arg_parse(args)?,
                    supported_protocols: vec!["/p2p-auction/1.0.0".into()],
                    connected_peers: runtime.swarm.connected_peers().count(),
                };

                runtime
                    .swarm
                    .behaviour_mut()
                    .gossip
                    .publish(IdentTopic::new(Topic::OVERLAY_META), to_vec(&payload)?)?;
            }
        }

        Ok(())
    }
}
