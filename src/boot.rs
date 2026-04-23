use crate::{behaviour::DhtBehaviour, gossip::topic, rpc::DhtRpc, runtime::Runtime, state::State};
use async_trait::async_trait;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, SwarmBuilder, identify,
    identity::Keypair,
    kad::{self, ALPHA_VALUE, K_VALUE, Mode},
    noise, ping, tcp, yamux,
};
use libp2p_gossipsub::{
    self as gossipsub, IdentTopic, MessageAuthenticity, MessageId, ValidationMode,
};
use std::{
    collections::hash_map::DefaultHasher,
    error::Error,
    hash::{Hash, Hasher},
    str::SplitWhitespace,
    time::Duration,
};
use tracing::info;

/// Struct that represents a boot node of the network.
/// Boot nodes serve as entry points and keep track of peers currently using the network.
pub struct BootNode(Multiaddr);

pub enum RpcAction {
    Ping,
    RoutingTable,
}

impl BootNode {
    /// Function that creates a new boot node from a predetermined address.
    pub fn new(address: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(Self(address.parse::<Multiaddr>()?))
    }
}

#[async_trait]
impl DhtRpc for BootNode {
    type RpcAction = RpcAction;

    fn action_from_str(action_text: &str) -> Option<Self::RpcAction> {
        match action_text {
            "PING" => Some(RpcAction::Ping),
            "ROUTING_TABLE" => Some(RpcAction::RoutingTable),
            _ => None,
        }
    }

    async fn init(
        self,
        ipfs_proto_name: StreamProtocol,
        key: Keypair,
    ) -> Result<Runtime, Box<dyn Error + Send + Sync>> {
        let state = State::init()?;

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

                let mut kad_cfg = kad::Config::new(ipfs_proto_name.clone());
                kad_cfg.set_query_timeout(Duration::from_secs(60));
                kad_cfg.set_periodic_bootstrap_interval(Some(Duration::from_secs(300)));
                kad_cfg.set_record_ttl(Some(Duration::from_secs(36 * 60 * 60)));
                kad_cfg.set_replication_interval(Some(Duration::from_secs(60 * 60)));
                kad_cfg.set_publication_interval(Some(Duration::from_secs(24 * 60 * 60)));
                kad_cfg.set_replication_factor(K_VALUE);
                kad_cfg.disjoint_query_paths(true);
                kad_cfg.set_parallelism(ALPHA_VALUE);
                kad_cfg.set_provider_record_ttl(Some(Duration::from_secs(48 * 60 * 60)));
                kad_cfg.set_provider_publication_interval(Some(Duration::from_secs(12 * 60 * 60)));
                kad_cfg.set_caching(kad::Caching::Enabled { max_peers: 1 });

                let store = kad::store::MemoryStore::new(local_id);
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

                gossip.subscribe(&IdentTopic::new(topic::TRANSACTIONS))?;
                gossip.subscribe(&IdentTopic::new(topic::BLOCKS))?;
                gossip.subscribe(&IdentTopic::new(topic::METADATA))?;
                gossip.subscribe(&IdentTopic::new(topic::PEER_REPUTATION))?;
                gossip.subscribe(&IdentTopic::new(topic::SUSPICIOUS_PEERS))?;
                gossip.subscribe(&IdentTopic::new(topic::LIVENESS))?;

                Ok(DhtBehaviour {
                    kad,
                    ping,
                    identify,
                    gossip,
                })
            })?
            .build();

        swarm.behaviour_mut().kad.set_mode(Some(Mode::Server));
        swarm.listen_on(self.0)?;

        let mut runtime = Runtime::new(swarm, state);
        runtime.load_from_local()?;

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

            RpcAction::RoutingTable => {
                info!(
                    "Current state of the routing table: {:?}",
                    runtime.swarm.connected_peers().collect::<Vec<&PeerId>>(),
                );
            }
        }

        Ok(())
    }
}
