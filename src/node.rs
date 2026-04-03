use crate::{
    behaviour::MyBehaviour,
    gossip::Topic,
    rpc::{LISTEN_ON, Rpc},
};
use async_trait::async_trait;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder, identify,
    identity::Keypair,
    kad::{self, K_VALUE, Mode},
    noise, ping, tcp, yamux,
};
use libp2p_gossipsub::{
    self as gossipsub, IdentTopic, MessageAuthenticity, MessageId, ValidationMode,
};
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
    // TODO(TRUST + ECLIPSE + SYBIL):
    // Later add local policy state here or in a separate manager:
    // - trusted peers
    // - quarantined peers
    // - peer score cache
    // - admission policy
}

pub enum RpcAction {
    Ping,
    Store,
    FindNode,
    FindValue,
    RoutingTable,
    Transaction,
    Block,
    Metadata,
    Reputation,
    Suspicious,
    Liveness,
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
            "ROUTING_TABLE" => Some(RpcAction::RoutingTable),
            "GOSSIP_TRANSACTION" => Some(RpcAction::Transaction),
            "GOSSIP_BLOCK" => Some(RpcAction::Block),
            "GOSSIP_META" => Some(RpcAction::Metadata),
            "GOSSIP_REPUTATION" => Some(RpcAction::Reputation),
            "GOSSIP_SUSPICIOUS" => Some(RpcAction::Suspicious),
            "GOSSIP_LIVENESS" => Some(RpcAction::Liveness),
            _ => None,
        }
    }

    async fn init(
        self,
        ipfs_proto_name: StreamProtocol,
        key: Keypair,
    ) -> Result<Swarm<MyBehaviour>, Box<dyn Error + Send + Sync>> {
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

                // all default values that can be ommited. explicit for development
                let mut kad_cfg = kad::Config::new(ipfs_proto_name.clone());
                kad_cfg.set_query_timeout(Duration::from_secs(60));
                kad_cfg.set_periodic_bootstrap_interval(Some(Duration::from_secs(300)));
                kad_cfg.set_record_ttl(Some(Duration::from_secs(36 * 60 * 60)));
                kad_cfg.set_replication_interval(Some(Duration::from_secs(60 * 60)));
                kad_cfg.set_publication_interval(Some(Duration::from_secs(24 * 60 * 60)));
                kad_cfg.set_replication_factor(K_VALUE);
                kad_cfg.disjoint_query_paths(true);

                // TODO(CHURN):
                // Also define / document:
                // - record TTL / expiration
                // - republish interval
                // - bucket refresh interval
                // - replication factor
                //
                // Right now only periodic bootstrap exists, which is not enough.

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

                // TODO(LEDGER SUPPORT):
                // Add anti-spam controls to gossip:
                // - message size bounds
                // - rate limiting
                // - per-peer penalty hooks
                // - custom validation hooks per topic

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
            // TODO(ECLIPSE):
            // Bootstrap nodes are trusted entry points for now, but long term:
            // - use multiple bootstrap peers
            // - prefer disjoint / diverse bootstrap origins
            // - avoid over-reliance on a single entry path
            swarm
                .behaviour_mut()
                .kad
                .add_address(bootstrap_id, bootstrap_addr.clone());
            swarm.dial(*bootstrap_id)?;
        }

        swarm.behaviour_mut().kad.set_mode(Some(Mode::Server));
        swarm.listen_on(LISTEN_ON.parse()?)?;

        Ok(swarm)
    }

    fn match_action(
        args: &mut SplitWhitespace,
        swarm: &mut Swarm<MyBehaviour>,
        rpc: RpcAction,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        match rpc {
            RpcAction::Ping => {
                let address = Self::arg_parse(args)?.parse::<Multiaddr>()?;
                swarm.dial(address)?;

                // TODO(TRUST):
                // Prefer dialing known / trusted peers first when there is a choice.
            }

            RpcAction::Store => {
                let key = kad::RecordKey::new(&Self::arg_parse(args)?);
                let value = Self::arg_parse(args)?.as_bytes().to_vec();

                let record = kad::Record {
                    key,
                    value,
                    publisher: None,
                    expires: None,
                };

                // TODO(CHURN):
                // expires: None is too weak for churn handling.
                // Later:
                // - set explicit expiration
                // - track ownership of locally published records
                // - republish before expiration
                // - configure replication factor / quorum

                swarm
                    .behaviour_mut()
                    .kad
                    .put_record(record, kad::Quorum::N(NonZeroUsize::new(3).unwrap()))?;

                // TODO(TRUST):
                // Quorum::One is simple but weak.
                // Later prefer:
                // - quorum based on replication policy
                // - trusted peers when selecting storage targets
            }

            RpcAction::FindNode => {
                let peer = Self::arg_parse(args)?.parse::<PeerId>()?;
                swarm.behaviour_mut().kad.get_closest_peers(peer);

                // TODO(ECLIPSE + BYZANTINE):
                // Later perform parallel / disjoint lookup paths and compare answers.
            }

            RpcAction::FindValue => {
                let key = kad::RecordKey::new(&Self::arg_parse(args)?);
                swarm.behaviour_mut().kad.get_record(key);

                // TODO(BYZANTINE):
                // Later require stronger confidence than "first answer wins".
            }

            RpcAction::RoutingTable => {
                info!(
                    "Current state of the routing table: {:?}",
                    swarm.connected_peers().collect::<Vec<&PeerId>>(),
                );

                // TODO(TRUST + ECLIPSE):
                // Expose richer diagnostics later:
                // - peer score
                // - age
                // - subnet
                // - suspicion state
                // - bucket diversity status
            }

            RpcAction::Transaction => {
                let payload = Self::remaining_args(args)?.into_bytes();
                swarm.behaviour_mut().gossip.publish(
                    libp2p_gossipsub::IdentTopic::new(Topic::TRANSACTIONS),
                    payload,
                )?;

                // TODO(LEDGER SUPPORT):
                // Only overlay dissemination now.
                // Later add:
                // - spam controls
                // - schema validation
                // - content-address indexing hook
            }

            RpcAction::Block => {
                let payload = Self::arg_parse(args)?.into_bytes();
                swarm
                    .behaviour_mut()
                    .gossip
                    .publish(libp2p_gossipsub::IdentTopic::new(Topic::BLOCKS), payload)?;

                // TODO(LEDGER SUPPORT):
                // Announcements should point to retrievable block content later.
            }

            RpcAction::Metadata => {
                let payload = Self::arg_parse(args)?.into_bytes();
                swarm.behaviour_mut().gossip.publish(
                    libp2p_gossipsub::IdentTopic::new(Topic::OVERLAY_META),
                    payload,
                )?;

                // TODO(ANTI-IMPERSONATION):
                // Publish signed metadata, not plain unsigned JSON.
            }

            RpcAction::Reputation => {
                let payload = Self::arg_parse(args)?.into_bytes();
                swarm.behaviour_mut().gossip.publish(
                    libp2p_gossipsub::IdentTopic::new(Topic::PEER_REPUTATION),
                    payload,
                )?;

                // TODO(TRUST):
                // Remote reputation reports must be bounded and validated.
            }

            RpcAction::Suspicious => {
                let payload = Self::arg_parse(args)?.into_bytes();
                swarm.behaviour_mut().gossip.publish(
                    libp2p_gossipsub::IdentTopic::new(Topic::SUSPICIOUS_PEERS),
                    payload,
                )?;

                // TODO(TRUST + BYZANTINE):
                // Suspicion reports should not directly blacklist peers.
                // They should feed a local threshold-based suspicion model.
            }

            RpcAction::Liveness => {
                let payload = Self::arg_parse(args)?.into_bytes();
                swarm
                    .behaviour_mut()
                    .gossip
                    .publish(libp2p_gossipsub::IdentTopic::new(Topic::LIVENESS), payload)?;

                // TODO(CHURN):
                // Use this as auxiliary liveness information only.
            }
        }

        Ok(())
    }
}
