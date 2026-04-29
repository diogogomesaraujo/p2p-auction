use crate::{behaviour::DhtBehaviour, rpc::DhtRpc, runtime::Runtime, state::State, topic::topic};
use async_trait::async_trait;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, SwarmBuilder, identify,
    identity::Keypair,
    kad::{self, Caching, Config, K_VALUE, Mode, store::MemoryStore},
    noise, ping, tcp, yamux,
};
use libp2p_gossipsub::{
    self as gossipsub, IdentTopic, MessageAuthenticity, MessageId, PeerScoreParams,
    PeerScoreThresholds, TopicScoreParams, ValidationMode,
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

                /* Kademlia */

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

                /* Ping */

                let ping = ping::Behaviour::new(
                    ping::Config::new()
                        .with_interval(Duration::from_secs(10))
                        .with_timeout(Duration::from_secs(3)),
                );

                /* Identify */

                let identify = identify::Behaviour::new(identify::Config::new(
                    ipfs_proto_name.to_string(),
                    key.public(),
                ));

                /* Gossip */

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

                // placeholder
                let topic_score = TopicScoreParams::default();

                // let mut topic_score = TopicScoreParams {
                //     topic_weight: (),
                //     time_in_mesh_weight: (),
                //     time_in_mesh_quantum: (),
                //     time_in_mesh_cap: (),
                //     first_message_deliveries_weight: (),
                //     first_message_deliveries_decay: (),
                //     first_message_deliveries_cap: (),
                //     mesh_message_deliveries_weight: (),
                //     mesh_message_deliveries_decay: (),
                //     mesh_message_deliveries_cap: (),
                //     mesh_message_deliveries_threshold: (),
                //     mesh_message_deliveries_window: (),
                //     mesh_message_deliveries_activation: (),
                //     mesh_failure_penalty_weight: (),
                //     mesh_failure_penalty_decay: (),
                //     invalid_message_deliveries_weight: (),
                //     invalid_message_deliveries_decay: (),
                // };

                // placeholder
                let mut peer_score = PeerScoreParams::default();

                // let mut peer_score = PeerScoreParams {
                //     topics: (),
                //     topic_score_cap: (),
                //     app_specific_weight: (),
                //     ip_colocation_factor_weight: (),
                //     ip_colocation_factor_threshold: (),
                //     ip_colocation_factor_whitelist: (),
                //     behaviour_penalty_weight: (),
                //     behaviour_penalty_threshold: (),
                //     behaviour_penalty_decay: (),
                //     decay_interval: (),
                //     decay_to_zero: (),
                //     retain_score: (),
                //     slow_peer_weight: (),
                //     slow_peer_threshold: (),
                //     slow_peer_decay: (),
                // };

                peer_score.topics.insert(
                    gossipsub::IdentTopic::new(topic::TRANSACTIONS).hash(),
                    topic_score.clone(),
                );
                peer_score.topics.insert(
                    gossipsub::IdentTopic::new(topic::BLOCKS).hash(),
                    topic_score,
                );

                // placeholder
                let thresholds = PeerScoreThresholds::default();

                // let thresholds = PeerScoreThresholds {
                //     gossip_threshold: (),
                //     publish_threshold: (),
                //     graylist_threshold: (),
                //     accept_px_threshold: (),
                //     opportunistic_graft_threshold: (),
                // };

                gossip.with_peer_score(peer_score, thresholds)?;

                gossip.subscribe(&IdentTopic::new(topic::TRANSACTIONS))?;
                gossip.subscribe(&IdentTopic::new(topic::BLOCKS))?;

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
