use crate::{behaviour::MyBehaviour, gossip::Topic, rpc::Rpc};
use async_trait::async_trait;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder, identify,
    identity::Keypair,
    kad::{self, Mode},
    noise, ping, tcp, yamux,
};

use libp2p_gossipsub::{self as gossipsub, IdentTopic, MessageAuthenticity, MessageId};

use std::{
    collections::hash_map::DefaultHasher,
    error::Error,
    hash::{Hash, Hasher},
    str::SplitWhitespace,
    time::Duration,
};
use tracing::info;

pub struct BootNode(Multiaddr);

// TODO(ECLIPSE):
// A single bootstrap node is a weak point.
// Later recommend:
// - multiple bootstrap nodes
// - different subnets / operators
// - diverse entry points
//
// TODO(TRUST):
// Bootstrap node may later help seed initial trust / admission policy,
// but it should not be a permanent centralized authority unless intended.

pub enum RpcAction {
    Ping,
    RoutingTable,
}

impl BootNode {
    pub fn new(address: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(Self(address.parse::<Multiaddr>()?))
    }
}

#[async_trait]
impl Rpc for BootNode {
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

                let mut kad_cfg = kad::Config::new(ipfs_proto_name.clone());
                kad_cfg.set_query_timeout(Duration::from_secs(60));
                kad_cfg.set_periodic_bootstrap_interval(Some(Duration::from_secs(300)));

                // TODO(CHURN):
                // Periodic bootstrap is only one piece.
                // Still missing:
                // - bucket refresh of stale ranges
                // - republish of records
                // - expiration / refresh policy
                // - availability strategy under churn

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
                    .validation_mode(libp2p_gossipsub::ValidationMode::Strict)
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

        swarm.behaviour_mut().kad.set_mode(Some(Mode::Server));
        swarm.listen_on(self.0)?;

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
            }

            RpcAction::RoutingTable => {
                info!(
                    "Current state of the routing table: {:?}",
                    swarm.connected_peers().collect::<Vec<&PeerId>>(),
                );
            }
        }

        Ok(())
    }
}
