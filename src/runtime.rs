use crate::reputation::SCORE_BLACKLIST_THRESHOLD;
use crate::{behaviour::Response, topic};
use crate::{
    behaviour::{DhtBehaviour, Request},
    blockchain::block::Block,
    state::State,
    topic::BLOCKS,
};
use libp2p::{PeerId, Swarm};
use libp2p::{
    StreamProtocol, SwarmBuilder, identify,
    identity::Keypair,
    kad::{self, Caching, Config, K_VALUE, Mode, store::MemoryStore},
    noise, ping,
    request_response::{self, ProtocolSupport},
    tcp, yamux,
};
use libp2p_gossipsub::IdentTopic;
use libp2p_gossipsub::{self as gossipsub, MessageAuthenticity, MessageId, ValidationMode};
use serde_json::to_vec;
use std::sync::Arc;
use std::{
    collections::hash_map::DefaultHasher,
    error::Error,
    hash::{Hash, Hasher},
    time::Duration,
};
use tokio::sync::RwLock;
use tracing::warn;

pub struct Runtime {
    pub swarm: Swarm<DhtBehaviour>,
    pub state: Arc<RwLock<State>>,
}

impl Runtime {
    pub fn new(swarm: Swarm<DhtBehaviour>, state: State) -> Self {
        Self {
            swarm,
            state: Arc::new(RwLock::new(state)),
        }
    }

    pub async fn init(
        ipfs_proto_name: StreamProtocol,
        key: Keypair,
        rpc_address: &str,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let state = State::init(rpc_address)?;

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

                gossip.subscribe(&IdentTopic::new(topic::BLOCKS))?;

                let request_response = request_response::cbor::Behaviour::<Request, Response>::new(
                    [(
                        StreamProtocol::new("/blockchain/cbor/1"),
                        ProtocolSupport::Full,
                    )],
                    request_response::Config::default(),
                );

                Ok(DhtBehaviour {
                    kad,
                    ping,
                    identify,
                    gossip,
                    request_response,
                })
            })?
            .build();

        swarm.behaviour_mut().kad.set_mode(Some(Mode::Server));

        let mut runtime = Runtime::new(swarm, state);
        let _ = runtime.swarm.behaviour_mut().kad.bootstrap();

        Ok(runtime)
    }

    pub async fn accept_block_from_gossip(
        &mut self,
        block: Block,
        peer: PeerId,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.accept_block(block, peer, true, true).await
    }

    pub async fn accept_block_from_r_r(
        &mut self,
        block: Block,
        peer: PeerId,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.accept_block(block, peer, false, false).await
    }

    /// Function validates and appends to chain a block received over gossip protocol.
    /// If the block is valid it gossips the block.
    async fn accept_block(
        &mut self,
        block: Block,
        peer: PeerId,
        rebroadcast: bool,
        request_missing: bool,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let result = self
            .state
            .write()
            .await
            .blockchain
            .accept_block(block.clone());

        match result {
            Ok(_) => {
                tracing::info!("Accepted block: {:?}", block);

                if rebroadcast {
                    self.swarm
                        .behaviour_mut()
                        .gossip
                        .publish(IdentTopic::new(BLOCKS), to_vec(&block)?)?;
                }
            }

            // Spaguetti Logic in error handling.
            // Need to implement a propper error module
            Err(e) => {
                let msg = e.to_string();

                if msg == "Already known block." {
                    return Ok(());
                }

                if msg == "The block proposed does not point to a block in the chain." {
                    self.state
                        .write()
                        .await
                        .received_blocks
                        .insert(block.hash.clone(), block.clone());

                    if request_missing {
                        self.swarm
                            .behaviour_mut()
                            .request_response
                            .send_request(&peer, Request::LongestChainHashes);
                    }
                }
            }
        }

        Ok(())
    }

    /// Adjusts a peer's application score by a given delta and
    /// sets syncs application score in gossip sub
    pub async fn adjust_score(
        &mut self,
        peer_id: &PeerId,
        delta: f64,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut state = self.state.write().await;
        let entry = state.peers.entry(peer_id.clone()).or_default();

        entry.application_score += delta;
        let score = entry.application_score;
        self.swarm
            .behaviour_mut()
            .gossip
            .set_application_score(peer_id, score);

        // ??????
        if score <= SCORE_BLACKLIST_THRESHOLD {
            warn!("Blacklisting peer {:?} (score={})", peer_id, score);
            self.swarm.behaviour_mut().gossip.blacklist_peer(peer_id);
            entry.blacklisted = true;
        }

        Ok(())
    }

    /// Replays persistent blacklist into gossipsub and bootstraps Kademlia.
    pub async fn load_from_local(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let blacklisted: Vec<PeerId> = self
            .state
            .read()
            .await
            .peers
            .iter()
            .filter_map(|(id, info)| if info.blacklisted { Some(*id) } else { None })
            .collect();

        for peer_id in blacklisted {
            self.swarm.behaviour_mut().gossip.blacklist_peer(&peer_id);
        }
        Ok(())
    }
}
