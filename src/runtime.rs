use crate::{
    behaviour::DhtBehaviour, blockchain::block::Block, reputation::SCORE_BLACKLIST_THRESHOLD,
    state::State,
};
use libp2p::{PeerId, Swarm};
use std::{error::Error, sync::Arc};
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

    pub async fn validate_blockchain(
        &mut self,
        _blocks: Vec<Block>,
    ) -> Result<State, Box<dyn Error + Send + Sync>> {
        todo!()
    }

    /// Function validates and appends to chain a block received over gossip protocol.
    /// If the block is valid it gossips the block.
    pub async fn accept_block(&mut self, block: Block) -> Result<(), Box<dyn Error + Send + Sync>> {
        let accept_block = self
            .state
            .write()
            .await
            .blockchain
            .accept_block(block.clone());

        match accept_block {
            Err(_) => {
                self.state
                    .write()
                    .await
                    .received_blocks
                    .insert(block.previous_hash.clone(), block.clone());

                tracing::warn!("Storing block temporarily: {:?}", block);
            }

            Ok(_) => {
                tracing::info!("Accepted block: {:?}", block);

                for (prev_h, block) in self.state.read().await.received_blocks.clone() {
                    let accepted_block = self
                        .state
                        .write()
                        .await
                        .blockchain
                        .accept_block(block.clone());

                    if let Ok(_) = accepted_block {
                        tracing::info!("Accepted block: {:?}", block);
                        self.state.write().await.received_blocks.remove(&prev_h);
                    }
                }
            }
        }
        Ok(())
    }

    /// Adjusts a peer's application score by a given delta, syncs it into
    /// gossipsub, and blacklists the peer if the score falls at or below
    /// the threshold.
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

        let _ = self.swarm.behaviour_mut().kad.bootstrap();
        Ok(())
    }
}
