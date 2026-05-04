use crate::{
    behaviour::DhtBehaviour,
    blockchain::{block::Block, transaction::Transaction},
    reputation::SCORE_BLACKLIST_THRESHOLD,
    state::State,
    topic::BLOCKS,
};
use libp2p::{PeerId, Swarm};
use libp2p_gossipsub::IdentTopic;
use serde_json::to_vec;
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

    /// Function validates and appends to chain a block received over gossip protocol.
    /// If the block is valid it gossips the block.
    pub async fn accept_block(&mut self, block: Block) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.state
            .write()
            .await
            .blockchain
            .accept_block(block.clone())?;
        self.swarm
            .behaviour_mut()
            .gossip
            .publish(IdentTopic::new(BLOCKS), to_vec(&block)?)?;
        Ok(())
    }

    /// Validates and adds a transaction to the mempool.
    pub async fn submit_transaction(
        &mut self,
        transaction: Transaction,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        transaction.verify()?;
        if !self
            .state
            .read()
            .await
            .blockchain
            .transaction_pool
            .contains(&transaction)
        {
            self.state
                .write()
                .await
                .blockchain
                .transaction_pool
                .add_transaction(transaction.clone())?;
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
        if let entry = self
            .state
            .write()
            .await
            .peers
            .entry(peer_id.clone())
            .or_default()
        {
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
