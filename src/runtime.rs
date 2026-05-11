use crate::{
    behaviour::DhtBehaviour,
    blockchain::{
        block::Block,
        merkle::root,
        transaction::{Transaction, TransactionPool},
    },
    reputation::SCORE_BLACKLIST_THRESHOLD,
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
        blocks: Vec<Block>,
    ) -> Result<State, Box<dyn Error + Send + Sync>> {
        let mut validated = self.state.read().await.clone();

        validated.blockchain.blocks.clear();
        validated.blockchain.accounts.clear();
        validated.blockchain.transaction_pool = TransactionPool::new();

        for block in blocks {
            if !block.verify()? {
                return Err("Invalid block hash or proof-of-work.".into());
            }

            let merkle_root = root(&block.transactions)?;

            if merkle_root != block.merkle_root {
                return Err("Invalid block Merkle root.".into());
            }

            validated.blockchain.execute_transactions(&block)?;

            validated.blockchain.blocks.push(block.clone());
        }

        Ok(validated)
    }

    /// Function validates and appends to chain a block received over gossip protocol.
    /// If the block is valid it gossips the block.
    pub async fn accept_block(&mut self, block: Block) -> Result<(), Box<dyn Error + Send + Sync>> {
        let accepted_block = self
            .state
            .write()
            .await
            .blockchain
            .accept_block(block.clone());
        if let Err(e) = accepted_block {
            tracing::error!("{e}");
            self.state
                .write()
                .await
                .received_blocks
                .insert(block.previous_hash.clone(), block.clone());
            tracing::warn!("Storing block temporarily: {:?}", block);
        } else {
            tracing::info!("Accepted block: {:?}", block);
            let mut block = block.clone();
            while let Some(b) = self.state.read().await.received_blocks.get(&block.hash) {
                if let Err(_) = self.state.write().await.blockchain.accept_block(b.clone()) {
                    continue;
                }
                block = b.clone();
                tracing::info!("Accepted block: {:?}", block);
            }
        }
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
