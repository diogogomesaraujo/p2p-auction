use crate::{
    behaviour::DhtBehaviour,
    blockchain::{block::Block, transaction::Transaction},
    state::State,
    topic,
};
use libp2p::{PeerId, Swarm};
use libp2p_gossipsub::IdentTopic;
use serde_json::to_vec;
use std::error::Error;

pub struct Runtime {
    pub swarm: Swarm<DhtBehaviour>,
    pub state: State,
}

impl Runtime {
    pub fn new(swarm: Swarm<DhtBehaviour>, state: State) -> Self {
        Self { swarm, state }
    }

    /// Function validates and appends to chain a block received over gossip protocol.
    /// If the block is valid it is gossiped along.
    pub fn accept_block(&mut self, block: Block) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.state.blockchain.accept_block(block.clone())?;
        self.swarm
            .behaviour_mut()
            .gossip
            .publish(IdentTopic::new(topic::topic::BLOCKS), to_vec(&block)?)?;
        Ok(())
    }

    /// Validates and adds a transaction to the mempool, then gossips it to peers.
    pub fn submit_transaction(
        &mut self,
        transaction: Transaction,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        transaction.verify()?;
        if !self
            .state
            .blockchain
            .transaction_mempool
            .contains(&transaction)
        {
            self.state
                .blockchain
                .transaction_mempool
                .add_transaction(transaction.clone())?;
            self.swarm.behaviour_mut().gossip.publish(
                IdentTopic::new(topic::topic::TRANSACTIONS),
                to_vec(&transaction)?,
            )?;
        }
        Ok(())
    }

    /// Adjusts a peer's application score by a given delta and syncs it into gossipsub.
    pub fn adjust_score(
        &mut self,
        peer_id: &PeerId,
        delta: f64,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let entry = self.state.peers.entry(peer_id.clone()).or_default();
        entry.application_score += delta;
        self.swarm
            .behaviour_mut()
            .gossip
            .set_application_score(peer_id, entry.application_score);
        Ok(())
    }

    /// Replays persistent blacklist into gossipsub and bootstraps Kademlia.
    pub fn load_from_local(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let blacklisted: Vec<PeerId> = self
            .state
            .peers
            .iter()
            .filter_map(|(id, info)| {
                if info.blacklisted {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();

        for peer_id in blacklisted {
            self.swarm.behaviour_mut().gossip.blacklist_peer(&peer_id);
        }

        let _ = self.swarm.behaviour_mut().kad.bootstrap();
        Ok(())
    }
}
