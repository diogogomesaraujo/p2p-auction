use crate::{INITIAL_PEER_SCORE, blockchain::Blockchain, time::Timestamp};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;

#[derive(Debug)]
pub struct State {
    pub peers: HashMap<PeerId, PeerInfo>,
    pub blockchain: Blockchain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub first_seen: Option<Timestamp>,
    pub last_seen: Option<Timestamp>,
    pub session_count: u32,
    pub blacklisted: bool,
    pub application_score: f64,
    pub orphan_blocks_sent: u32,
}

impl Default for PeerInfo {
    fn default() -> Self {
        Self {
            first_seen: None,
            last_seen: None,
            session_count: 0,
            blacklisted: false,
            application_score: INITIAL_PEER_SCORE,
            orphan_blocks_sent: 0,
        }
    }
}

impl State {
    pub fn init() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(Self {
            peers: HashMap::new(),
            blockchain: Blockchain::new(u32::MAX)?, // ??? replace by an initial probe function
        })
    }
}
