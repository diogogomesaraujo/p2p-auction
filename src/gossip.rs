use serde::{Deserialize, Serialize};

pub struct Topic;

impl Topic {
    pub const TRANSACTIONS: &str = "transactions";
    pub const BLOCKS: &str = "blocks";
    pub const OVERLAY_META: &str = "overlay-meta";
    pub const PEER_REPUTATION: &str = "peer-reputation";
    pub const SUSPICIOUS_PEERS: &str = "suspicious-peers";
    pub const LIVENESS: &str = "liveness";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionAnnouncement {
    pub tx_id: String,
    pub origin: String,
    pub timestamp_unix: u64,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockAnnouncement {
    pub block_id: String,
    pub height: u64,
    pub origin: String,
    pub timestamp_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayMetadata {
    pub peer_id: String,
    pub role: String,
    pub supported_protocols: Vec<String>,
    pub connected_peers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationSignal {
    pub observed_peer: String,
    pub score_delta: i32,
    pub reason: String,
    pub reporter: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousPeerReport {
    pub accused_peer: String,
    pub reason: String,
    pub reporter: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessSummary {
    pub peer_id: String,
    pub status: String,
    pub connected_peers: usize,
    pub timestamp_unix: u64,
}
