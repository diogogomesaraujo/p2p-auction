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
pub struct OverlayMetadata {
    pub peer_id: String,
    pub role: String,
    pub supported_protocols: Vec<String>,
    pub connected_peers: usize,
}
