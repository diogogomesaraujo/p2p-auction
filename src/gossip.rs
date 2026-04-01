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

// TODO(ANTI-IMPERSONATION):
// These messages are currently plain payload structs.
// Later add signed envelopes, for example:
// {
//   payload: ...,
//   signer_peer_id: ...,
//   signature: ...,
//   timestamp_unix: ...,
// }
//
// Especially important for:
// - OverlayMetadata
// - ReputationSignal
// - SuspiciousPeerReport

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionAnnouncement {
    pub tx_id: String,
    pub origin: String,
    pub timestamp_unix: u64,
    pub summary: String,
    // TODO(LEDGER SUPPORT):
    // Add content-address / hash field later so block/tx announcements can be verified and fetched.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockAnnouncement {
    pub block_id: String,
    pub height: u64,
    pub origin: String,
    pub timestamp_unix: u64,
    // TODO(LEDGER SUPPORT):
    // Prefer block hash / CID style identifier for content-addressed retrieval.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayMetadata {
    pub peer_id: String,
    pub role: String,
    pub supported_protocols: Vec<String>,
    pub connected_peers: usize,
    // TODO(ANTI-IMPERSONATION):
    // Must later be signed and verified against the sender PeerId.
    //
    // TODO(TRUST):
    // Could also include identity age / first_seen / capabilities for peer admission weighting.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationSignal {
    pub observed_peer: String,
    pub score_delta: i32,
    pub reason: String,
    pub reporter: String,
    // TODO(TRUST):
    // Do not apply these directly.
    // Later:
    // - validate reporter identity
    // - weight by local trust in reporter
    // - cap score_delta
    // - decay old reputation over time
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousPeerReport {
    pub accused_peer: String,
    pub reason: String,
    pub reporter: String,
    // TODO(TRUST + BYZANTINE):
    // This should contribute to suspicion tracking, not instant blacklist.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessSummary {
    pub peer_id: String,
    pub status: String,
    pub connected_peers: usize,
    pub timestamp_unix: u64,
    // TODO(CHURN):
    // Treat as advisory only. Direct observations should matter more.
}
