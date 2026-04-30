pub mod behaviour;
pub mod blockchain;
pub mod boot;
pub mod key;
pub mod node;
pub mod rpc;
pub mod runtime;
pub mod state;
pub mod time;

pub const CONFIG_DIR: &str = "config";
pub const QUORUM: usize = 3;
pub const LOOKUP_QUORUM: u16 = 1;

pub const INVALID_MESSAGE_THRESHOLD: u32 = 5;

pub const INITIAL_PEER_SCORE: f64 = 0.0;

pub const PLACEHOLDER: f64 = 0.0;
pub const PUNISH_UNACCEPTED_BLOCK: f64 = PLACEHOLDER;
pub const PUNISH_MALFORMED_BLOCK: f64 = PLACEHOLDER;
pub const REWARD_VALID_BLOCK: f64 = PLACEHOLDER;

pub mod topic {
    pub const BLOCKS: &str = "blocks";
}
