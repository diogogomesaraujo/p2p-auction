pub mod behaviour;
pub mod blockchain;
pub mod boot;
pub mod key;
pub mod node;
pub mod rpc;
pub mod runtime;
pub mod state;
pub mod time;
pub mod topic;

pub const CONFIG_DIR: &str = "config";
pub const QUORUM: usize = 3;
pub const LOOKUP_QUORUM: u16 = 1;
pub const INVALID_MESSAGE_THRESHOLD: u32 = 5;
