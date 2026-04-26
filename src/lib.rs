pub mod behaviour;
pub mod blockchain;
pub mod boot;
pub mod gossip;
pub mod key;
pub mod node;
pub mod rpc;
pub mod runtime;
pub mod state;
pub mod time;

pub const CONFIG_DIR: &str = "config";
pub const QUORUM: usize = 3;
pub const MAX_CONSECUTIVE_FAILURES: u32 = 5;
pub const LOOKUP_QUORUM: u16 = 1;
