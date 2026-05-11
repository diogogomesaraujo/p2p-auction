pub mod behaviour;
pub mod blockchain;
pub mod boot;
pub mod key;
pub mod node;
pub mod runtime;
pub mod state;
pub mod time;
pub mod vm;

pub mod config {
    pub const CONFIG_DIR: &str = "config";
    pub const QUORUM: usize = 3;
    pub const LOOKUP_QUORUM: u16 = 1;
}

pub mod reputation {
    /* Placeholders (while params aren't thought through) */

    /* Ping */
    pub const PUNISH_PING_FAILURE: f64 = -1.0;

    /* Block */
    pub const REWARD_VALID_BLOCK: f64 = 1.0;

    pub const PUNISH_UNACCEPTED_BLOCK: f64 = -2.0;
    pub const PUNISH_MALFORMED_BLOCK: f64 = -5.0;

    // implement escalation -> from a certain threshold punish harder.

    /* Message? */
    pub const INVALID_MESSAGE_THRESHOLD: u32 = 3;

    /* Overall Application Score */
    pub const INITIAL_PEER_SCORE: f64 = 0.0;
    pub const SCORE_BLACKLIST_THRESHOLD: f64 = -10.0;
}

pub mod topic {
    pub const BLOCKS: &str = "blocks";
}
