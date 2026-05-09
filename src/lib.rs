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
    pub const PLACEHOLDER_FLOAT: f64 = 0.0;
    pub const PLACEHOLDER_INT: u32 = 0;

    /* Ping */
    pub const PUNISH_PING_FAILURE: f64 = PLACEHOLDER_FLOAT;

    /* Block */
    pub const REWARD_VALID_BLOCK: f64 = PLACEHOLDER_FLOAT;

    pub const PUNISH_UNACCEPTED_BLOCK: f64 = PLACEHOLDER_FLOAT;
    pub const PUNISH_MALFORMED_BLOCK: f64 = PLACEHOLDER_FLOAT;
    // implement escalation -> from a certain threshold punish harder.

    /* Message? */
    pub const INVALID_MESSAGE_THRESHOLD: u32 = PLACEHOLDER_INT;

    /* Overall Application Score */
    pub const INITIAL_PEER_SCORE: f64 = 0.0;
    pub const SCORE_BLACKLIST_THRESHOLD: f64 = PLACEHOLDER_FLOAT;
}

pub mod topic {
    pub const BLOCKS: &str = "blocks";
}
