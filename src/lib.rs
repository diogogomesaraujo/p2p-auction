pub mod behaviour;
pub mod blockchain;
pub mod boot;
pub mod bot;
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

pub mod topic {
    pub const BLOCKS: &str = "blocks";
}

pub mod error {
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum AcceptBlockError {
        #[error("The block proposed already exists in the chain.")]
        Duplicate,

        #[error("The block proposed has been pruned.")]
        Pruned,

        #[error("The block proposed has a pruned parent.")]
        PrunedParent,

        #[error("The block proposed has an invalid hash.")]
        InvalidHash,

        #[error("The block proposed does not point to a block in the chain.")]
        Orphan,

        #[error("The order of transactions is wrong.")]
        WrongTransactionOrder,
    }
}
