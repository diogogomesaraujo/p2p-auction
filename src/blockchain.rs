//! Module that implements the proof-of-work (PoW) blockchain components that form the distributed ledger.
//!
//! The PoW algorithm is based on the following references:
//! - [Simple PoW Implementation in Go](https://towardsdev.com/the-proof-of-work-pow-mechanism-in-blockchain-6a49196cab75)
//! - [Simple PoW Implementation in C](https://www.jmeiners.com/tiny-blockchain/)
//! - [Simple PoW Implementation in Rust](https://hackernoon.com/rusty-chains-a-basic-blockchain-implementation-written-in-pure-rust-gk2m3uri)
//! - [Bitcoin Protocol Specification](https://en.bitcoin.it/wiki/Protocol_documentation#Block_Headers)

use crate::blockchain::{account::Account, transaction::Transaction};
use blake2::Blake2b512;
use std::error::Error;

/// Type that defines the hash-function chosen to compute the hashes that will form the blockchain.
///
/// [Blake2](https://web.archive.org/web/20161002114950/http://blake2.net/) was chosen due to its
/// robustness and performance improvements in relation to the SHA-2 family.
type HashFunction = Blake2b512;

pub mod hash {
    use crate::blockchain::HashFunction;
    use blake2::Digest;

    /// Function that hashes a given payload, returning the result in bytes.
    pub fn hash(mut h: HashFunction, data: &str) -> Vec<u8> {
        h.update(data.as_bytes());
        let bytes = h.finalize().to_vec();
        bytes
    }

    /// Function that encodes the result in bytes of the hash-function as a `String`.
    pub fn encode_hash(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    #[cfg(test)]
    mod test {
        use crate::blockchain::hash::{encode_hash, hash};
        use blake2::{Blake2b512, Digest};

        #[test]
        fn test_hash() {
            let to_hash = "I am not in danger, Skyler. I am the danger.";
            let hashed = hash(Blake2b512::new(), to_hash);

            assert_eq!(
                encode_hash(&hashed),
                "3a141d45dea6b8af5bab5f942d88f3c0d48edcda84fac341d821d13d65896e2a7d5a8ec921da654301e72db33631fd94963e064056172f4d970a77625aa7ed93"
            );
        }
    }
}

pub mod pow {
    use crate::{
        blockchain::{HashFunction, hash, transaction::Transaction},
        time::now_unix,
    };
    use blake2::Digest;
    use std::error::Error;
    use tracing::info;

    /// Constant that defines the rate with which a miner logs the block mining progress.
    const LOG_MINERATION: u32 = 100000;

    /// Constant that represents the magic number used to define the difficulty of mineration.
    const TARGET: &[u8] = &[
        0, 0, 0x0F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ];

    /// Struct that represents a proof-of-work instance used to create a blockchain.
    pub struct ProofOfWork {
        pub transactions: Vec<Transaction>,
        pub difficulty: u32,
    }

    /// Function that, given a set of transactions, previous block and execution timestamp, finds a
    /// valid nonce that will be used to publish a block.
    pub fn mine(
        pow: &ProofOfWork,
        previous_hash: &str,
    ) -> Result<(String, u32, u64), Box<dyn Error + Send + Sync>> {
        loop {
            let timestamp = now_unix()?;

            for nonce in 0..pow.difficulty {
                if nonce % LOG_MINERATION == 0 {
                    info!("Still mining. The current nonce value is: {}.", nonce);
                }

                let input = format!(
                    "{}:{}:{}:{}",
                    previous_hash,
                    serde_json::to_string(&pow.transactions)?,
                    nonce,
                    timestamp
                );
                let h = hash::hash(HashFunction::new(), &input);

                if h.as_slice() < TARGET {
                    return Ok((hex::encode(h), nonce, timestamp));
                }
            }
        }
    }
}

pub mod transaction {
    use crate::time::now_unix;
    use serde::{Deserialize, Serialize};
    use std::error::Error;

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Transaction {
        pub record: Data,
        pub from: String,
        pub created_at: u64,
        pub nonce: u64,
        pub signature: String, // todo: refactor and use ed25519
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum Data {
        CreateUserAccount(String),
        ChangeStoreValue { key: String, value: String },
        TransferTokens { to: String, amount: u128 },
        CreateTokens { receiver: String, amount: u128 },
        // add more and adapt for auction
    }

    impl Transaction {
        pub fn new(
            record: Data,
            from: String,
            nonce: u64,
            signature: String,
        ) -> Result<Self, Box<dyn Error + Send + Sync>> {
            Ok(Self {
                record,
                from,
                created_at: now_unix()?,
                nonce,
                signature,
            })
        }
    }
}

pub mod account {
    use std::{collections::HashMap, error::Error};

    #[derive(Clone, Debug)]
    pub struct Account {
        pub store: HashMap<String, String>,
        pub kind: Kind,
        /// Amount of tokens that account owns (like BTC or ETH) -> might not need
        pub tokens: u128,
    }

    #[derive(Clone, Debug)]
    pub enum Kind {
        User,

        // like smart contract in etherium -> might not need
        Contract,
    }

    impl Account {
        pub fn new(kind: Kind) -> Result<Self, Box<dyn Error + Send + Sync>> {
            Ok(Self {
                store: HashMap::new(),
                kind,
                tokens: 0,
            })
        }
    }
}

pub trait State {
    /// Will bring us all registered user ids
    fn get_user_ids(&self) -> Vec<String>;

    /// Will return a account given it's id if is available (mutable)
    fn get_account_by_id_mut(&mut self, id: &String) -> Option<&mut Account>;

    /// Will return a account given it's id if is available
    fn get_account_by_id(&self, id: &String) -> Option<&Account>;

    /// Will add a new account
    fn create_account(&mut self, id: String, kind: account::Kind) -> Result<(), &str>;
}

/// Struct that defines a published block.
#[derive(Debug)]
pub struct Block {
    pub previous_hash: String,
    pub transactions: Vec<Transaction>,
    pub hash: String,
    pub nonce: u32,
    pub timestamp: u64,
}

impl Block {
    /// Function that creates a new block for a given set of transactions after mining the correct nonce.
    pub fn new(
        previous_hash: Option<String>,
        transactions: Vec<Transaction>,
        difficulty: u32,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let previous_hash = match previous_hash {
            Some(ph) => ph,
            None => "0".to_string(),
        };
        let p = pow::ProofOfWork {
            transactions,
            difficulty,
        };
        let (h, nonce, timestamp) = pow::mine(&p, &previous_hash)?;
        Ok(Block {
            previous_hash,
            transactions: p.transactions,
            hash: h,
            timestamp,
            nonce,
        })
    }
}

/// Struct that represents the blockchain that will be used as the ledger for the auction system.
#[derive(Debug)]
pub struct Blockchain {
    pub blocks: Vec<Block>,
    pub difficulty: u32,
}

impl Blockchain {
    /// Function that creates a new blockchain instance.
    pub fn new(difficulty: u32) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(Self {
            difficulty,
            blocks: vec![],
        })
    }

    /// Function that appends a block to the blockchain.
    pub fn add_block(
        &mut self,
        transactions: Vec<Transaction>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let previous_block_hash = match self.blocks.last() {
            Some(pb) => Some(pb.hash.clone()),
            None => None,
        };
        self.blocks.push(Block::new(
            previous_block_hash,
            transactions,
            self.difficulty,
        )?);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::blockchain::{
        Blockchain,
        transaction::{Data, Transaction},
    };
    use std::error::Error;

    #[test]
    fn test_blockchain() -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut blockchain = Blockchain::new(u32::MAX)?;

        for n in 0..2 {
            let transactions = vec![Transaction::new(
                Data::CreateUserAccount(format!("user_{n}")),
                "system".to_string(),
                n,
                "ekiwnv".to_string(),
            )?];

            blockchain.add_block(transactions)?;
        }

        println!("{:#?}", blockchain);

        Ok(())
    }
}
