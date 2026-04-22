//! Module that implements the proof-of-work (PoW) blockchain components that form the distributed ledger.
//!
//! The PoW algorithm is based on the following references:
//! - [Simple PoW Implementation in Go](https://towardsdev.com/the-proof-of-work-pow-mechanism-in-blockchain-6a49196cab75)
//! - [Simple PoW Implementation in C](https://www.jmeiners.com/tiny-blockchain/)
//! - [Simple PoW Implementation in Rust](https://hackernoon.com/rusty-chains-a-basic-blockchain-implementation-written-in-pure-rust-gk2m3uri)
//! - [Bitcoin Protocol Specification](https://en.bitcoin.it/wiki/Protocol_documentation#Block_Headers)

use crate::blockchain::{account::Account, block::Block, transaction::Transaction};
use blake2::Blake2b512;
use std::error::Error;

/// Type that defines the hash-function chosen to compute the hashes that will form the blockchain.
///
/// [Blake2](https://web.archive.org/web/20161002114950/http://blake2.net/) was chosen due to its
/// robustness and performance improvements in relation to the SHA-2 family.
type HashFunction = Blake2b512;

/// Module that defines the hash-function of the blockchain.
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

/// Module that defines the proof-of-work algorithm of the blockchain.
pub mod pow {
    use crate::{
        blockchain::{block::UnsignedBlock, transaction::Transaction},
        time::now_unix,
    };
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

                let unsigned_block =
                    UnsignedBlock::new(previous_hash, &pow.transactions, nonce, timestamp);

                let h = unsigned_block.hash()?;

                if h.as_slice() < TARGET {
                    return Ok((hex::encode(h), nonce, timestamp));
                }
            }
        }
    }
}

/// Module that defines transactions and their execution.
pub mod transaction {
    use crate::{blockchain::State, time::now_unix};
    use ed25519_dalek_blake2b::{Keypair, PublicKey, Signature, Signer, Verifier};
    use hex::ToHex;
    use serde::{Deserialize, Serialize};
    use std::error::Error;

    /// Struct that represents a transaction that can be executed in the blockchain. A transaction can
    /// change the current state of the chain.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Transaction {
        pub record: Data,
        pub from: String,
        pub created_at: u64,
        pub nonce: u64,
        pub signature: String, // todo: refactor and use ed25519
    }

    /// Enum that represents the different kinds of actions that can be performed.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum Data {
        CreateUserAccount(String),
        ChangeStoreValue { key: String, value: String },
        TransferTokens { to: String, amount: u128 },
        CreateTokens { receiver: String, amount: u128 },
        // add more and adapt for auction
    }

    impl Transaction {
        /// Function that creates a transaction.
        pub fn new(
            record: Data,
            from: String,
            nonce: u64,
            key: Keypair,
        ) -> Result<Self, Box<dyn Error + Send + Sync>> {
            let signature = Self::sign(&record, &from, &nonce, &key)?;
            Ok(Self {
                record,
                from,
                created_at: now_unix()?,
                nonce,
                signature,
            })
        }

        /// Function that serializes the parameters used to compute a transaction's signature.
        fn serialize(
            record: &Data,
            from: &String,
            nonce: &u64,
        ) -> Result<String, Box<dyn Error + Send + Sync>> {
            Ok(format!(
                "{}:{}:{}",
                serde_json::to_string(&record)?,
                from,
                nonce
            ))
        }

        /// Function that signs the parameters used to construct a transaction.
        fn sign(
            record: &Data,
            from: &String,
            nonce: &u64,
            key: &Keypair,
        ) -> Result<String, Box<dyn Error + Send + Sync>> {
            let input = Self::serialize(record, from, nonce)?;
            let signature = key.sign(input.as_bytes());
            Ok(signature.encode_hex())
        }

        /// Function that verifies the validity of a transaction.
        pub fn verify(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
            let bytes = &hex::decode(&self.from)?;
            let pk = match PublicKey::from_bytes(bytes) {
                Ok(pk) => pk,
                _ => return Err("Malformed from field.".into()),
            };
            let signature = match Signature::from_bytes(&hex::decode(&self.signature)?) {
                Ok(s) => s,
                _ => return Err("Malformed signature.".into()),
            };
            match pk.verify(
                match Transaction::serialize(&self.record, &self.from, &self.nonce) {
                    Ok(input) => input,
                    _ => return Err("Invalid fields.".into()),
                }
                .as_bytes(),
                &signature,
            ) {
                Ok(_) => Ok(()),
                _ => return Err("Invalid signature.".into()),
            }
        }

        /// Function that executes a transaction and changes the blockchain state.
        pub fn execute<T: State>(
            &self,
            _state: &mut T,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            // TODO
            Ok(())
        }
    }
}

/// Module that defines a blockchain user account.
pub mod account {
    use std::{collections::HashMap, error::Error};

    /// Struct that defines an account that can either be a user managed account or a smart contract operating independently.
    #[derive(Clone, Debug)]
    pub struct Account {
        pub store: HashMap<String, String>,
        pub kind: Kind,
        /// Amount of tokens that account owns (like BTC or ETH) -> might not need
        pub tokens: u128,
    }

    /// Enum that represents the types of accounts that can be created in the blockchain.
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

/// Module that defines the unsigned and signed block.
pub mod block {
    use crate::blockchain::{
        HashFunction,
        hash::{self, encode_hash},
        pow,
        transaction::Transaction,
    };
    use blake2::Digest;
    use serde::{Deserialize, Serialize};
    use std::error::Error;

    /// Struct that represents the parameters that form the block's hash.
    pub struct UnsignedBlock {
        pub previous_hash: String,
        pub transactions: Vec<Transaction>,
        pub nonce: u32,
        pub timestamp: u64,
    }

    impl UnsignedBlock {
        /// Function that creates a new unsigned block.
        pub fn new(
            previous_hash: &str,
            transactions: &[Transaction],
            nonce: u32,
            timestamp: u64,
        ) -> Self {
            Self {
                previous_hash: previous_hash.to_string(),
                transactions: transactions.to_vec(),
                nonce,
                timestamp,
            }
        }

        /// Function that hashes an unsigned block to form a block that can be appended to the chain.
        pub fn hash(&self) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
            let input = format!(
                "{}:{}:{}:{}",
                self.previous_hash,
                serde_json::to_string(&self.transactions)?,
                self.nonce,
                self.timestamp
            );
            Ok(hash::hash(HashFunction::new(), &input))
        }
    }

    /// Struct that defines a published block.
    #[derive(Debug, Clone, Serialize, Deserialize)]
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

        /// Function that verifies if a block has a valid hash.
        pub fn verify(&self) -> bool {
            let unsigned_block = UnsignedBlock::new(
                &self.previous_hash,
                &self.transactions,
                self.nonce,
                self.timestamp,
            );
            match unsigned_block.hash() {
                Ok(h) => encode_hash(&h) == self.hash,
                Err(_) => false,
            }
        }
    }
}

/// Trait that defines the functions that can mutate the blockchain.
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

/// Struct that represents the blockchain that will be used as the ledger for the auction system.
#[derive(Debug, Clone)]
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
        if transactions.len() == 0 {
            return Err(
                "There needs to be at least one transaction for a block to be generated.".into(),
            );
        }

        let previous_block_hash = match self.blocks.last() {
            Some(pb) => Some(pb.hash.clone()),
            None => None,
        };
        let block_to_append = Block::new(previous_block_hash, transactions, self.difficulty)?;

        if !block_to_append.verify() {
            return Err("Failed to produce a valid block.".into());
        }

        if let Some(block) = self.blocks.last() {
            if block_to_append.previous_hash != block.hash {
                return Err(
                    "The new block does not point to the previous block in the chain.".into(),
                );
            }
        }

        {
            let mut blockchain_temp = self.clone();
            block_to_append.transactions.iter().try_for_each(
                |t| -> Result<(), Box<dyn Error + Send + Sync>> {
                    t.verify()?;
                    t.execute(&mut blockchain_temp)?;
                    Ok(())
                },
            )?;
            *self = blockchain_temp;
        }

        self.blocks.push(block_to_append);
        Ok(())
    }

    /// Function that verifies each block in the blockchain.
    pub fn verify(&self) -> bool {
        self.blocks.iter().fold(false, |acc, b| acc && b.verify())
    }
}

impl State for Blockchain {
    fn create_account(&mut self, _id: String, _kind: account::Kind) -> Result<(), &str> {
        todo!()
    }

    fn get_account_by_id(&self, _id: &String) -> Option<&Account> {
        todo!()
    }

    fn get_account_by_id_mut(&mut self, _id: &String) -> Option<&mut Account> {
        todo!()
    }

    fn get_user_ids(&self) -> Vec<String> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use crate::blockchain::{
        Blockchain,
        transaction::{Data, Transaction},
    };
    use ed25519_dalek_blake2b::Keypair;
    use hex::ToHex;
    use rand::rngs::OsRng;
    use std::error::Error;

    #[test]
    fn test_blockchain() -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut blockchain = Blockchain::new(u32::MAX)?;

        for n in 0..2 {
            let keys = Keypair::generate(&mut OsRng);

            let transactions = vec![Transaction::new(
                Data::CreateUserAccount(format!("user_{n}")),
                keys.public.encode_hex(),
                n,
                keys,
            )?];

            blockchain.add_block(transactions)?;
        }

        blockchain.verify();

        Ok(())
    }
}
