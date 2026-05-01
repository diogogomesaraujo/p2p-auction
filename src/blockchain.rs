//! Module that implements the proof-of-work (PoW) blockchain components that form the distributed ledger.
//!
//! The PoW algorithm is based on the following references:
//! - [Simple PoW Implementation in Go](https://towardsdev.com/the-proof-of-work-pow-mechanism-in-blockchain-6a49196cab75);
//! - [Simple PoW Implementation in C](https://www.jmeiners.com/tiny-blockchain/);
//! - [Simple PoW Implementation in Rust](https://hackernoon.com/rusty-chains-a-basic-blockchain-implementation-written-in-pure-rust-gk2m3uri);
//! - [Bitcoin Protocol Specification](https://en.bitcoin.it/wiki/Protocol_documentation#Block_Headers);
//! - [Full Blockchain in Go](https://www.youtube.com/playlist?list=PL0xRBLFXXsP6-hxQmCDcl_BHJMm0mhxx7);
//! - [Transaction Mempool](https://medium.com/coinmonks/creating-a-blockchain-part-6-transaction-mempool-and-tx-encoding-a1581479449e);
//! - [Merkle Tree in Blockchain Implementation](https://dsvynarenko.hashnode.dev/designing-blockchain-4-merkle-trees-and-state-verification).

use crate::blockchain::{account::Account, block::Block, transaction::TransactionPool};
use blake2::Blake2b512;
use num_bigint::BigUint;
use std::{
    collections::{HashMap, HashSet},
    error::Error,
};

/// Type that defines the hash-function chosen to compute the hashes that will form the blockchain.
///
/// [Blake2](https://web.archive.org/web/20161002114950/http://blake2.net/) was chosen due to its
/// robustness and performance improvements in relation to the SHA-2 family.
type HashFunction = Blake2b512;

pub mod ed25519 {
    use ed25519_dalek_blake2b::{PublicKey, Signature};
    use hex::ToHex;
    use std::error::Error;

    pub fn string_to_public_key(
        public_key: &str,
    ) -> Result<PublicKey, Box<dyn Error + Send + Sync>> {
        match PublicKey::from_bytes(&hex::decode(public_key)?) {
            Ok(pk) => Ok(pk),
            Err(e) => Err(e.to_string().into()),
        }
    }

    pub fn string_to_signature(signature: &str) -> Result<Signature, Box<dyn Error + Send + Sync>> {
        match Signature::from_bytes(&hex::decode(signature)?) {
            Ok(pk) => Ok(pk),
            Err(e) => Err(e.to_string().into()),
        }
    }

    pub fn signature_tp_string(signature: &Signature) -> String {
        signature.encode_hex()
    }

    pub fn public_key_to_string(public_key: &PublicKey) -> String {
        public_key.encode_hex()
    }
}

/// Module that defines the hash-function of the blockchain.
pub mod hash {
    use crate::blockchain::HashFunction;
    use blake2::Digest;
    use std::error::Error;

    pub trait Hashable {
        fn hash(&self) -> Result<String, Box<dyn Error + Send + Sync>>;
    }

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
        blockchain::{block::UnsignedBlock, hash, transaction::Transaction},
        time::{Timestamp, now_unix},
    };
    use std::error::Error;
    use tracing::info;

    /// Constant that defines the rate with which a miner logs the block mining progress.
    const LOG_MINERATION: u32 = 100000;

    /// Constant that represents the magic number used to define the difficulty of mineration.
    const TARGET: &[u8] = &[
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ];

    macro_rules! puzzle {
        ($hash:ident, $target:expr) => {
            $hash.as_slice() < $target
        };
    }

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
    ) -> Result<(String, u32, Timestamp), Box<dyn Error + Send + Sync>> {
        loop {
            let timestamp = now_unix()?;

            for nonce in 0..pow.difficulty {
                if nonce % LOG_MINERATION == 0 {
                    info!("Still mining. The current nonce value is: {}.", nonce);
                }

                let unsigned_block =
                    UnsignedBlock::new(previous_hash, &pow.transactions, nonce, timestamp)?;

                let h = unsigned_block.hash()?;

                if puzzle!(h, TARGET) {
                    return Ok((hash::encode_hash(&h), nonce, timestamp));
                }
            }
        }
    }

    pub fn verify(hash: Vec<u8>) -> bool {
        puzzle!(hash, TARGET)
    }
}

/// Module that defines the merkle tree structure for lightweight transaction verification.
pub mod merkle {
    use crate::blockchain::{
        HashFunction,
        hash::{self, Hashable},
    };
    use blake2::Digest;
    use std::{collections::VecDeque, error::Error};

    /// Function that returns the Merkle root of a given set of transactions.
    pub fn root<T: Hashable>(t: &[T]) -> Result<String, Box<dyn Error + Send + Sync>> {
        if t.is_empty() {
            return Err("Cannot build Merkle root from empty transaction list.".into());
        }
        let mut tmp: VecDeque<String> = VecDeque::new();
        let mut pairs = t.chunks(2);
        while let Some(pair) = pairs.next() {
            match pair {
                [l, r] => {
                    let lh = l.hash()?;
                    let rh = r.hash()?;
                    tmp.push_back(hash(&lh, &rh)?);
                }
                [s] => {
                    let sh = s.hash()?;
                    tmp.push_back(hash(&sh, &sh)?);
                }
                _ => unreachable!(),
            }
        }

        while tmp.len() > 1 {
            let mut tmp2: VecDeque<String> = VecDeque::new();
            while let Some(l) = tmp.pop_front() {
                match tmp.pop_front() {
                    Some(r) => {
                        tmp2.push_back(hash(&l, &r)?);
                    }
                    None => {
                        tmp2.push_back(hash(&l, &l)?);
                    }
                }
            }
            tmp = tmp2;
        }

        match tmp.pop_front() {
            Some(root) => return Ok(root),
            _ => return Err("Merkle root calculation failed.".into()),
        }
    }

    /// Function that concatenates and hashes sibling nodes in a Merkle tree.
    pub fn hash(left: &str, right: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
        let input = format!("{}:{}", left, right);
        let h = hash::hash(HashFunction::new(), &input);
        Ok(hash::encode_hash(&h))
    }
}

/// Module that defines transactions and their execution.
pub mod transaction {
    use crate::{
        blockchain::{
            Blockchain, HashFunction, WorldState,
            ed25519::{signature_tp_string, string_to_public_key, string_to_signature},
            hash::{self, Hashable},
        },
        time::{Timestamp, now_unix},
    };
    use blake2::Digest;
    use ed25519_dalek_blake2b::{Keypair, Signer, Verifier};
    use serde::{Deserialize, Serialize};
    use std::{collections::HashMap, error::Error};

    /// Struct that represents a transaction that can be executed in the blockchain. A transaction can
    /// change the current state of the chain.
    #[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
    pub struct Transaction {
        pub id: String,
        pub record: Data,
        pub from: String,
        pub created_at: Timestamp,
        pub nonce: u32,
        pub signature: String,
    }

    /// Enum that represents the different kinds of actions that can be performed.
    #[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
    pub enum Data {
        CreateUserAccount {
            public_key: String,
        },
        TransferTokens {
            from: String,
            to: String,
            amount: u64,
        },
        // add more and adapt for auction
    }

    impl Transaction {
        /// Function that creates a transaction.
        pub fn new(
            record: Data,
            from: String,
            nonce: u32,
            signature: &str,
        ) -> Result<Self, Box<dyn Error + Send + Sync>> {
            let id = hash::encode_hash(&hash::hash(
                HashFunction::new(),
                &format!(
                    "{}:{}:{}:{}",
                    serde_json::to_string(&record)?,
                    from,
                    nonce,
                    signature
                ),
            ));
            Ok(Self {
                id,
                record,
                from,
                created_at: now_unix()?,
                nonce,
                signature: signature.to_string(),
            })
        }

        /// Function that serializes the parameters used to compute a transaction's signature.
        fn serialize(
            record: &Data,
            from: &String,
            nonce: &u32,
        ) -> Result<String, Box<dyn Error + Send + Sync>> {
            Ok(format!(
                "{}:{}:{}",
                serde_json::to_string(&record)?,
                from,
                nonce
            ))
        }

        /// Function that signs the parameters used to construct a transaction.
        pub fn sign(
            record: Data,
            from: &str,
            nonce: u32,
            keys: &Keypair,
        ) -> Result<Transaction, Box<dyn Error + Send + Sync>> {
            let input = Self::serialize(&record, &from.to_string(), &nonce)?;
            Ok(Transaction::new(
                record,
                from.to_string(),
                nonce,
                &signature_tp_string(&keys.sign(input.as_bytes())),
            )?)
        }

        /// Function that verifies the validity of a transaction.
        pub fn verify(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
            let pk = string_to_public_key(&self.from)?;
            let signature = match string_to_signature(&self.signature) {
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
        pub fn execute(
            &self,
            blockchain: &mut Blockchain,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            match &self.record {
                Data::CreateUserAccount { public_key } => blockchain.create_account(public_key)?,
                Data::TransferTokens { from, to, amount } => {
                    blockchain.transfer_funds(from, to, *amount)?
                }
            };

            Ok(())
        }
    }

    impl Hashable for Transaction {
        fn hash(&self) -> Result<String, Box<dyn Error + Send + Sync>> {
            let input = serde_json::to_string(self)?;
            let h = crate::blockchain::hash::hash(HashFunction::new(), &input);
            Ok(hash::encode_hash(&h))
        }
    }

    /// Type that implements the queue of transactions to be executed and published as a block,
    /// constructed from the mempool and sorted by timestamp.
    pub type TransactionQueue = Vec<Transaction>;

    /// Struct that temporarily holds unexecuted transactions mapped by timestamp.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TransactionPool(HashMap<Timestamp, Transaction>);

    impl TransactionPool {
        /// Function that creates an empty mempool.
        pub fn new() -> Self {
            Self(HashMap::new())
        }

        /// Function to get the current mempool.
        pub fn get(&self) -> &HashMap<Timestamp, Transaction> {
            &self.0
        }

        /// Function that sorts the mempool by timestamp mapping it to a queue of transactions,
        fn to_sorted_queue(self) -> TransactionQueue {
            let mut v = self
                .0
                .into_iter()
                .collect::<Vec<(Timestamp, Transaction)>>();
            v.sort_by(|a, b| a.0.cmp(&b.0));
            v.into_iter().map(|(_, t)| t).collect::<TransactionQueue>()
        }

        /// Function that gets the current length of the mempool.
        pub fn len(&self) -> usize {
            self.0.len()
        }

        pub fn remove(&mut self, timestamp: Timestamp) {
            self.0.remove(&timestamp);
        }

        /// Function that adds a transaction to the mempool.
        pub fn add_transaction(
            &mut self,
            transaction: Transaction,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            self.0.insert(transaction.created_at, transaction);
            Ok(())
        }

        /// Function that flushes the current mempool and returns a queue sorted by timestamp.
        pub fn flush(&mut self) -> TransactionQueue {
            let memqueue = self.clone().to_sorted_queue();
            *self = Self::new();
            memqueue
        }

        pub fn contains(&self, transaction: &Transaction) -> bool {
            self.0.contains_key(&transaction.created_at)
                && self.0[&transaction.created_at] == *transaction
        }
    }

    #[cfg(test)]
    pub mod test {
        use crate::blockchain::{
            ed25519::public_key_to_string,
            transaction::{Data, Transaction, TransactionPool},
        };
        use ed25519_dalek_blake2b::Keypair;
        use rand::rngs::OsRng;
        use std::error::Error;

        pub fn test_mempool() -> Result<(), Box<dyn Error + Send + Sync>> {
            let k1 = Keypair::generate(&mut OsRng);
            let k2 = Keypair::generate(&mut OsRng);

            let t1 = Transaction::sign(
                Data::CreateUserAccount {
                    public_key: "skylar".to_string(),
                },
                &public_key_to_string(&k1.public),
                0,
                &k1,
            )?;

            let t2 = Transaction::sign(
                Data::CreateUserAccount {
                    public_key: "walter".to_string(),
                },
                &public_key_to_string(&k2.public),
                1,
                &k2,
            )?;

            let mut pool = TransactionPool::new();
            pool.add_transaction(t1.clone())?;
            pool.add_transaction(t2.clone())?;

            assert_eq!(
                pool.flush().into_iter().collect::<Vec<Transaction>>(),
                vec![t1, t2]
            );

            Ok(())
        }
    }
}

/// Module that defines a blockchain user account.
pub mod account {
    use std::error::Error;

    const INITIAL_TOKEN_COUNT: u64 = 5;

    /// Struct that defines an account that can either be a user managed account or a smart contract operating independently.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Account {
        pub kind: Kind,
        pub tokens: u64,
        pub nonce: u64,
        pub public_key: String,
    }

    /// Enum that represents the types of accounts that can be created in the blockchain.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Kind {
        User,
    }

    impl Account {
        pub fn new(kind: Kind, public_key: String) -> Result<Self, Box<dyn Error + Send + Sync>> {
            Ok(Self {
                kind,
                nonce: 0,
                public_key,
                tokens: INITIAL_TOKEN_COUNT,
            })
        }

        // verify the last confirmed nonce in blockchain for self address
        // increment by one and sign transaction with it
    }
}

/// Module that defines the unsigned and signed block.
pub mod block {
    use crate::{
        blockchain::{
            HashFunction,
            hash::{self, Hashable, encode_hash},
            merkle, pow,
            transaction::Transaction,
        },
        time::Timestamp,
    };
    use blake2::Digest;
    use serde::{Deserialize, Serialize};
    use std::error::Error;

    /// Struct that represents the parameters that form the block's hash.
    pub struct UnsignedBlock {
        pub previous_hash: String,
        pub merkle_root: String,
        pub nonce: u32,
        pub timestamp: Timestamp,
    }

    impl UnsignedBlock {
        /// Function that creates a new unsigned block.
        pub fn new(
            previous_hash: &str,
            transactions: &[Transaction],
            nonce: u32,
            timestamp: u64,
        ) -> Result<Self, Box<dyn Error + Send + Sync>> {
            let merkle_root = merkle::root(transactions)?;
            Ok(Self {
                previous_hash: previous_hash.to_string(),
                merkle_root: merkle_root.to_string(),
                nonce,
                timestamp,
            })
        }

        /// Function that hashes an unsigned block to form a block that can be appended to the chain.
        pub fn hash(&self) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
            let input = format!(
                "{}:{}:{}:{}",
                self.previous_hash, self.merkle_root, self.nonce, self.timestamp
            );
            Ok(hash::hash(HashFunction::new(), &input))
        }
    }

    /// Struct that defines a published block.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct Block {
        pub previous_hash: String,
        pub transactions: Vec<Transaction>,
        pub merkle_root: String,
        pub hash: String,
        pub nonce: u32,
        pub timestamp: Timestamp,
        pub miner: String,
    }

    impl Block {
        /// Function that creates a new block for a given set of transactions after mining the correct nonce.
        pub fn new(
            public_key: String,
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
            let merkle_root = crate::blockchain::merkle::root(&p.transactions)?;

            Ok(Block {
                transactions: p.transactions,
                miner: public_key,
                hash: h,
                previous_hash,
                merkle_root,
                timestamp,
                nonce,
            })
        }

        /// Function that verifies if a block has a valid hash.
        pub fn verify(&self) -> Result<bool, Box<dyn Error + Send + Sync>> {
            let unsigned_block = UnsignedBlock::new(
                &self.previous_hash,
                &self.transactions,
                self.nonce,
                self.timestamp,
            )?;
            match unsigned_block.hash() {
                Ok(h) => Ok(encode_hash(&h) == self.hash),
                Err(_) => Ok(false),
            }
        }
    }

    impl Hashable for Block {
        fn hash(&self) -> Result<String, Box<dyn Error + Send + Sync>> {
            let input = serde_json::to_string(self)?;
            let h = crate::blockchain::hash::hash(HashFunction::new(), &input);
            Ok(hash::encode_hash(&h))
        }
    }
}

/// Struct that represents the blockchain that will be used as the ledger for the auction system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blockchain {
    pub blocks: Vec<Block>,
    pub accounts: HashMap<String, Account>,
    pub transaction_pool: TransactionPool,
    pub difficulty: u32,
}

impl Blockchain {
    /// Function that creates a new blockchain instance.
    pub fn new(difficulty: u32) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(Self {
            accounts: HashMap::new(),
            transaction_pool: TransactionPool::new(),
            blocks: vec![],
            difficulty,
        })
    }

    fn execute_transactions(
        &mut self,
        block_to_append: &Block,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        block_to_append.transactions.iter().try_for_each(
            |t| -> Result<(), Box<dyn Error + Send + Sync>> {
                t.verify()?;
                t.execute(self)?;
                Ok(())
            },
        )?;
        Ok(())
    }

    pub fn accept_block(&mut self, block: Block) -> Result<(), Box<dyn Error + Send + Sync>> {
        if !block.verify()? {
            return Err("The block proposed has an invalid hash.".into());
        }

        let prev_hash = match self.blocks.last() {
            Some(b) => b.clone().previous_hash,
            None => "0".to_string(),
        };

        if block.previous_hash != prev_hash {
            return Err("The block proposed does not point to the current chain tip.".into());
        }

        if !block.transactions.iter().fold(true, |acc, t| {
            let has = self.transaction_pool.contains(t);
            self.transaction_pool.remove(t.created_at);
            acc && has
        }) {
            return Err(
                "The block proposed contains transactions that are not in the mempool.".into(),
            );
        }

        if let None = self.get_account_by_id(&block.miner) {
            return Err("The block proposed has a non-existent miner account.".into());
        }

        if let Err(e) = self.compensate_miner(&block.miner) {
            return Err(
                format!("The block proposed contains an invalid miner account. {e}").into(),
            );
        }

        if let Err(e) = self.execute_transactions(&block) {
            return Err(format!("The block proposed contains invalid transactions. {e}").into());
        }

        self.blocks.push(block);
        Ok(())
    }

    fn insert_after(&self) -> Option<String> {
        let chain = self.hash_chain();

        if chain.len() == 0 {
            return None;
        }

        Some(
            chain[1..]
                .iter()
                .fold(chain[0].clone(), |(acc_prev_h, acc_h), (prev_h, h)| {
                    if prev_h == &acc_prev_h {
                        (
                            acc_prev_h,
                            Self::choose_hash(&acc_h, h).expect("shouldn't fail"),
                        )
                    } else {
                        (prev_h.clone(), h.clone())
                    }
                })
                .1,
        )
    }

    /// Function that appends a block to the blockchain.
    pub fn propose_block(
        &mut self,
        public_key: String,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let transactions = self.transaction_pool.flush();

        if transactions.len() == 0 {
            return Err(
                "There needs to be at least one transaction for a block to be generated.".into(),
            );
        }

        let previous_block_hash = self.insert_after();
        let block_to_append = Block::new(
            public_key,
            previous_block_hash,
            transactions,
            self.difficulty,
        )?;

        if !block_to_append.verify()? {
            return Err("Failed to produce a valid block.".into());
        }

        if let Some(block) = self.blocks.last() {
            if block_to_append.previous_hash != block.hash {
                return Err(
                    "The new block does not point to the previous block in the chain.".into(),
                );
            }
        }

        let mut hypothetical_blockchain = self.clone();
        hypothetical_blockchain.execute_transactions(&block_to_append)?;

        Ok(())
    }

    /// Function that verifies each block in the blockchain.
    pub fn verify(&self) -> Result<bool, Box<dyn Error + Send + Sync>> {
        let mut previous_hash = "0".to_string();

        for block in &self.blocks {
            if !block.verify()? || previous_hash != block.previous_hash {
                return Ok(false);
            }
            previous_hash = block.hash.clone();
        }
        Ok(true)
    }

    fn hash_chain(&self) -> Vec<(String, String)> {
        self.blocks
            .iter()
            .map(|b| (b.previous_hash.clone(), b.hash.clone()))
            .collect()
    }

    fn choose_hash(h1: &str, h2: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
        let h1b = BigUint::from_bytes_le(&hex::decode(h1)?);
        let h2b = BigUint::from_bytes_le(&hex::decode(h2)?);

        assert_eq!(h1b.to_str_radix(16), h1);

        match h1b < h2b {
            true => Ok(h1.to_string()),
            false => Ok(h2.to_string()),
        }
    }

    pub fn fix(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        // break the chain
        let mut map: HashMap<String, String> = HashMap::new();
        let chain = self.hash_chain();
        chain
            .iter()
            .try_for_each(|(prev_h, h)| -> Result<(), Box<dyn Error + Send + Sync>> {
                if let Some((_, h_temp)) = chain
                    .iter()
                    .find(|(prev_h_temp, h_temp)| prev_h_temp == prev_h_temp && h != h_temp)
                {
                    map.insert(prev_h.clone(), Self::choose_hash(h, h_temp)?);
                }
                Ok(())
            })?;

        // remove branches

        let mut prev_hash = "0";
        let mut new_chain = HashSet::new();

        new_chain.insert(prev_hash.to_string());

        while let Some(h) = map.get(prev_hash) {
            new_chain.insert(h.clone());
            prev_hash = h;
        }

        // reconstruct blockchain

        self.blocks = self
            .blocks
            .clone() // super not chill
            .into_iter()
            .filter(|b| new_chain.contains(&b.hash))
            .collect();

        Ok(())
    }
}

pub trait Mine {}

/// Trait that defines the functions that can mutate the blockchain.
pub trait WorldState {
    const CREATE_ACCOUNT_MESSAGE: &str = "blocktion";
    const MINER_COMPENSATION: u64 = 5;

    fn account_balance(&self, public_key: &str) -> Option<u64>;

    fn transfer_funds(
        &mut self,
        from: &str,
        to: &str,
        amount: u64,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;

    fn compensate_miner(&mut self, public_key: &str) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Will return a account given it's id if is available
    fn get_account_by_id(&self, public_key: &str) -> Option<&Account>;

    fn get_account_by_id_mut(&mut self, public_key: &str) -> Option<&mut Account>;

    /// Will add a new account
    fn create_account(&mut self, public_key: &str) -> Result<(), Box<dyn Error + Send + Sync>>;
}

impl WorldState for Blockchain {
    fn create_account(&mut self, public_key: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.accounts.insert(
            public_key.to_string(),
            Account::new(account::Kind::User, public_key.to_string())?,
        );
        Ok(())
    }

    fn transfer_funds(
        &mut self,
        from: &str,
        to: &str,
        amount: u64,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        match (self.get_account_by_id(from), self.get_account_by_id(to)) {
            (Some(f), Some(_)) => {
                if f.tokens >= amount {
                    let from = match self.get_account_by_id_mut(from) {
                        Some(from) => from,
                        None => return Err("From account does not exist.".into()),
                    };
                    from.tokens -= amount;

                    let to = match self.get_account_by_id_mut(to) {
                        Some(from) => from,
                        None => return Err("To account does not exist.".into()),
                    };
                    to.tokens += amount;
                } else {
                    return Err("Not enough funds.".into());
                }
            }
            _ => return Err("Invalid accounts.".into()),
        };

        Ok(())
    }

    fn compensate_miner(&mut self, public_key: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        match self.accounts.get_mut(public_key) {
            Some(account) => {
                account.tokens += Self::MINER_COMPENSATION;
                Ok(())
            }
            None => return Err("The miner account provided does not exist".into()),
        }
    }

    fn account_balance(&self, public_key: &str) -> Option<u64> {
        Some(self.accounts.get(public_key)?.tokens)
    }

    fn get_account_by_id(&self, public_key: &str) -> Option<&Account> {
        self.accounts.get(&public_key.to_string())
    }

    fn get_account_by_id_mut(&mut self, public_key: &str) -> Option<&mut Account> {
        self.accounts.get_mut(&public_key.to_string())
    }
}

#[cfg(test)]
mod test {
    use crate::blockchain::{
        Blockchain,
        block::Block,
        ed25519::public_key_to_string,
        transaction::{Data, Transaction},
    };
    use ed25519_dalek_blake2b::Keypair;
    use rand::rngs::OsRng;
    use std::error::Error;

    #[test]
    fn test_blockchain() -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut blockchain = Blockchain::new(u32::MAX)?;

        for n in 0..1 {
            let keys = Keypair::generate(&mut OsRng);

            let pk = public_key_to_string(&keys.public);
            let t = Transaction::sign(
                Data::CreateUserAccount {
                    public_key: pk.clone(),
                },
                &pk,
                n,
                &keys,
            )?;

            blockchain.transaction_pool.add_transaction(t)?;
            blockchain.propose_block(pk)?;
        }

        // verify blockchain

        assert!(blockchain.verify()?);

        // verify fix function

        let mut fixed_blockchain = blockchain.clone();
        fixed_blockchain.fix()?;

        assert_eq!(blockchain, fixed_blockchain);

        Ok(())
    }

    #[test]
    fn test_blockchain_fix() -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut blockchain = Blockchain::new(u32::MAX)?;

        let b1 = Block {
            previous_hash: "0".to_string(),
            transactions: vec![],
            merkle_root: "".to_string(),
            hash: "11".to_string(),
            nonce: 0,
            timestamp: 1,
            miner: "".to_string(),
        };

        let b2 = Block {
            previous_hash: "0".to_string(),
            transactions: vec![],
            merkle_root: "".to_string(),
            hash: "22".to_string(),
            nonce: 0,
            timestamp: 1,
            miner: "".to_string(),
        };

        let b3 = Block {
            previous_hash: "22".to_string(),
            transactions: vec![],
            merkle_root: "".to_string(),
            hash: "33".to_string(),
            nonce: 0,
            timestamp: 1,
            miner: "".to_string(),
        };

        blockchain.blocks.push(b1.clone());
        blockchain.blocks.push(b2);
        blockchain.blocks.push(b3);

        blockchain.fix()?;

        assert_eq!(blockchain.blocks, vec![b1]);

        Ok(())
    }
}
