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

use crate::{
    blockchain::{
        block::Block,
        transaction::{Data, Transaction, TransactionPool},
    },
    error::AcceptBlockError,
};
use blake2::Blake2b512;
use num_bigint::BigUint;
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    error::Error,
    sync::{Arc, atomic::AtomicBool},
};
use tokio::sync::Notify;
use tracing::info;

/// Constant that defines the number of blocks that need to be appended before a block's transactions can be executed.
pub const EXECUTE_AFTER_N_BLOCKS: usize = 2;

/// Type that defines the hash-function chosen to compute the hashes that will form the blockchain.
///
/// [Blake2](https://web.archive.org/web/20161002114950/http://blake2.net/) was chosen due to its
/// robustness and performance improvements in relation to the SHA-2 family.
type HashFunction = Blake2b512;

pub mod ed25519 {
    use ed25519_dalek_blake2b::{PublicKey, Signature};
    use hex::ToHex;
    use std::error::Error;

    /// Function that converts a string into an Ed25519 public key.
    pub fn string_to_public_key(
        public_key: &str,
    ) -> Result<PublicKey, Box<dyn Error + Send + Sync>> {
        match PublicKey::from_bytes(&hex::decode(public_key)?) {
            Ok(pk) => Ok(pk),
            Err(e) => Err(e.to_string().into()),
        }
    }

    /// Function that converts a string into an Ed25519 signature.
    pub fn string_to_signature(signature: &str) -> Result<Signature, Box<dyn Error + Send + Sync>> {
        match Signature::from_bytes(&hex::decode(signature)?) {
            Ok(pk) => Ok(pk),
            Err(e) => Err(e.to_string().into()),
        }
    }

    /// Function that converts an Ed25519 signature into a string.
    pub fn signature_to_string(signature: &Signature) -> String {
        signature.encode_hex()
    }

    /// Function that converts an Ed25519 public key into a string.
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
        /// Function that hashes a transaction in the context of merkle trees.
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
}

/// Module that defines the proof-of-work algorithm of the blockchain.
pub mod pow {
    use crate::{
        blockchain::{block::Header, hash, transaction::Transaction},
        time::{Timestamp, now_unix},
    };
    use std::error::Error;
    use tracing::info;

    /// Constant that defines the rate with which a miner logs the block mining progress.
    const LOG_MINERATION: u32 = 100000;

    /// Constant that represents the magic number used to define the difficulty of mineration.
    const TARGET: &[u8] = &[
        0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ];

    /// Macro that determines the computational problem that will ensure the proof-of-work difficulty.
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
                    Header::new(previous_hash, &pow.transactions, nonce, timestamp)?;

                let h = unsigned_block.hash()?;

                if puzzle!(h, TARGET) {
                    return Ok((hash::encode_hash(&h), nonce, timestamp));
                }
            }
        }
    }

    /// Function that verifies if a proposed block hash solved the puzzle correctly.
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
            HashFunction,
            ed25519::{signature_to_string, string_to_public_key, string_to_signature},
            hash::{self, Hashable},
        },
        state::{
            self,
            service::{TransactionRequest, transaction_request},
        },
        time::{Timestamp, now_unix},
    };
    use blake2::Digest;
    use ed25519_dalek_blake2b::{Keypair, Signer};
    use serde::{Deserialize, Serialize};
    use std::{collections::HashMap, error::Error};

    /// Struct that represents a transaction that can be executed in the blockchain. A transaction can
    /// change the current state of the chain.
    #[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
    pub struct Transaction {
        pub id: String,
        pub record: Data,
        pub from: String,
        pub timestamp: Timestamp,
        pub nonce: u32,
        pub signature: String,
    }

    /// Enum that represents the different kinds of actions that can be performed.
    #[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
    pub enum Data {
        CreateUserAccount {
            public_key: String,
        },
        Bid {
            auction_id: String,
            amount: u64,
        },
        CreateAuction {
            auction_id: String,
            start_amount: u64,
            stop_time: Timestamp,
        },
        StopAuction {
            auction_id: String,
        },
    }

    impl Into<transaction_request::Record> for Data {
        /// Function that converts the a transaction record into the defined protobuf format.
        fn into(self) -> transaction_request::Record {
            match self {
                Data::Bid { auction_id, amount } => {
                    transaction_request::Record::BidRequest(state::service::Bid {
                        auction_id,
                        amount,
                    })
                }
                Data::CreateAuction {
                    auction_id,
                    start_amount,
                    stop_time,
                } => transaction_request::Record::CreateAuctionRequest(
                    state::service::CreateAuction {
                        auction_id,
                        start_amount,
                        stop_time,
                    },
                ),

                Data::CreateUserAccount { public_key } => {
                    transaction_request::Record::CreateAccountRequest(state::service::Account {
                        public_key,
                    })
                }

                Data::StopAuction { auction_id } => {
                    transaction_request::Record::StopAuctionRequest(state::service::StopAuction {
                        auction_id,
                    })
                }
            }
        }
    }

    impl Into<state::service::transaction::Record> for Data {
        /// Function that converts the a transaction record into the defined protobuf format.
        fn into(self) -> state::service::transaction::Record {
            match self {
                Data::Bid { auction_id, amount } => {
                    state::service::transaction::Record::BidRequest(state::service::Bid {
                        auction_id,
                        amount,
                    })
                }
                Data::CreateAuction {
                    auction_id,
                    start_amount,
                    stop_time,
                } => state::service::transaction::Record::CreateAuctionRequest(
                    state::service::CreateAuction {
                        auction_id,
                        start_amount,
                        stop_time,
                    },
                ),
                Data::CreateUserAccount { public_key } => {
                    state::service::transaction::Record::CreateAccountRequest(
                        state::service::Account { public_key },
                    )
                }
                Data::StopAuction { auction_id } => {
                    state::service::transaction::Record::StopAuctionRequest(
                        state::service::StopAuction { auction_id },
                    )
                }
            }
        }
    }

    impl Into<TransactionRequest> for Transaction {
        /// Function that converts the a transaction into the defined protobuf format.
        fn into(self) -> TransactionRequest {
            TransactionRequest {
                signature: self.signature,
                from: self.from,
                record: Some(self.record.into()),
                nonce: self.nonce,
            }
        }
    }

    impl Into<state::service::Transaction> for Transaction {
        /// Function that converts the a transaction record into the defined protobuf format.
        fn into(self) -> state::service::Transaction {
            state::service::Transaction {
                id: self.id,
                from: self.from,
                timestamp: self.timestamp,
                nonce: self.nonce,
                signature: self.signature,
                record: Some(self.record.into()),
            }
        }
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
                timestamp: now_unix()?,
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
            #[derive(Serialize)]
            struct TransactionHeader {
                record: Data,
                from: String,
                nonce: u32,
            }

            let header = TransactionHeader {
                record: record.clone(),
                from: from.clone(),
                nonce: nonce.clone(),
            };

            Ok(serde_json::to_string(&header)?)
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
                &signature_to_string(&keys.sign(input.as_bytes())),
            )?)
        }

        /// Function that verifies the validity of a transaction.
        pub fn verify(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
            let pk = string_to_public_key(&self.from)?;
            let signature = match string_to_signature(&self.signature) {
                Ok(s) => s,
                _ => return Err("Malformed signature.".into()),
            };
            match pk.verify_strict(
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
    }

    impl Hashable for Transaction {
        /// Function that hashes a transaction.
        fn hash(&self) -> Result<String, Box<dyn Error + Send + Sync>> {
            let input = serde_json::to_string(self)?;
            let h = crate::blockchain::hash::hash(HashFunction::new(), &input);
            Ok(hash::encode_hash(&h))
        }
    }

    /// Type that implements the queue of transactions to be executed and published as a block,
    /// constructed from the mempool and sorted by id.
    pub type TransactionQueue = Vec<Transaction>;

    /// Struct that temporarily holds unexecuted transactions mapped by id.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TransactionPool(HashMap<String, Transaction>);

    impl TransactionPool {
        /// Function that creates an empty mempool.
        pub fn new() -> Self {
            Self(HashMap::new())
        }

        /// Function to get the current mempool.
        pub fn get(&self) -> &HashMap<String, Transaction> {
            &self.0
        }

        /// Function that sorts the mempool by timestamp mapping it to a queue of transactions.
        fn to_sorted_queue(self) -> TransactionQueue {
            let mut v = self.0.into_values().collect::<Vec<Transaction>>();
            v.sort_by(|a, b| a.timestamp.cmp(&b.timestamp).then_with(|| a.id.cmp(&b.id)));
            v
        }

        /// Function that gets the current length of the mempool.
        pub fn len(&self) -> usize {
            self.0.len()
        }

        /// Function that removes a transaction from the transaction pool.
        pub fn remove(&mut self, id: String) {
            self.0.remove(&id);
        }

        /// Function that adds a transaction to the mempool.
        pub fn add_transaction(
            &mut self,
            transaction: Transaction,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            self.0.insert(transaction.id.clone(), transaction);
            Ok(())
        }

        /// Function that detects duplicate nonces for same sender.
        pub fn replay(&self, transaction: &Transaction) -> bool {
            self.0
                .values()
                .any(|t| t.from == transaction.from && t.nonce == transaction.nonce)
        }

        /// Function that flushes the current mempool and returns a queue sorted by timestamp.
        pub fn flush(&mut self) -> TransactionQueue {
            let memqueue = self.clone().to_sorted_queue();
            *self = Self::new();
            memqueue
        }

        /// Function that checks if a transaction is in the pool.
        pub fn contains(&self, transaction: &Transaction) -> bool {
            self.0.contains_key(&transaction.id) && self.0[&transaction.id] == *transaction
        }
    }
}

/// Module that defines the unsigned and signed block.
pub mod block {
    use crate::{
        blockchain::{
            HashFunction,
            hash::{self, Hashable, encode_hash},
            merkle::{self},
            pow,
            transaction::Transaction,
        },
        state,
        time::Timestamp,
    };
    use blake2::Digest;
    use serde::{Deserialize, Serialize};
    use std::error::Error;

    /// Struct that represents the parameters that form the block's hash.
    #[derive(Serialize, Deserialize)]
    pub struct Header {
        pub previous_hash: String,
        pub merkle_root: String,
        pub nonce: u32,
        pub timestamp: Timestamp,
    }

    impl Header {
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
            let input = serde_json::to_string(&self)?;
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

    impl Into<state::service::Block> for Block {
        /// Function that converts a block into the defined protobuf format.
        fn into(self) -> state::service::Block {
            state::service::Block {
                previous_hash: self.previous_hash,
                transactions: self.transactions.into_iter().map(|t| t.into()).collect(),
                merkle_root: self.merkle_root,
                hash: self.hash,
                nonce: self.nonce,
                timestamp: self.timestamp,
                miner: self.miner,
            }
        }
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
            let unsigned_block = Header::new(
                &self.previous_hash,
                &self.transactions,
                self.nonce,
                self.timestamp,
            )?;
            let h = unsigned_block.hash()?;
            Ok(encode_hash(&h) == self.hash
                && pow::verify(h)
                && unsigned_block.merkle_root == self.merkle_root)
        }
    }

    impl Hashable for Block {
        /// Function that hashes a block.
        fn hash(&self) -> Result<String, Box<dyn Error + Send + Sync>> {
            let input = serde_json::to_string(self)?;
            let h = crate::blockchain::hash::hash(HashFunction::new(), &input);
            Ok(hash::encode_hash(&h))
        }
    }
}

/// Struct that represents state for a given account
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub public_key: String,
    pub nonce: u32,
}

/// Struct that represents the blockchain that will be used as the ledger for the auction system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blockchain {
    pub blocks: HashMap<String, Block>,
    pub longest_chain: Vec<String>,
    pub commited_pointer: usize,
    pub transaction_pool: TransactionPool,
    pub difficulty: u32,
    pub pruned: HashSet<String>,
    pub accounts: HashMap<String, Account>,
    pub auctions: HashMap<String, (String, u64)>,
}

impl Blockchain {
    /// Function that creates a new blockchain instance.
    pub fn new(difficulty: u32) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(Self {
            transaction_pool: TransactionPool::new(),
            blocks: HashMap::new(),
            pruned: HashSet::new(),
            accounts: HashMap::new(),
            auctions: HashMap::new(),
            longest_chain: vec![],
            commited_pointer: 0,
            difficulty,
        })
    }

    /// Function that checks if the block received exists.
    fn has_previous_block(&self, previous_hash: &str) -> bool {
        if previous_hash == "0" {
            return true;
        }

        match self.blocks.iter().find(|(_, b)| b.hash == previous_hash) {
            Some(_) => true,
            _ => false,
        }
    }

    /// Function that pushes a block.
    fn push_block(&mut self, block: Block) {
        self.blocks.insert(block.hash.clone(), block);
    }

    /// Function that accepts a block proposed by another node.
    pub fn accept_block(
        &mut self,
        block: Block,
        notifiers: &HashMap<String, Arc<(Notify, AtomicBool)>>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if self.blocks.contains_key(&block.hash) {
            return Err("Already known block.".into());
        }

        if self.pruned.contains(&block.hash) {
            return Err(AcceptBlockError::Pruned.into());
        }

        if self.pruned.contains(&block.previous_hash) {
            return Err(AcceptBlockError::PrunedParent.into());
        }

        if !block.verify()? {
            return Err(AcceptBlockError::InvalidHash.into());
        }

        if !self.has_previous_block(&block.previous_hash) {
            return Err(AcceptBlockError::Orphan.into());
        }

        if merkle::root(&block.transactions)? != block.merkle_root {
            return Err(AcceptBlockError::WrongTransactionOrder.into());
        }

        self.verify()?;

        self.push_block(block);

        self.fix(notifiers)?;

        Ok(())
    }

    fn execute_single_transaction(
        &mut self,
        transaction: &Transaction,
        block_hash: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        transaction.verify()?;

        match &transaction.record {
            Data::CreateUserAccount { public_key } => {
                if transaction.from != *public_key {
                    return Err("Create account sender mismatch.".into());
                }

                if transaction.nonce != 0 {
                    return Err("Create account nonce must be 0.".into());
                }

                self.create_account(public_key.clone())?;
            }

            Data::Bid { .. } => {
                let account = self
                    .get_account_mut(&transaction.from)
                    .ok_or("Unknown account.")?;

                if transaction.nonce != account.nonce {
                    return Err("Invalid nonce.".into());
                }

                account.nonce += 1;
            }

            Data::CreateAuction {
                auction_id,
                stop_time,
                ..
            } => {
                let account = self
                    .get_account_mut(&transaction.from)
                    .ok_or("Unknown account.")?;

                if transaction.nonce != account.nonce {
                    return Err("Invalid nonce.".into());
                }

                account.nonce += 1;

                self.create_auction(auction_id, &block_hash, *stop_time);
            }

            Data::StopAuction { auction_id } => {
                if let Some(start_auction_transaction) = self.get_auction(auction_id) {
                    if let Data::CreateAuction { stop_time, .. } = start_auction_transaction.record
                    {
                        if transaction.timestamp < stop_time
                            && transaction.from != start_auction_transaction.from
                        {
                            return Err("Only the creator can end the auction early.".into());
                        }
                    }
                }

                let account = self
                    .get_account_mut(&transaction.from)
                    .ok_or("Unknown account.")?;

                if transaction.nonce != account.nonce {
                    return Err("Invalid nonce.".into());
                }

                account.nonce += 1;

                self.remove_auction(auction_id);
            }
        }

        Ok(())
    }

    /// Function that notifies RPC clients that the transaction was validated.
    fn execute_transactions(&mut self, notifiers: &HashMap<String, Arc<(Notify, AtomicBool)>>) {
        let mut count = 0;
        for i in self.commited_pointer
            ..(self
                .longest_chain
                .len()
                .saturating_sub(EXECUTE_AFTER_N_BLOCKS))
        {
            let h = &self.longest_chain[i];
            if let Some(b) = self.blocks.get(h).cloned() {
                for t in b.transactions.clone() {
                    let executed = match self.execute_single_transaction(&t, &b.hash) {
                        Ok(()) => true,
                        Err(e) => {
                            tracing::warn!("Rejected transaction {}: {}", t.id, e);
                            false
                        }
                    };

                    if let Some(notify) = notifiers.get(&t.id) {
                        notify.0.notify_one();
                        notify
                            .1
                            .store(executed, std::sync::atomic::Ordering::SeqCst);
                    }
                }
            }
            count += 1;
        }
        self.commited_pointer += count;
    }

    /// Function that appends a block to the blockchain.
    pub fn propose_block(
        &mut self,
        public_key: &str,
        notifiers: &HashMap<String, Arc<(Notify, AtomicBool)>>,
    ) -> Result<Block, Box<dyn Error + Send + Sync>> {
        let transactions = self.transaction_pool.flush();

        if transactions.len() == 0 {
            return Err(
                "There needs to be at least one transaction for a block to be generated.".into(),
            );
        }

        let previous_block_hash = self.longest_chain.last().cloned();

        let block_to_append = Block::new(
            public_key.to_string(),
            previous_block_hash,
            transactions,
            self.difficulty,
        )?;

        if !block_to_append.verify()? {
            return Err("Failed to produce a valid block.".into());
        }

        self.push_block(block_to_append.clone());

        self.fix(notifiers)?;

        Ok(block_to_append)
    }

    /// Function that verifies each block in the blockchain's longest chain.
    pub fn verify(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        for h in self.longest_chain.iter() {
            if let Some(b) = self.blocks.get(h)
                && b.verify()?
            {
            } else {
                return Err("Couldn't find a block of the longest chain.".into());
            }
        }

        Ok(())
    }

    /// Function that checks if a block has a given transaction.
    pub fn has_transaction(&self, transaction: &Transaction) -> bool {
        self.blocks
            .iter()
            .any(|(_, b)| b.transactions.contains(transaction))
    }

    /// Function that finds the longest chain by looking at all the blockchain's branches.
    fn find_longest_branch(branch_map: &HashMap<String, Vec<String>>, prev_h: &str) -> Vec<String> {
        let mut result = vec![prev_h.to_string()];

        fn min_hash(a: &str, b: &str) -> Ordering {
            let a = BigUint::from_bytes_le(
                &hex::decode(a).expect("Shouldn't be able to get hashes that are not in hex!"),
            );
            let b = BigUint::from_bytes_le(
                &hex::decode(b).expect("Shouldn't be able to get hashes that are not in hex!"),
            );

            a.cmp(&b)
        }

        if let Some(leaves) = branch_map.get(prev_h) {
            let winner = leaves
                .iter()
                .map(|leaf| Self::find_longest_branch(branch_map, leaf))
                .max_by(|a, b| {
                    a.len()
                        .cmp(&b.len())
                        .then_with(|| min_hash(b.last().unwrap(), a.last().unwrap()))
                })
                .unwrap_or_default();

            result.extend(winner);
        }

        result
    }

    /// Function that prunes every block that belongs to a branch beaten by longest chain
    /// and whose forking point from longest chain is before EXECUTE_AFTER_N_BLOCKS from end.
    pub fn prune(
        &mut self,
        branch_map: &HashMap<String, Vec<String>>,
        notifiers: &HashMap<String, Arc<(Notify, AtomicBool)>>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if self.longest_chain.len() < EXECUTE_AFTER_N_BLOCKS {
            return Ok(());
        }

        let longest_chain: HashSet<&String> = self.longest_chain.iter().collect();
        let mut losers = Vec::new();

        for i in 0..(self.longest_chain.len() - EXECUTE_AFTER_N_BLOCKS) {
            let parent = self.longest_chain[i].clone();
            if let Some(cs) = branch_map.get(&parent) {
                for c in cs {
                    if !longest_chain.contains(c) {
                        losers.push(c.clone());
                    }
                }
            }
        }

        let mut bin: HashSet<String> = losers.clone().into_iter().collect();

        while let Some(h) = losers.pop() {
            if let Some(cs) = branch_map.get(&h) {
                for c in cs {
                    if bin.insert(c.clone()) {
                        losers.push(c.clone());
                    }
                }
            }
        }

        for h in bin {
            self.pruned.insert(h.clone());

            if let Some(b) = self.blocks.get(&h) {
                b.transactions.iter().for_each(|t| {
                    if let Some(notify) = notifiers.get(&t.id) {
                        notify.0.notify_one();
                    }
                });
            }

            self.blocks.remove(&h);
        }

        Ok(())
    }

    /// Function that fixes the blockchain by analysing all branches and choosing the one with smallest hash
    /// or the one that is longest if it has grown more that the constant defined.
    pub fn fix(
        &mut self,
        notifiers: &HashMap<String, Arc<(Notify, AtomicBool)>>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // construct branch map

        let mut branch_map: HashMap<String, Vec<String>> = HashMap::new();
        self.blocks.iter().for_each(|(h, b)| {
            if let Some(v) = branch_map.get_mut(&b.previous_hash) {
                v.push(h.clone());
            } else {
                branch_map.insert(b.previous_hash.clone(), vec![h.clone()]);
            }
        });

        // find longest chain

        self.longest_chain = Self::find_longest_branch(&branch_map, "0")[1..].to_vec();

        // prune

        self.prune(&branch_map, notifiers)?;

        self.execute_transactions(notifiers);

        Ok(())
    }

    /// Function that adds transaction to transaction pool.
    pub fn add_transaction(
        &mut self,
        transaction: Transaction,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        transaction.verify()?;

        if self.has_transaction(&transaction) {
            return Err("Transaction already recorded.".into());
        }

        if self.transaction_pool.contains(&transaction) {
            return Err("Transaction already pending.".into());
        }

        match &transaction.record {
            Data::CreateUserAccount { public_key } => {
                if transaction.from != *public_key {
                    return Err("Create account sender mismatch.".into());
                }

                if transaction.nonce != 0 {
                    return Err("Create account nonce must be 0.".into());
                }

                if self.accounts.contains_key(public_key) {
                    return Err("Account already exists.".into());
                }
            }

            _ => {
                let expected_nonce = self
                    .accounts
                    .get(&transaction.from)
                    .map(|account| account.nonce)
                    .ok_or("Unknown account.")?;

                if transaction.nonce < expected_nonce {
                    return Err("Nonce already used.".into());
                }

                if self.transaction_pool.replay(&transaction) {
                    return Err("Duplicate pending nonce.".into());
                }
            }
        }

        self.transaction_pool.add_transaction(transaction)?;

        Ok(())
    }
}

pub trait WorldState {
    fn get_account(&self, public_key: &str) -> Option<&Account>;
    fn get_account_mut(&mut self, public_key: &str) -> Option<&mut Account>;
    fn create_account(&mut self, public_key: String) -> Result<(), Box<dyn Error + Send + Sync>>;
    fn create_auction(&mut self, auction_id: &str, block_id: &str, stop_time: u64);
    fn get_auction(&mut self, auction_id: &str) -> Option<&Transaction>;
    fn remove_auction(&mut self, auction_id: &str);
    fn get_block_from_hash(&self, hash: &str) -> Option<&Block>;
    fn get_next_block_hash_from_hash(&self, hash: &str) -> Option<&String>;
}

impl WorldState for Blockchain {
    fn get_account(&self, public_key: &str) -> Option<&Account> {
        self.accounts.get(public_key)
    }

    fn get_account_mut(&mut self, public_key: &str) -> Option<&mut Account> {
        self.accounts.get_mut(public_key)
    }

    fn get_auction(&mut self, auction_id: &str) -> Option<&Transaction> {
        if let Some((block_id, _)) = self.auctions.get(auction_id) {
            if let Some(block) = self.blocks.get(block_id) {
                return block.transactions.iter().find(|t| {
                    if let Data::CreateAuction {
                        auction_id: aid, ..
                    } = &t.record
                        && aid == auction_id
                    {
                        true
                    } else {
                        false
                    }
                });
            }
        }
        None
    }

    fn get_block_from_hash(&self, hash: &str) -> Option<&Block> {
        if self.longest_chain[0..(self
            .longest_chain
            .len()
            .saturating_sub(EXECUTE_AFTER_N_BLOCKS))]
            .contains(&hash.to_string())
        {
            self.blocks.get(hash)
        } else {
            None
        }
    }

    fn get_next_block_hash_from_hash(&self, hash: &str) -> Option<&String> {
        if let Some(i) = self.longest_chain[0..(self
            .longest_chain
            .len()
            .saturating_sub(EXECUTE_AFTER_N_BLOCKS))]
            .iter()
            .enumerate()
            .fold(None, |acc, (i, h)| {
                if h == &hash.to_string() {
                    Some(i + 1)
                } else {
                    acc
                }
            })
        {
            self.longest_chain.get(i)
        } else {
            None
        }
    }

    fn create_auction(&mut self, auction_id: &str, block_id: &str, stop_time: u64) {
        self.auctions
            .insert(auction_id.to_string(), (block_id.to_string(), stop_time));
    }

    fn remove_auction(&mut self, auction_id: &str) {
        self.auctions.remove(auction_id);
    }

    fn create_account(&mut self, public_key: String) -> Result<(), Box<dyn Error + Send + Sync>> {
        info!("Creating Account: {}", public_key);

        if self.accounts.contains_key(&public_key) {
            return Err("Account already exists.".into());
        }

        self.accounts.insert(
            public_key.clone(),
            Account {
                public_key,
                nonce: 1,
            },
        );

        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use crate::blockchain::block::Block;
    use crate::blockchain::hash::{encode_hash, hash};
    use crate::blockchain::merkle::root;
    use crate::blockchain::transaction::TransactionPool;
    use crate::blockchain::{Blockchain, WorldState};
    use crate::blockchain::{
        ed25519::public_key_to_string,
        transaction::{Data, Transaction},
    };
    use blake2::{Blake2b512, Digest};
    use ed25519_dalek_blake2b::Keypair;
    use rand::rngs::OsRng;
    use std::collections::HashMap;
    use std::error::Error;

    /* Hash */

    #[test]
    fn test_hash() {
        let to_hash = "I am not in danger, Skyler. I am the danger.";
        let hashed = hash(Blake2b512::new(), to_hash);

        assert_eq!(
            encode_hash(&hashed),
            "3a141d45dea6b8af5bab5f942d88f3c0d48edcda84fac341d821d13d65896e2a7d5a8ec921da654301e72db33631fd94963e064056172f4d970a77625aa7ed93"
        );
    }

    /* Transaction */

    /// Tests that a correctly signed transaction passes verification.
    #[test]
    fn test_transaction_valid_signature_verifies() -> Result<(), Box<dyn Error + Send + Sync>> {
        let k = generate_keypair();
        let t = signed_create_account_tx(&k, 0)?;
        assert!(t.verify().is_ok());
        Ok(())
    }

    /// Tests that tampering with the nonce after signing invalidates the transaction.
    #[test]
    fn test_transaction_tampered_nonce_fails_verification()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let k = generate_keypair();
        let mut t = signed_create_account_tx(&k, 0)?;
        t.nonce = 999;
        assert!(t.verify().is_err());
        Ok(())
    }

    /// Tests that tampering with the record after signing invalidates the transaction.
    #[test]
    fn test_transaction_tampered_record_fails_verification()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let k = generate_keypair();
        let mut t = signed_create_account_tx(&k, 0)?;
        t.record = Data::CreateUserAccount {
            public_key: "imposter".to_string(),
        };
        assert!(t.verify().is_err());
        Ok(())
    }

    /// Tests that a transaction signed by one keypair cannot be verified with another keypair's public key.
    #[test]
    fn test_transaction_wrong_keypair_fails_verification()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let k1 = generate_keypair();
        let k2 = generate_keypair();
        let mut t = signed_create_account_tx(&k1, 0)?;
        t.from = public_key_to_string(&k2.public); // swap sender to different key
        assert!(t.verify().is_err());
        Ok(())
    }

    /// Tests that two different transactions produce different IDs.
    #[test]
    fn test_transaction_unique_ids() -> Result<(), Box<dyn Error + Send + Sync>> {
        let k1 = generate_keypair();
        let k2 = generate_keypair();
        let t1 = signed_create_account_tx(&k1, 0)?;
        let t2 = signed_create_account_tx(&k2, 0)?;
        assert_ne!(t1.id, t2.id);
        Ok(())
    }

    /// Tests that flush() drains the pool and returns all transactions sorted by timestamp.
    #[test]
    fn test_pool_flush_returns_transactions_and_empties_pool()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let k1 = generate_keypair();
        let k2 = generate_keypair();
        let t1 = signed_create_account_tx(&k1, 0)?;
        let t2 = signed_create_account_tx(&k2, 0)?;
        let mut pool = TransactionPool::new();
        pool.add_transaction(t1.clone())?;
        pool.add_transaction(t2.clone())?;
        let queue = pool.flush();
        assert_eq!(queue.len(), 2);
        assert_eq!(pool.len(), 0);
        // verify sorted by timestamp
        assert!(queue[0].timestamp <= queue[1].timestamp);
        Ok(())
    }

    /* TransactionPool */

    /// Tests that replay() propperly detects duplicate nonces for same sender.
    #[test]
    fn test_pool_replay_detects_same_sender_same_nonce() -> Result<(), Box<dyn Error + Send + Sync>>
    {
        let k = generate_keypair();
        let pk = public_key_to_string(&k.public);

        let tx1 = Transaction::sign(
            Data::CreateAuction {
                auction_id: "a1".to_string(),
                start_amount: 10,
                stop_time: 9999999999,
            },
            &pk,
            1,
            &k,
        )?;

        let tx2 = Transaction::sign(
            Data::CreateAuction {
                auction_id: "a2".to_string(),
                start_amount: 20,
                stop_time: 9999999999,
            },
            &pk,
            1,
            &k,
        )?;

        let mut pool = TransactionPool::new();
        pool.add_transaction(tx1)?;

        assert!(pool.replay(&tx2));

        Ok(())
    }

    /// Tests that remove() correctly deletes a transaction from the pool by timestamp.
    #[test]
    fn test_pool_remove_deletes_transaction() -> Result<(), Box<dyn Error + Send + Sync>> {
        let k = generate_keypair();
        let t = signed_create_account_tx(&k, 0)?;
        let mut pool = TransactionPool::new();
        pool.add_transaction(t.clone())?;
        pool.remove(t.id.clone());
        assert_eq!(pool.len(), 0);
        assert!(!pool.contains(&t));
        Ok(())
    }

    /// Tests that a transaction added to the pool can be found via contains().
    #[test]
    fn test_pool_added_transaction_is_contained() -> Result<(), Box<dyn Error + Send + Sync>> {
        let k = generate_keypair();
        let t = signed_create_account_tx(&k, 0)?;
        let mut pool = TransactionPool::new();
        pool.add_transaction(t.clone())?;
        assert!(pool.contains(&t));
        Ok(())
    }

    /* Blocks */

    /// Tests that a freshly mined block passes its own verification.
    #[test]
    fn test_block_mined_block_is_valid() -> Result<(), Box<dyn Error + Send + Sync>> {
        let k = generate_keypair();
        let pk = public_key_to_string(&k.public);
        let t = signed_create_account_tx(&k, 0)?;
        let block = Block::new(pk, None, vec![t], u32::MAX)?;
        assert!(block.verify()?);
        Ok(())
    }

    /// Tests that tampering with the nonce after mining invalidates the block.
    #[test]
    fn test_block_tampered_nonce_fails_verification() -> Result<(), Box<dyn Error + Send + Sync>> {
        let k = generate_keypair();
        let pk = public_key_to_string(&k.public);
        let t = signed_create_account_tx(&k, 0)?;
        let mut block = Block::new(pk, None, vec![t], u32::MAX)?;
        block.nonce = block.nonce.wrapping_add(1);
        assert!(!block.verify()?);
        Ok(())
    }

    /// Tests that replacing the stored hash with a different value fails verification.
    #[test]
    fn test_block_tampered_hash_fails_verification() -> Result<(), Box<dyn Error + Send + Sync>> {
        let k = generate_keypair();
        let pk = public_key_to_string(&k.public);
        let t = signed_create_account_tx(&k, 0)?;
        let mut block = Block::new(pk, None, vec![t], u32::MAX)?;
        block.hash = "00".repeat(64);
        assert!(!block.verify()?);
        Ok(())
    }

    /// Tests that tampering with a transaction inside a mined block fails verification.
    #[test]
    fn test_block_tampered_transaction_fails_verification()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let k = generate_keypair();
        let pk = public_key_to_string(&k.public);
        let t = signed_create_account_tx(&k, 0)?;
        let mut block = Block::new(pk, None, vec![t], u32::MAX)?;
        block.transactions[0].nonce = 999;
        assert!(!block.verify()?);
        Ok(())
    }

    /// Test that block with transactions reordered is rejected.
    #[test]
    fn test_block_verify_rejects_transaction_reordering() -> Result<(), Box<dyn Error + Send + Sync>>
    {
        let k1 = generate_keypair();
        let k2 = generate_keypair();

        let pk = public_key_to_string(&k1.public);

        let tx1 = signed_create_account_tx(&k1, 0)?;
        let tx2 = signed_create_account_tx(&k2, 0)?;

        let mut block = Block::new(pk, None, vec![tx1.clone(), tx2.clone()], u32::MAX)?;
        block.transactions = vec![tx2, tx1];

        assert!(!block.verify()?);

        Ok(())
    }

    /* Merkle */

    /// Test that merkle root gives same output always for same input
    #[test]
    fn test_merkle_root_is_deterministic() -> Result<(), Box<dyn Error + Send + Sync>> {
        let k1 = generate_keypair();
        let k2 = generate_keypair();

        let txs = vec![
            signed_create_account_tx(&k1, 0)?,
            signed_create_account_tx(&k2, 0)?,
        ];

        assert_eq!(root(&txs)?, root(&txs)?);

        Ok(())
    }

    /// Test that merkle root changes when the ordering of transactions changes.
    #[test]
    fn test_merkle_root_changes_when_order_changes() -> Result<(), Box<dyn Error + Send + Sync>> {
        let k1 = generate_keypair();
        let k2 = generate_keypair();

        let tx1 = signed_create_account_tx(&k1, 0)?;
        let tx2 = signed_create_account_tx(&k2, 0)?;

        let a = vec![tx1.clone(), tx2.clone()];
        let b = vec![tx2, tx1];

        assert_ne!(root(&a)?, root(&b)?);

        Ok(())
    }

    /// Test that merkle root fails when there are no transactions.
    #[test]
    fn test_merkle_root_empty_transactions_fails() {
        let txs: Vec<Transaction> = vec![];
        assert!(root(&txs).is_err());
    }

    /* WorldState */

    /// Tests that a created account can be retrieved and a non-existent one returns None.
    #[test]
    fn test_worldstate_account_creation_and_lookup() -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut chain = Blockchain::new(u32::MAX)?;
        chain.create_account("walter_pk".to_string())?;
        assert!(chain.get_account("walter_pk").is_some());
        assert!(chain.get_account("jesse_pk").is_none());
        Ok(())
    }

    /// Tests that attempting to create an account with an already existing public key fails.
    #[test]
    fn test_worldstate_duplicate_account_is_rejected() -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut chain = Blockchain::new(u32::MAX)?;
        chain.create_account("walter_pk".to_string())?;
        assert!(chain.create_account("walter_pk".to_string()).is_err());
        assert_eq!(chain.accounts.len(), 1);
        Ok(())
    }

    /* accept_block() */

    /// Tests that accept_block() rejects a block whose hash does not satisfy PoW.
    #[test]
    fn test_accept_block_rejects_invalid_pow() -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut chain = Blockchain::new(u32::MAX)?;
        let shady_block = Block {
            previous_hash: "0".to_string(),
            transactions: vec![],
            merkle_root: "".to_string(),
            hash: "not_a_valid_pow_hash".to_string(),
            nonce: 0,
            timestamp: 1,
            miner: "".to_string(),
        };
        assert!(chain.accept_block(shady_block, &HashMap::new()).is_err());
        Ok(())
    }

    /// Tests that accept_block() rejects a block that does not point to the current chain tip.
    #[test]
    fn test_accept_block_rejects_wrong_previous_hash() -> Result<(), Box<dyn Error + Send + Sync>> {
        let k = generate_keypair();
        let pk = public_key_to_string(&k.public);
        let t = signed_create_account_tx(&k, 0)?;
        let mut block = Block::new(pk.clone(), None, vec![t.clone()], u32::MAX)?;
        block.previous_hash = "wrong".to_string();

        let mut chain = Blockchain::new(u32::MAX)?;
        chain.transaction_pool.add_transaction(t)?;

        assert!(chain.accept_block(block, &HashMap::new()).is_err());
        Ok(())
    }

    /// Tests that accept_block() rejects a block whose transactions are not in the treansaction pool.
    #[test]
    fn test_accept_block_rejects_transactions_not_in_transaction_pool()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let k = generate_keypair();
        let pk = public_key_to_string(&k.public);
        let t = signed_create_account_tx(&k, 0)?;
        let block = Block::new(pk.clone(), None, vec![t], u32::MAX)?;

        let mut chain = Blockchain::new(u32::MAX)?;
        chain.create_account(pk)?;
        // intentionally not adding t to the transaction pool

        assert!(chain.accept_block(block, &HashMap::new()).is_err());
        Ok(())
    }

    /// Tests that accept_block() rejects a block proposed by an unknown miner.
    #[test]
    fn test_accept_block_rejects_unknown_miner() -> Result<(), Box<dyn Error + Send + Sync>> {
        let k = generate_keypair();
        let pk = public_key_to_string(&k.public);
        let t = signed_create_account_tx(&k, 0)?;
        let block = Block::new(pk.clone(), None, vec![t.clone()], u32::MAX)?;

        let mut chain = Blockchain::new(u32::MAX)?;
        chain.transaction_pool.add_transaction(t)?;
        // intentionally not registering pk as an account

        assert!(chain.accept_block(block, &HashMap::new()).is_err());
        Ok(())
    }

    /* Blockchain */

    /// Tests that an empty blockchain passes verification.
    #[test]
    fn test_blockchain_empty_chain_is_valid() -> Result<(), Box<dyn Error + Send + Sync>> {
        let chain = Blockchain::new(u32::MAX)?;
        chain.verify()?;
        Ok(())
    }

    /// Tests that propose_block() mines, commits the block, and the chain remains valid.
    #[test]
    fn test_blockchain_propose_block_grows_chain() -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut chain = Blockchain::new(u32::MAX)?;
        let k = generate_keypair();
        let pk = public_key_to_string(&k.public);
        let t = signed_create_account_tx(&k, 0)?;
        chain.transaction_pool.add_transaction(t)?;
        chain.propose_block(&pk, &HashMap::new())?;
        assert_eq!(chain.blocks.len(), 1);
        chain.verify()?;
        Ok(())
    }

    /// Tests that propose_block() fails when the transaction pool is empty.
    #[test]
    fn test_blockchain_propose_block_fails_with_empty_mempool()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut chain = Blockchain::new(u32::MAX)?;
        let k = generate_keypair();
        let pk = public_key_to_string(&k.public);
        assert!(chain.propose_block(&pk, &HashMap::new()).is_err());
        Ok(())
    }

    /// Tests that propose_block() correctly executes transactions, creating the account on-chain.
    #[test]
    fn test_blockchain_propose_block_executes_transactions()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut chain = Blockchain::new(u32::MAX)?;
        let k = generate_keypair();
        let pk = public_key_to_string(&k.public);
        let t = signed_create_account_tx(&k, 0)?;
        chain.transaction_pool.add_transaction(t)?;
        chain.propose_block(&pk, &HashMap::new())?;
        assert!(chain.get_account(&pk).is_some());
        Ok(())
    }

    /// Tests that a multi-block chain remains valid after sequential propose_block() calls.
    #[test]
    fn test_blockchain_multi_block_chain_is_valid() -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut chain = Blockchain::new(u32::MAX)?;
        for _ in 0..3 {
            let k = generate_keypair();
            let pk = public_key_to_string(&k.public);
            let t = signed_create_account_tx(&k, 0)?;
            chain.transaction_pool.add_transaction(t)?;
            chain.propose_block(&pk, &HashMap::new())?;
        }
        assert_eq!(chain.blocks.len(), 3);
        chain.verify()?;
        Ok(())
    }

    /// Tests that fix() direcly returns longest chain as was on a linear chain with no forks.
    #[test]
    fn test_blockchain_fix_is_noop_on_linear_chain() -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut chain = Blockchain::new(u32::MAX)?;
        let k = generate_keypair();
        let pk = public_key_to_string(&k.public);
        let t = signed_create_account_tx(&k, 0)?;
        chain.transaction_pool.add_transaction(t)?;
        chain.propose_block(&pk, &HashMap::new())?;
        let before = chain.blocks.clone();
        chain.fix(&HashMap::new())?;
        assert_eq!(chain.blocks, before);
        Ok(())
    }

    /// Tests that fix() resolves a fork by keeping the winning branch and returning
    /// the discarded branch's transactions to the transaction pool.
    #[test]
    fn test_blockchain_fix_resolves_fork() -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut blockchain = Blockchain::new(u32::MAX)?;

        let t1 = Transaction::new(
            Data::CreateUserAccount {
                public_key: "skylar".to_string(),
            },
            "walter".to_string(),
            0,
            "i'm the one who knocks",
        )?;

        // b1 and b2 both point to genesis — fork at block 0
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
        // b3 extends b2 (the losing branch)
        let b3 = Block {
            previous_hash: "22".to_string(),
            transactions: vec![t1.clone()],
            merkle_root: "".to_string(),
            hash: "33".to_string(),
            nonce: 0,
            timestamp: 1,
            miner: "".to_string(),
        };

        blockchain.blocks.insert(b1.hash.clone(), b1.clone());
        blockchain.blocks.insert(b2.hash.clone(), b2.clone());
        blockchain.blocks.insert(b3.hash.clone(), b3.clone());

        blockchain.fix(&HashMap::new())?;

        let mut blocks: HashMap<String, Block> = HashMap::new();
        blocks.insert(b1.hash.clone(), b1.clone());

        // b1 wins (0x11 < 0x22), b2+b3 are discarded, t1 goes back to mempool
        assert_eq!(blockchain.blocks, blocks);
        assert_eq!(blockchain.transaction_pool.flush(), vec![t1]);
        Ok(())
    }

    /// Test that blockchain create account is not executed until two new blocks
    /// are added to longest chain (due to EXECUTE_AFTER_N_BLOCKS)
    #[test]
    fn test_blockchain_account_is_not_executed_until_two_confirmations()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut chain = Blockchain::new(u32::MAX)?;

        let k1 = generate_keypair();
        let pk1 = public_key_to_string(&k1.public);

        mine_create_account(&mut chain, &k1)?;
        assert!(chain.get_account(&pk1).is_none());

        mine_create_account(&mut chain, &generate_keypair())?;
        assert!(chain.get_account(&pk1).is_none());

        mine_create_account(&mut chain, &generate_keypair())?;
        assert!(chain.get_account(&pk1).is_some());

        Ok(())
    }

    /// Tests that a created account can later submit a valid nonce transaction,
    /// and that the account nonce is incremented only after confirmation.
    #[test]
    fn test_blockchain_create_account_then_valid_nonce_transaction_flow()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut chain = Blockchain::new(u32::MAX)?;

        let user = generate_keypair();
        let user_pk = public_key_to_string(&user.public);

        mine_create_account(&mut chain, &user)?;
        mine_create_account(&mut chain, &generate_keypair())?;
        mine_create_account(&mut chain, &generate_keypair())?;

        assert_eq!(chain.get_account(&user_pk).unwrap().nonce, 1);

        let tx = Transaction::sign(
            Data::CreateAuction {
                auction_id: "auction-1".to_string(),
                start_amount: 10,
                stop_time: 9999999999,
            },
            &user_pk,
            1,
            &user,
        )?;

        chain.add_transaction(tx)?;
        chain.propose_block(&user_pk, &HashMap::new())?;

        mine_create_account(&mut chain, &generate_keypair())?;
        mine_create_account(&mut chain, &generate_keypair())?;

        assert_eq!(chain.get_account(&user_pk).unwrap().nonce, 2);

        Ok(())
    }

    /// Tests that transactions from accounts that do not exist are rejected from the transaction pool.
    #[test]
    fn test_blockchain_rejects_unknown_account_transaction()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut chain = Blockchain::new(u32::MAX)?;

        let k = generate_keypair();
        let pk = public_key_to_string(&k.public);

        let tx = Transaction::sign(
            Data::CreateAuction {
                auction_id: "auction-1".to_string(),
                start_amount: 10,
                stop_time: 9999999999,
            },
            &pk,
            1,
            &k,
        )?;

        assert!(chain.add_transaction(tx).is_err());

        Ok(())
    }

    /// Tests that a transaction with an already-used nonce is rejected after account execution.
    #[test]
    fn test_blockchain_rejects_old_nonce_after_execution()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut chain = Blockchain::new(u32::MAX)?;

        let user = generate_keypair();
        let user_pk = public_key_to_string(&user.public);

        mine_create_account(&mut chain, &user)?;
        mine_create_account(&mut chain, &generate_keypair())?;
        mine_create_account(&mut chain, &generate_keypair())?;

        let tx = Transaction::sign(
            Data::CreateAuction {
                auction_id: "auction-1".to_string(),
                start_amount: 10,
                stop_time: 9999999999,
            },
            &user_pk,
            0,
            &user,
        )?;

        assert!(chain.add_transaction(tx).is_err());

        Ok(())
    }

    /// Tests that an invalid transaction included in a mined block does not mutate account state.
    #[test]
    fn test_blockchain_invalid_transaction_inside_block_does_not_execute()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut chain = Blockchain::new(u32::MAX)?;

        let user = generate_keypair();
        let user_pk = public_key_to_string(&user.public);

        mine_create_account(&mut chain, &user)?;
        mine_create_account(&mut chain, &generate_keypair())?;
        mine_create_account(&mut chain, &generate_keypair())?;

        let bad_tx = Transaction::sign(
            Data::CreateAuction {
                auction_id: "bad-auction".to_string(),
                start_amount: 10,
                stop_time: 9999999999,
            },
            &user_pk,
            99,
            &user,
        )?;

        chain.transaction_pool.add_transaction(bad_tx)?;
        chain.propose_block(&user_pk, &HashMap::new())?;

        mine_create_account(&mut chain, &generate_keypair())?;
        mine_create_account(&mut chain, &generate_keypair())?;

        assert_eq!(chain.get_account(&user_pk).unwrap().nonce, 1);

        Ok(())
    }

    /* Attacks */

    /// Tests that transactions with malformed or invalid signatures are rejected from the transaction pool.
    #[test]
    fn test_blockchain_propose_block_fails_with_empty_transaction_pool()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut chain = Blockchain::new(u32::MAX)?;

        let k = generate_keypair();
        let mut tx = signed_create_account_tx(&k, 0)?;
        tx.signature = "deadbeef".to_string();

        assert!(chain.add_transaction(tx).is_err());

        Ok(())
    }

    /// Tests that an attacker cannot create an account for another public key.
    #[test]
    fn test_attack_create_account_sender_mismatch_rejected()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut chain = Blockchain::new(u32::MAX)?;

        let attacker = generate_keypair();
        let victim = generate_keypair();

        let attacker_pk = public_key_to_string(&attacker.public);
        let victim_pk = public_key_to_string(&victim.public);

        let tx = Transaction::sign(
            Data::CreateUserAccount {
                public_key: victim_pk,
            },
            &attacker_pk,
            0,
            &attacker,
        )?;

        assert!(chain.add_transaction(tx).is_err());

        Ok(())
    }

    /// Tests that account creation transactions must use nonce zero.
    #[test]
    fn test_attack_create_account_with_non_zero_nonce_rejected()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut chain = Blockchain::new(u32::MAX)?;

        let k = generate_keypair();
        let tx = signed_create_account_tx(&k, 1)?;

        assert!(chain.add_transaction(tx).is_err());

        Ok(())
    }

    /// Tests that two pending transactions from the same sender cannot use the same nonce.
    #[test]
    fn test_attack_duplicate_pending_nonce_rejected() -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut chain = Blockchain::new(u32::MAX)?;

        let user = generate_keypair();
        let user_pk = public_key_to_string(&user.public);

        mine_create_account(&mut chain, &user)?;
        mine_create_account(&mut chain, &generate_keypair())?;
        mine_create_account(&mut chain, &generate_keypair())?;

        let tx1 = Transaction::sign(
            Data::CreateAuction {
                auction_id: "auction-a".to_string(),
                start_amount: 10,
                stop_time: 9999999999,
            },
            &user_pk,
            1,
            &user,
        )?;

        let tx2 = Transaction::sign(
            Data::CreateAuction {
                auction_id: "auction-b".to_string(),
                start_amount: 20,
                stop_time: 9999999999,
            },
            &user_pk,
            1,
            &user,
        )?;

        chain.add_transaction(tx1)?;
        assert!(chain.add_transaction(tx2).is_err());

        Ok(())
    }

    /// Tests that a transaction already recorded on-chain cannot be replayed into the transaction pool.
    #[test]
    fn test_attack_replay_recorded_transaction_rejected() -> Result<(), Box<dyn Error + Send + Sync>>
    {
        let mut chain = Blockchain::new(u32::MAX)?;

        let k = generate_keypair();
        let pk = public_key_to_string(&k.public);
        let tx = signed_create_account_tx(&k, 0)?;

        chain.add_transaction(tx.clone())?;
        chain.propose_block(&pk, &HashMap::new())?;

        assert!(chain.add_transaction(tx).is_err());

        Ok(())
    }

    /// Tests that accept_block() rejects a block whose Merkle root was tampered with.
    #[test]
    fn test_attack_accept_block_with_tampered_merkle_root_rejected()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let miner = generate_keypair();
        let miner_pk = public_key_to_string(&miner.public);

        let tx = signed_create_account_tx(&miner, 0)?;
        let mut block = Block::new(miner_pk, None, vec![tx], u32::MAX)?;
        block.merkle_root = "bad-root".to_string();

        let mut chain = Blockchain::new(u32::MAX)?;

        assert!(chain.accept_block(block, &HashMap::new()).is_err());

        Ok(())
    }

    /// Tests that accept_block() rejects the same block when submitted twice.
    #[test]
    fn test_attack_accept_same_block_twice_rejected() -> Result<(), Box<dyn Error + Send + Sync>> {
        let miner = generate_keypair();
        let miner_pk = public_key_to_string(&miner.public);

        let tx = signed_create_account_tx(&miner, 0)?;
        let block = Block::new(miner_pk, None, vec![tx], u32::MAX)?;

        let mut chain = Blockchain::new(u32::MAX)?;

        chain.accept_block(block.clone(), &HashMap::new())?;
        assert!(chain.accept_block(block, &HashMap::new()).is_err());

        Ok(())
    }

    #[test]
    fn test_attack_duplicate_account_creation_rejected() -> Result<(), Box<dyn Error + Send + Sync>>
    {
        let mut chain = Blockchain::new(u32::MAX)?;

        let k = generate_keypair();
        let pk = public_key_to_string(&k.public);

        mine_create_account(&mut chain, &k)?;
        mine_create_account(&mut chain, &generate_keypair())?;
        mine_create_account(&mut chain, &generate_keypair())?;

        assert!(chain.get_account(&pk).is_some());

        let duplicate = signed_create_account_tx(&k, 0)?;
        assert!(chain.add_transaction(duplicate).is_err());

        Ok(())
    }

    /// Tests that a transaction with a future nonce can enter a block,
    /// but is not executed until the account nonce matches.
    #[test]
    fn test_attack_future_nonce_transaction_does_not_execute()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut chain = Blockchain::new(u32::MAX)?;

        let user = generate_keypair();
        let user_pk = public_key_to_string(&user.public);

        mine_create_account(&mut chain, &user)?;
        mine_create_account(&mut chain, &generate_keypair())?;
        mine_create_account(&mut chain, &generate_keypair())?;

        assert_eq!(chain.get_account(&user_pk).unwrap().nonce, 1);

        let future_tx = Transaction::sign(
            Data::CreateAuction {
                auction_id: "future-nonce-auction".to_string(),
                start_amount: 10,
                stop_time: 9999999999,
            },
            &user_pk,
            100,
            &user,
        )?;

        chain.transaction_pool.add_transaction(future_tx)?;
        chain.propose_block(&user_pk, &HashMap::new())?;

        mine_create_account(&mut chain, &generate_keypair())?;
        mine_create_account(&mut chain, &generate_keypair())?;

        assert_eq!(chain.get_account(&user_pk).unwrap().nonce, 1);

        Ok(())
    }

    /// Tests that replaying the same transaction while it is still pending is rejected.
    #[test]
    fn test_attack_duplicate_pending_transaction_rejected()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut chain = Blockchain::new(u32::MAX)?;

        let user = generate_keypair();
        let user_pk = public_key_to_string(&user.public);

        mine_create_account(&mut chain, &user)?;
        mine_create_account(&mut chain, &generate_keypair())?;
        mine_create_account(&mut chain, &generate_keypair())?;

        let tx = Transaction::sign(
            Data::CreateAuction {
                auction_id: "pending-replay".to_string(),
                start_amount: 10,
                stop_time: 9999999999,
            },
            &user_pk,
            1,
            &user,
        )?;

        chain.add_transaction(tx.clone())?;
        assert!(chain.add_transaction(tx).is_err());

        Ok(())
    }

    /* Utility functions */

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
            blockchain.propose_block(&pk, &HashMap::new())?;
        }

        // verify blockchain

        assert!(blockchain.verify().is_ok());

        // verify fix function

        let mut fixed_blockchain = blockchain.clone();
        fixed_blockchain.fix(&HashMap::new())?;

        assert_eq!(blockchain, fixed_blockchain);

        Ok(())
    }

    pub fn signed_create_account_tx(
        keys: &Keypair,
        nonce: u32,
    ) -> Result<Transaction, Box<dyn Error + Send + Sync>> {
        let pk = public_key_to_string(&keys.public);
        Transaction::sign(
            Data::CreateUserAccount {
                public_key: pk.clone(),
            },
            &pk,
            nonce,
            keys,
        )
    }

    pub fn generate_keypair() -> Keypair {
        Keypair::generate(&mut OsRng)
    }

    pub fn mine_create_account(
        chain: &mut Blockchain,
        keys: &Keypair,
    ) -> Result<Block, Box<dyn Error + Send + Sync>> {
        let pk = public_key_to_string(&keys.public);
        let tx = signed_create_account_tx(keys, 0)?;

        chain.add_transaction(tx)?;
        chain.propose_block(&pk, &HashMap::new())
    }
}
