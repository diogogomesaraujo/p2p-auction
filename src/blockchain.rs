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

use crate::blockchain::{
    account::Account,
    block::Block,
    ed25519::string_to_public_key,
    transaction::{Mempool, Transaction},
};
use blake2::Blake2b512;
use ed25519_dalek_blake2b::Signature;
use std::{collections::HashMap, error::Error};

/// Type that defines the hash-function chosen to compute the hashes that will form the blockchain.
///
/// [Blake2](https://web.archive.org/web/20161002114950/http://blake2.net/) was chosen due to its
/// robustness and performance improvements in relation to the SHA-2 family.
type HashFunction = Blake2b512;

pub mod ed25519 {
    use ed25519_dalek_blake2b::PublicKey;
    use std::error::Error;

    pub fn string_to_public_key(
        public_key: &str,
    ) -> Result<PublicKey, Box<dyn Error + Send + Sync>> {
        match PublicKey::from_bytes(&hex::decode(public_key)?) {
            Ok(pk) => Ok(pk),
            Err(e) => Err(e.to_string().into()),
        }
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
        blockchain::{block::UnsignedBlock, transaction::Transaction},
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
                    return Ok((hex::encode(h), nonce, timestamp));
                }
            }
        }
    }

    pub fn verify(hash: Vec<u8>) -> bool {
        puzzle!(hash, TARGET)
    }
}

/// Module that defines the merkle tree structure for lightweight transaction verification
pub mod merkle {
    use crate::blockchain::{
        HashFunction,
        hash::{self, Hashable},
    };
    use blake2::Digest;
    use std::{collections::VecDeque, error::Error};

    /// Enum that represents the side of the sibling node in the tree.
    /// Useful to build and verify Merkle proofs.
    pub enum Side {
        Left,
        Right,
    }

    /// Type that represents a Merkle proof. It is a list of `(Side, hash)` pairs,
    /// one per tree level, where each entry is the sibling hash needed to recompute the root.
    type Proof = Vec<(String, Side)>;

    /// Function that returns the Merkle root of a given set of transactions
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

    /// Function that produces the Merkle proof for the transaction at the given index.
    /// Tree is treated internally as a queue, avoiding the need for a recursive type.
    pub fn proof<T: Hashable>(
        t_idx: usize,
        t: &[T],
    ) -> Result<Proof, Box<dyn Error + Send + Sync>> {
        if t_idx > t.len() {
            return Err("Transaction index was out of bounds".into());
        }
        let mut th = t[t_idx].hash()?;

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

        let mut proof: Proof = Vec::new();

        while tmp.len() > 1 {
            let mut tmp2: VecDeque<String> = VecDeque::new();
            loop {
                match (tmp.pop_front(), tmp.pop_front()) {
                    (Some(l), Some(r)) => {
                        if l == th {
                            proof.push((r.clone(), Side::Right));
                        } else if r == th {
                            proof.push((l.clone(), Side::Left));
                        }
                        th = hash(&l, &r)?;
                        tmp2.push_back(th.clone());
                    }
                    (Some(s), None) => {
                        if s == th {
                            proof.push((s.clone(), Side::Left));
                        }
                        th = hash(&s, &s)?;
                        tmp2.push_back(th.clone());
                    }
                    (None, _) => break,
                }
            }
            tmp = tmp2;
        }

        match tmp.pop_front() {
            Some(_) => Ok(proof),
            _ => return Err("Failed to provide Merkle proof.".into()),
        }
    }

    /// Function which verifies that the given transaction and Merkle proof correctly
    /// produce the target Merkle root.
    pub fn verify<T: Hashable>(
        t: T,
        root: String,
        proof: Proof,
    ) -> Result<bool, Box<dyn Error + Send + Sync>> {
        let result = proof.iter().try_fold(
            t.hash()?,
            |acc, (sibling, side)| -> Result<String, Box<dyn Error + Send + Sync>> {
                match side {
                    Side::Left => hash(sibling, &acc),
                    Side::Right => hash(&acc, sibling),
                }
            },
        )?;
        Ok(result == root)
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
        blockchain::{HashFunction, WorldState, ed25519::string_to_public_key, hash::Hashable},
        time::{Timestamp, now_unix},
    };
    use blake2::Digest;
    use ed25519_dalek_blake2b::{Keypair, Signature, Signer, Verifier};
    use hex::ToHex;
    use serde::{Deserialize, Serialize};
    use std::{
        collections::{HashMap, VecDeque},
        error::Error,
    };

    /// Struct that represents a transaction that can be executed in the blockchain. A transaction can
    /// change the current state of the chain.
    #[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
    pub struct Transaction {
        pub record: Data,
        pub from: String,
        pub created_at: Timestamp,
        pub nonce: u32,
        pub signature: String,
    }

    /// Enum that represents the different kinds of actions that can be performed.
    #[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
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
            nonce: u32,
            keys: &Keypair,
        ) -> Result<Self, Box<dyn Error + Send + Sync>> {
            let signature = Self::sign(&record, &from, &nonce, &keys)?;
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
        fn sign(
            record: &Data,
            from: &String,
            nonce: &u32,
            keys: &Keypair,
        ) -> Result<String, Box<dyn Error + Send + Sync>> {
            let input = Self::serialize(record, from, nonce)?;
            let signature = keys.sign(input.as_bytes());
            Ok(signature.encode_hex())
        }

        /// Function that verifies the validity of a transaction.
        pub fn verify(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
            let pk = string_to_public_key(&self.from)?;
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
        pub fn execute<T: WorldState>(
            &self,
            _state: &mut T,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            // check and increment nonce
            Ok(())
        }
    }

    impl Hashable for Transaction {
        fn hash(&self) -> Result<String, Box<dyn Error + Send + Sync>> {
            let input = serde_json::to_string(self)?;
            let h = crate::blockchain::hash::hash(HashFunction::new(), &input);
            Ok(hex::encode(h))
        }
    }

    /// Type that implements the queue of transactions to be executed and published as a block,
    /// constructed from the mempool and sorted by timestamp.
    pub type Memqueue = VecDeque<Transaction>;

    /// Struct that temporarily holds unexecuted transactions mapped by timestamp.
    #[derive(Debug, Clone)]
    pub struct Mempool(HashMap<Timestamp, Transaction>);

    impl Mempool {
        /// Function that creates an empty mempool.
        pub fn new() -> Self {
            Self(HashMap::new())
        }

        /// Function to get the current mempool.
        pub fn get(&self) -> &HashMap<Timestamp, Transaction> {
            &self.0
        }

        /// Function that sorts the mempool by timestamp mapping it to a queue of transactions,
        fn to_sorted_queue(self) -> Memqueue {
            let mut v = self
                .0
                .into_iter()
                .collect::<Vec<(Timestamp, Transaction)>>();
            v.sort_by(|a, b| a.0.cmp(&b.0));
            v.into_iter().map(|(_, t)| t).collect::<Memqueue>()
        }

        /// Function that gets the current length of the mempool.
        pub fn len(&self) -> usize {
            self.0.len()
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
        pub fn flush(&mut self) -> Memqueue {
            let memqueue = self.clone().to_sorted_queue();
            *self = Self::new();
            memqueue
        }

        pub fn contains(&self, transaction: &Transaction) -> bool {
            self.0.contains_key(&transaction.created_at)
        }
    }

    #[cfg(test)]
    pub mod test {
        use crate::blockchain::transaction::{Data, Mempool, Transaction};
        use ed25519_dalek_blake2b::Keypair;
        use hex::ToHex;
        use rand::rngs::OsRng;
        use std::error::Error;

        pub fn test_mempool() -> Result<(), Box<dyn Error + Send + Sync>> {
            let k1 = Keypair::generate(&mut OsRng);
            let k2 = Keypair::generate(&mut OsRng);

            let t1 = {
                let data = Data::CreateUserAccount("skylar".to_string());
                let from = k2.public.encode_hex();
                let nonce = 0;
                Transaction::new(data, from, nonce, &k1)?
            };

            let t2 = {
                let data = Data::CreateUserAccount("walter".to_string());
                let from = k1.public.encode_hex();
                let nonce = 0;
                Transaction::new(data, from, nonce, &k2)?
            };

            let mut pool = Mempool::new();
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

    const INITIAL_TOKEN_COUNT: u128 = 5;

    /// Struct that defines an account that can either be a user managed account or a smart contract operating independently.
    #[derive(Clone, Debug)]
    pub struct Account {
        pub kind: Kind,
        pub tokens: u128,
        pub nonce: u64,
        pub public_key: String,
    }

    /// Enum that represents the types of accounts that can be created in the blockchain.
    #[derive(Clone, Debug)]
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
            merkle::{self, Side},
            pow,
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
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Block {
        pub previous_hash: String,
        pub transactions: Vec<Transaction>,
        pub merkle_root: String,
        pub hash: String,
        pub nonce: u32,
        pub timestamp: Timestamp,
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
            let merkle_root = crate::blockchain::merkle::root(&p.transactions)?;

            Ok(Block {
                previous_hash,
                transactions: p.transactions,
                merkle_root,
                hash: h,
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

        /// Function that returns the proof that a given transaction belongs to the block.
        /// If the transaction doesn't belong to the block it returns Err.
        pub fn provide_transaction_proof(
            &self,
            transaction_idx: usize,
        ) -> Result<Vec<(String, Side)>, Box<dyn Error + Send + Sync>> {
            merkle::proof(transaction_idx, &self.transactions)
        }
    }

    impl Hashable for Block {
        fn hash(&self) -> Result<String, Box<dyn Error + Send + Sync>> {
            let input = serde_json::to_string(self)?;
            let h = crate::blockchain::hash::hash(HashFunction::new(), &input);
            Ok(hex::encode(h))
        }
    }
}

/// Struct that represents the blockchain that will be used as the ledger for the auction system.
#[derive(Debug, Clone)]
pub struct Blockchain {
    pub blocks: Vec<Block>,
    pub accounts: HashMap<String, Account>,
    pub transaction_mempool: Mempool,
    pub difficulty: u32,
}

impl Blockchain {
    /// Function that creates a new blockchain instance.
    pub fn new(difficulty: u32) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(Self {
            accounts: HashMap::new(),
            transaction_mempool: Mempool::new(),
            blocks: vec![],
            difficulty,
        })
    }

    pub fn accept_block(&mut self, _block: Block) -> Result<(), Box<dyn Error + Send + Sync>> {
        todo!()
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
}

/// Trait that defines the functions that can mutate the blockchain.
pub trait WorldState {
    const CREATE_ACCOUNT_MESSAGE: &str = "blocktion";

    fn account_balance(&self, public_key: &str) -> Option<u128>;

    fn transfer_funds(
        &mut self,
        from: &str,
        to: &str,
        amount: u128,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Will return a account given it's id if is available
    fn get_account_by_id(&self, public_key: &str) -> Option<&Account>;

    fn get_account_by_id_mut(&mut self, public_key: &str) -> Option<&mut Account>;

    /// Will add a new account
    fn create_account(
        &mut self,
        public_key: &str,
        signature: &Signature,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;
}

impl WorldState for Blockchain {
    fn create_account(
        &mut self,
        public_key: &str,
        signature: &Signature,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let pk = string_to_public_key(public_key)?;
        if let Err(_) = pk.verify_strict(Blockchain::CREATE_ACCOUNT_MESSAGE.as_bytes(), signature) {
            return Err("The signature is not verifiable by the public key.".into());
        }

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
        amount: u128,
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

    fn account_balance(&self, public_key: &str) -> Option<u128> {
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
        transaction::{Data, Transaction},
    };
    use ed25519_dalek_blake2b::Keypair;
    use hex::ToHex;
    use rand::rngs::OsRng;
    use std::error::Error;

    #[test]
    fn test_blockchain() -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut blockchain = Blockchain::new(u32::MAX)?;

        for n in 0..100 {
            let keys = Keypair::generate(&mut OsRng);

            let transactions = vec![Transaction::new(
                Data::CreateUserAccount(format!("user_{n}")),
                keys.public.encode_hex(),
                n,
                &keys,
            )?];

            blockchain.add_block(transactions)?;
        }

        assert!(blockchain.verify()?);

        Ok(())
    }
}
