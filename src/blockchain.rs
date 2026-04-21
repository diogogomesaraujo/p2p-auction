use crate::{
    blockchain::{account::Account, transaction::Transaction},
    time::now_unix,
};
use blake2::Blake2b512;
use std::{collections::HashMap, error::Error};

type HashFunction = Blake2b512;

// https://towardsdev.com/the-proof-of-work-pow-mechanism-in-blockchain-6a49196cab75
// https://www.jmeiners.com/tiny-blockchain/
// https://en.bitcoin.it/wiki/Protocol_documentation#Block_Headers

// datastructures inspired by:
// https://hackernoon.com/rusty-chains-a-basic-blockchain-implementation-written-in-pure-rust-gk2m3uri

pub mod hash {
    use crate::blockchain::HashFunction;
    use blake2::Digest;

    pub fn hash(mut h: HashFunction, data: &str) -> String {
        h.update(data.as_bytes());
        let bytes = h.finalize().to_vec();
        hex::encode(bytes)
    }
}

pub mod pow {
    use crate::blockchain::{HashFunction, hash, transaction::Transaction};
    use tracing::info;

    const LOG_MINERATION: u32 = 100000;

    pub struct ProofOfWork {
        pub transactions: Vec<Transaction>,
        pub difficulty: u32,
    }

    pub fn mine(pow: &ProofOfWork, hasher: HashFunction) -> (String, u32) {
        let prefix = [0..pow.difficulty]
            .iter()
            .fold(String::new(), |acc, _| [acc, String::from("0")].join(""));

        fn mine_rec(
            pow: &ProofOfWork,
            hasher: HashFunction,
            nonce: u32,
            prefix: &str,
        ) -> (String, u32) {
            if nonce % LOG_MINERATION == 0 {
                info!("Still mining. The current nonce value is: {}.", nonce);
            }
            let input = format!(
                "{:?}:{}",
                pow.transactions, /* don't know if it's actually like this */ nonce
            );
            let h = hash::hash(hasher.clone(), &input);

            if let Some(_) = h.strip_prefix(&prefix) {
                return (h, nonce);
            }

            mine_rec(pow, hasher, nonce + 1, prefix)
        }

        mine_rec(&pow, hasher, 0, &prefix)
    }
}

pub mod transaction {
    use std::time::SystemTime;

    #[derive(Clone, Debug)]
    pub struct Transaction {
        pub record: Data,
        from: String,
        created_at: SystemTime,
        nonce: u128,
        signature: Option<String>,
    }

    #[derive(Debug, Clone)]
    pub enum Data {
        CreateUserAccount(String),
        ChangeStoreValue { key: String, value: String },
        TransferTokens { to: String, amount: u128 },
        CreateTokens { receiver: String, amount: u128 },
        // add more and adapt for auction
    }
}

pub mod account {
    use std::{collections::HashMap, error::Error};

    #[derive(Clone, Debug)]
    pub struct Account {
        store: HashMap<String, String>,
        kind: Kind,
        /// Amount of tokens that account owns (like BTC or ETH) -> might not need
        tokens: u128,
    }

    #[derive(Clone, Debug)]
    pub enum Kind {
        User,

        // like smart contract in etherium -> might not need
        Contract,

        /// whatever roles we will need
        Validator {
            correctly_validated_blocks: u128,
            incorrectly_validated_blocks: u128,
            you_get_the_idea: bool,
        },
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

trait WorldState {
    /// Will bring us all registered user ids
    fn get_user_ids(&self) -> Vec<String>;

    /// Will return a account given it's id if is available (mutable)
    fn get_account_by_id_mut(&mut self, id: &String) -> Option<&mut Account>;

    /// Will return a account given it's id if is available
    fn get_account_by_id(&self, id: &String) -> Option<&Account>;

    /// Will add a new account
    fn create_account(&mut self, id: String, kind: account::Kind) -> Result<(), &str>;
}

pub struct Block {
    pub index: u32,
    pub previous_hash: String,
    pub transactions: Vec<Transaction>,
    pub hash: String,
    pub nonce: u32,
    pub timestamp: u64,
}

impl Block {
    pub fn new(
        index: u32,
        previous_hash: String,
        transactions: Vec<Transaction>,
        difficulty: u32,
        hasher: HashFunction,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let p = pow::ProofOfWork {
            transactions,
            difficulty,
        };
        let (h, nonce) = pow::mine(&p, hasher);
        Ok(Block {
            index,
            previous_hash,
            transactions: p.transactions,
            hash: h,
            timestamp: now_unix()?,
            nonce,
        })
    }
}

pub struct Blockchain {
    pub blocks: Vec<Block>,
    pub difficulty: u32,
    pub accounts: HashMap<String, Account>,
    pending_transactions: Vec<Transaction>,
}

impl Blockchain {
    pub fn new(
        difficulty: u32,
        hasher: HashFunction,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let genesis_block = Block::new(0, String::new(), Vec::new(), difficulty, hasher);
        Ok(Self {
            difficulty,
            blocks: vec![genesis_block?],
            accounts: HashMap::new(),
            pending_transactions: Vec::new(),
        })
    }

    pub fn add_block(
        &mut self,
        data: Vec<Transaction>,
        hasher: HashFunction,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let previous_block = match self.blocks.last() {
            Some(pb) => pb,
            None => return Err("Invalid state: The blockchain is empty.".into()),
        };
        self.blocks.push(Block::new(
            previous_block.index + 1,
            previous_block.hash.clone(),
            data,
            self.difficulty,
            hasher,
        )?);
        Ok(())
    }
}
