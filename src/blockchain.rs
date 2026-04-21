use crate::time::now_unix;
use blake2::Blake2b512;
use std::error::Error;

type HashFunction = Blake2b512;

// https://towardsdev.com/the-proof-of-work-pow-mechanism-in-blockchain-6a49196cab75
// https://www.jmeiners.com/tiny-blockchain/
// https://en.bitcoin.it/wiki/Protocol_documentation#Block_Headers
// https://hackernoon.com/rusty-chains-a-basic-blockchain-implementation-written-in-pure-rust-gk2m3uri

pub mod hash {
    use crate::blockchain::HashFunction;
    use blake2::Digest;

    pub fn hash(mut h: HashFunction, data: &str) -> String {
        h.update(data.as_bytes());
        let bytes = h.finalize().to_vec();
        hex::encode(bytes)
    }

    #[cfg(test)]
    pub mod test {
        use crate::blockchain::hash::hash;
        use blake2::{Blake2b512, Digest};

        #[test]
        fn test_hash() {
            let to_hash = "I am not in danger, Skyler. I am the danger.";
            let hashed = hash(Blake2b512::new(), to_hash);

            assert_eq!(
                hashed,
                "3a141d45dea6b8af5bab5f942d88f3c0d48edcda84fac341d821d13d65896e2a7d5a8ec921da654301e72db33631fd94963e064056172f4d970a77625aa7ed93"
            );
        }
    }
}

pub mod pow {
    use crate::blockchain::{HashFunction, hash};
    use tracing::info;

    const LOG_MINERATION: u32 = 100000;

    pub struct ProofOfWork {
        pub data: String,
        pub difficulty: u32,
    }

    // todo: refactor
    pub fn mine(pow: &ProofOfWork, hasher: &HashFunction) -> (String, u32) {
        let prefix = [0..pow.difficulty]
            .iter()
            .fold(String::new(), |acc, _| [acc, String::from("0")].join(""));

        fn mine_rec(
            pow: &ProofOfWork,
            hasher: &HashFunction,
            nonce: u32,
            prefix: &str,
        ) -> (String, u32) {
            if nonce % LOG_MINERATION == 0 {
                info!("Still mining. The current nonce value is: {}.", nonce);
            }

            let input = format!("{}:{}", pow.data, nonce);
            let h = hash::hash(hasher.clone(), &input);

            if let Some(_) = h.strip_prefix(&prefix) {
                return (h, nonce);
            }

            mine_rec(pow, hasher, nonce + 1, prefix)
        }

        mine_rec(&pow, hasher, 0, &prefix)
    }
}

#[derive(Debug)]
pub struct Block {
    pub index: u32,
    pub previous_hash: String,
    pub data: String,
    pub hash: String,
    pub nonce: u32,
    pub timestamp: u64,
}

impl Block {
    pub fn new(
        index: u32,
        previous_hash: String,
        data: String,
        difficulty: u32,
        hasher: &HashFunction,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let p = pow::ProofOfWork { data, difficulty };
        let (h, nonce) = pow::mine(&p, hasher);
        Ok(Block {
            index,
            previous_hash,
            data: p.data,
            hash: h,
            timestamp: now_unix()?,
            nonce,
        })
    }
}

#[derive(Debug)]
pub struct Blockchain {
    pub blocks: Vec<Block>,
    pub difficulty: u32,
}

impl Blockchain {
    pub fn new(
        difficulty: u32,
        hasher: &HashFunction,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let genesis_block = Block::new(
            0,
            String::new(),
            String::from("Genesis Block"),
            difficulty,
            hasher,
        );
        Ok(Self {
            difficulty,
            blocks: vec![genesis_block?],
        })
    }

    pub fn add_block(
        &mut self,
        data: &str,
        hasher: &HashFunction,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let previous_block = match self.blocks.last() {
            Some(pb) => pb,
            None => return Err("Invalid state: The blockchain is empty.".into()),
        };
        self.blocks.push(Block::new(
            previous_block.index + 1,
            previous_block.hash.clone(),
            data.to_string(),
            self.difficulty,
            hasher,
        )?);
        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use std::error::Error;

    use crate::blockchain::Blockchain;
    use blake2::{Blake2b512, Digest};

    #[test]
    fn test_blockchain() -> Result<(), Box<dyn Error + Send + Sync>> {
        let h = Blake2b512::new();
        let mut blockchain = Blockchain::new(u32::MAX, &h)?;

        blockchain.add_block("First Block", &h)?;
        blockchain.add_block("Second Block", &h)?;
        blockchain.add_block("Third Block", &h)?;
        blockchain.add_block("Fourth Block", &h)?;

        println!("{:?}", blockchain);

        Ok(())
    }
}
