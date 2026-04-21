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

    pub fn hash(mut h: HashFunction, data: &str) -> Vec<u8> {
        h.update(data.as_bytes());
        let bytes = h.finalize().to_vec();
        bytes
    }

    pub fn encode_hash(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    #[cfg(test)]
    pub mod test {
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
        blockchain::{HashFunction, hash},
        time::now_unix,
    };
    use blake2::Digest;
    use std::error::Error;
    use tracing::info;

    const LOG_MINERATION: u32 = 100000;
    const TARGET: &[u8] = &[
        0, 0, 0x0F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ];

    pub struct ProofOfWork {
        pub data: String,
        pub difficulty: u32,
    }

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

                let input = format!("{}:{}:{}:{}", previous_hash, pow.data, nonce, timestamp);
                let h = hash::hash(HashFunction::new(), &input);

                if h.as_slice() < TARGET {
                    return Ok((hex::encode(h), nonce, timestamp));
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct Block {
    pub previous_hash: String,
    pub data: String,
    pub hash: String,
    pub nonce: u32,
    pub timestamp: u64,
}

impl Block {
    pub fn new(
        previous_hash: Option<String>,
        data: String,
        difficulty: u32,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let previous_hash = match previous_hash {
            Some(ph) => ph,
            None => "0".to_string(),
        };
        let p = pow::ProofOfWork { data, difficulty };
        let (h, nonce, timestamp) = pow::mine(&p, &previous_hash)?;
        Ok(Block {
            previous_hash,
            data: p.data,
            hash: h,
            timestamp,
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
    pub fn new(difficulty: u32) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(Self {
            difficulty,
            blocks: vec![],
        })
    }

    pub fn add_block(&mut self, data: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let previous_block_hash = match self.blocks.last() {
            Some(pb) => Some(pb.hash.clone()),
            None => None,
        };
        self.blocks.push(Block::new(
            previous_block_hash,
            data.to_string(),
            self.difficulty,
        )?);
        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use std::error::Error;

    use crate::blockchain::Blockchain;

    #[test]
    fn test_blockchain() -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut blockchain = Blockchain::new(u32::MAX)?;

        for n in 0..2 {
            blockchain.add_block(&format!("{n}"))?;
        }
        println!("{:?}", blockchain);

        Ok(())
    }
}
