use blake2::{Blake2b512, Digest};
use libp2p::{PeerId, identity::Keypair};
use std::{
    error::Error,
    fs::File,
    io::{Read, Write},
};
use tracing::info;

/// Number of leading zero bits required in the Blake2b hash of a peer's PeerId bytes.
/// Higher means it is more expensive to generate identities.
/// 2^PEER_ID_DIFFICULTY hash attempts on average.
pub const PEER_ID_DIFFICULTY: u32 = 16;

/// Function that verifies a PeerId satisfies the PoW difficulty.
pub fn verify_peer_id(peer_id: &PeerId) -> bool {
    let bytes = peer_id.to_bytes();
    let mut h = Blake2b512::new();
    h.update(&bytes);
    let digest = h.finalize();
    leading_zero_bits(&digest) >= PEER_ID_DIFFICULTY
}

/// Function that counts the leading zero bits of a byte slice.
fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0u32;
    for b in bytes {
        if *b == 0 {
            count += 8;
        } else {
            count += b.leading_zeros();
            break;
        }
    }
    count
}

/// Function that tries to get a key from the given path, otherwise it mines a new key
/// whose PeerId satisfies PEER_ID_DIFFICULTY, stores it, and returns it.
pub fn get_key(path: &str) -> Result<Keypair, Box<dyn Error + Send + Sync>> {
    match key_from_file(path) {
        Ok(key) => {
            let peer_id = PeerId::from_public_key(&key.public());
            if !verify_peer_id(&peer_id) {
                return Err(format!(
                    "Stored key at {path} does not meet PoW difficulty {PEER_ID_DIFFICULTY}."
                )
                .into());
            }
            Ok(key)
        }
        Err(_) => {
            let key = mine_key()?;
            key_to_file(&key, path)?;
            Ok(key)
        }
    }
}

/// Function that mines an Ed25519 keypair whose PeerId hash has PEER_ID_DIFFICULTY leading zero bits.
pub fn mine_key() -> Result<Keypair, Box<dyn Error + Send + Sync>> {
    info!(
        "Mining a peer ID with at least {} leading zero bits...",
        PEER_ID_DIFFICULTY
    );
    let mut attempts: u64 = 0;
    loop {
        let key = Keypair::generate_ed25519();
        let peer_id = PeerId::from_public_key(&key.public());
        attempts += 1;
        if verify_peer_id(&peer_id) {
            info!(
                "Mined valid peer ID after {} attempts: {}",
                attempts, peer_id
            );
            return Ok(key);
        }
        if attempts % 50_000 == 0 {
            info!("Still mining peer ID... ({} attempts)", attempts);
        }
    }
}

/// Function that tries to get a key from a file.
pub fn key_from_file(path: &str) -> Result<Keypair, Box<dyn Error + Send + Sync>> {
    let mut file = File::open(path)?;

    let mut buf = String::new();
    file.read_to_string(&mut buf)?;

    let key = hex::decode(buf)?;

    Ok(Keypair::from_protobuf_encoding(&key)?)
}

pub fn key_to_file(key: &Keypair, path: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut file = File::create(path)?;

    let key_hex = hex::encode(key.to_protobuf_encoding()?);
    file.write_all(key_hex.as_bytes())?;

    Ok(())
}

#[cfg(test)]
pub mod test {
    use crate::key::{key_from_file, key_to_file, mine_key, verify_peer_id};
    use libp2p::{PeerId, identity::Keypair};
    use std::error::Error;

    #[test]
    fn test_key_conversion() -> Result<(), Box<dyn Error + Send + Sync>> {
        let key = Keypair::generate_ed25519();
        let test_filepath = "test";

        key_to_file(&key, test_filepath)?;

        assert_eq!(
            key.to_protobuf_encoding()?,
            key_from_file(test_filepath)?.to_protobuf_encoding()?
        );
        Ok(())
    }

    #[test]
    fn test_mined_key_satisfies_difficulty() -> Result<(), Box<dyn Error + Send + Sync>> {
        let key = mine_key()?;
        let peer_id = PeerId::from_public_key(&key.public());
        assert!(verify_peer_id(&peer_id));
        Ok(())
    }
}
