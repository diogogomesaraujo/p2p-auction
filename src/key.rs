use libp2p::identity::Keypair;
use std::{
    error::Error,
    fs::File,
    io::{Read, Write},
};

pub fn get_key(path: &str) -> Result<Keypair, Box<dyn Error + Send + Sync>> {
    match key_from_file(path) {
        Ok(key) => Ok(key),
        Err(_) => {
            let key = Keypair::generate_ed25519();

            key_to_file(&key, path)?;
            Ok(key)
        }
    }
}

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
    use std::error::Error;

    use libp2p::identity::Keypair;

    use crate::key::{key_from_file, key_to_file};

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
}
