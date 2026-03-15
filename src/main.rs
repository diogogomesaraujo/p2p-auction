use libp2p::{StreamProtocol, identity};
use p2p_auction::{kad_instance_init, kad_run};
use std::error::Error;
use tokio::io::{BufReader, stdin};

const IPFS_PROTO_NAME: StreamProtocol = StreamProtocol::new("/my-dht/1.0.0");

const BOOT_NODES: [&str; 4] = [
    "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let _ = tracing_subscriber::fmt().try_init()?;

    let self_key = identity::Keypair::generate_ed25519();

    let mut i = kad_instance_init(IPFS_PROTO_NAME, self_key, &BOOT_NODES).await?;
    kad_run(&mut i, BufReader::new(stdin())).await?;

    Ok(())
}
