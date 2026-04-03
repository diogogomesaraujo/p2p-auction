use clap::Parser;
use libp2p::{Multiaddr, PeerId, StreamProtocol, identity};
use p2p_auction::{node::Node, rpc::Rpc};
use std::{error::Error, thread::sleep, time::Duration};
use tokio::io::{BufReader, stdin};
use tracing::info;

const IPFS_PROTO_NAME: StreamProtocol = StreamProtocol::new("/p2p-auction/1.0.0");

const BOOT_NODES: [(&str, &str); 1] = [(
    "/ip4/127.0.0.1/tcp/63358",
    "12D3KooWJYwhndvmbeZ4ovzgRB4ZXmc29VDHU1APoKRWub1AUcUE",
)];

fn boot_nodes_from_str(
    boot_nodes: &[(&str, &str)],
) -> Result<Vec<(Multiaddr, PeerId)>, Box<dyn Error + Send + Sync>> {
    boot_nodes
        .into_iter()
        .try_fold(vec![], |mut acc, (addr, id)| {
            acc.push((addr.parse::<Multiaddr>()?, id.parse::<PeerId>()?));
            Ok(acc)
        })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let _ = tracing_subscriber::fmt().try_init()?;

    info!("Running DHT node.");

    let self_key = identity::Keypair::generate_ed25519();

    sleep(Duration::from_secs(1));

    let node = Node::new(boot_nodes_from_str(&BOOT_NODES)?);

    let mut i = node.init(IPFS_PROTO_NAME, self_key).await?;
    Node::run(&mut i, BufReader::new(stdin())).await?;

    Ok(())
}
