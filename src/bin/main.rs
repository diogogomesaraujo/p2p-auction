use clap::Parser;
use libp2p::{Multiaddr, PeerId, StreamProtocol};
use p2p_auction::{key::get_key, node::Node, rpc::Rpc};
use std::error::Error;
use tokio::io::{BufReader, stdin};

const IPFS_PROTO_NAME: StreamProtocol = StreamProtocol::new("/p2p-auction/1.0.0");

const BOOT_NODES: [(&str, &str); 1] = [(
    "/ip4/172.20.0.2/tcp/63358",
    "12D3KooWPJTsznbE7Axq6yXzTcFirB5DVU221mfR1q3eAeRziCWt",
)];

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    key_path: String,

    #[arg(long)]
    state_path: Option<String>,
}

fn boot_nodes_from_str(
    boot_nodes: &[(&str, &str)],
) -> Result<Vec<(Multiaddr, PeerId)>, Box<dyn Error + Send + Sync>> {
    boot_nodes.iter().try_fold(vec![], |mut acc, (addr, id)| {
        acc.push((addr.parse::<Multiaddr>()?, id.parse::<PeerId>()?));
        Ok(acc)
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Args::parse();

    tracing_subscriber::fmt().try_init()?;

    let self_key = get_key(&args.key_path)?;

    let node = Node::new(boot_nodes_from_str(&BOOT_NODES)?);

    let mut i = node.init(IPFS_PROTO_NAME, self_key).await?;
    Node::run(&mut i, BufReader::new(stdin())).await?;

    Ok(())
}
