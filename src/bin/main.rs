use blocktion::{key::get_key, node::Node, rpc::DhtRpc};
use clap::Parser;
use libp2p::{Multiaddr, PeerId, StreamProtocol};
use std::error::Error;
use tokio::io::{BufReader, stdin};

const IPFS_PROTO_NAME: StreamProtocol = StreamProtocol::new("/p2p-auction/1.0.0");

const _BOOT_NODES: [(&str, &str); 1] = [(
    "/ip4/10.0.0.2/tcp/63358",
    "12D3KooWPJTsznbE7Axq6yXzTcFirB5DVU221mfR1q3eAeRziCWt",
)];

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    key_path: String,

    #[arg(long)]
    state_path: Option<String>,

    #[arg(long)]
    boot_path: String,

    #[arg(long)]
    boot_key: String,

    #[arg(long)]
    rpc_port: u32,
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

    let node = Node::new(
        boot_nodes_from_str(&[(&args.boot_path, &args.boot_key)])?,
        &format!("127.0.0.1:{}", args.rpc_port),
    );

    let mut i = node.init(IPFS_PROTO_NAME, self_key).await?;
    Node::run(&mut i, BufReader::new(stdin())).await?;

    Ok(())
}
