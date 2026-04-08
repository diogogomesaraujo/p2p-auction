use clap::Parser;
use libp2p::{Multiaddr, PeerId, StreamProtocol, identity::Keypair};
use p2p_auction::{
    key::{key_from_file, key_to_file},
    node::Node,
    rpc::Rpc,
};
use std::error::Error;
use tokio::io::{BufReader, stdin};

const IPFS_PROTO_NAME: StreamProtocol = StreamProtocol::new("/p2p-auction/1.0.0");

const BOOT_NODES: [(&str, &str); 1] = [(
    "/ip4/127.0.0.1/tcp/63358",
    "12D3KooWJYwhndvmbeZ4ovzgRB4ZXmc29VDHU1APoKRWub1AUcUE",
)];

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    key_path: Option<String>,

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

    let self_key = match args.key_path {
        Some(path) => key_from_file(&path)?,
        None => {
            let key = Keypair::generate_ed25519();
            key_to_file(&key)?;

            key
        }
    };

    let node = Node::new(boot_nodes_from_str(&BOOT_NODES)?);

    let mut i = node.init(IPFS_PROTO_NAME, self_key).await?;
    Node::run(&mut i, BufReader::new(stdin())).await?;

    Ok(())
}
