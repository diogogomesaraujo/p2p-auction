use clap::Parser;
use libp2p::StreamProtocol;
use p2p_auction::{boot::BootNode, key::get_key, rpc::Rpc};
use std::error::Error;
use tokio::io::{BufReader, stdin};

const IPFS_PROTO_NAME: StreamProtocol = StreamProtocol::new("/p2p-auction/1.0.0");

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    key_path: String,

    #[arg(long)]
    port: u32,

    #[arg(long)]
    state_path: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Args::parse();

    tracing_subscriber::fmt().try_init()?;

    let node = BootNode::new(&format!("/ip4/0.0.0.0/tcp/{}", args.port))?;

    let self_key = get_key(&args.key_path)?;

    let mut i = node.init(IPFS_PROTO_NAME, self_key).await?;
    BootNode::run(&mut i, BufReader::new(stdin())).await?;

    Ok(())
}
