use blocktion::{
    blockchain::{
        ed25519::public_key_to_string,
        transaction::{Data, Transaction},
    },
    boot::BootNode,
    key::get_key,
    runtime::Runtime,
    vm::VirtualMachine,
};
use clap::Parser;
use ed25519_dalek_blake2b::Keypair;
use libp2p::StreamProtocol;
use rand::rngs::OsRng;
use std::error::Error;
use tokio::io::{BufReader, stdin};

const IPFS_PROTO_NAME: StreamProtocol = StreamProtocol::new("/p2p-auction/1.0.0");

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    key_path: String,

    #[arg(long)]
    kad_port: u32,

    #[arg(long)]
    rpc_port: u32,

    #[arg(long)]
    state_path: Option<String>,

    #[arg(long, default_value_t = 10)]
    seed_blocks: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Args::parse();

    tracing_subscriber::fmt().try_init()?;

    let node = BootNode::new(&format!("/ip4/0.0.0.0/tcp/{}", args.kad_port))?;
    let self_key = get_key(&args.key_path)?;

    let mut i = node
        .init(
            IPFS_PROTO_NAME,
            self_key,
            &format!("0.0.0.0:{}", args.rpc_port),
        )
        .await?;

    // _seed_valid_test_chain(&mut i, args.seed_blocks).await?;

    let keys = Keypair::generate(&mut OsRng);

    BootNode::run(&mut i, keys, BufReader::new(stdin())).await?;

    Ok(())
}

async fn _seed_valid_test_chain(
    runtime: &mut Runtime,
    count: u32,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut state = runtime.state.write().await;

    for n in 0..count {
        let keys = Keypair::generate(&mut OsRng);
        let pk = public_key_to_string(&keys.public);

        let tx = Transaction::sign(
            Data::CreateUserAccount {
                public_key: pk.clone(),
            },
            &pk,
            n,
            &keys,
        )?;

        state.blockchain.transaction_pool.add_transaction(tx)?;
        // state.blockchain.propose_block(&pk)?;

        println!("Seeded block {}/{}", n + 1, count);
    }

    Ok(())
}
