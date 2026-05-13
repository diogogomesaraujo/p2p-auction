use std::{error::Error, time::Duration};

use blocktion::{
    blockchain::transaction::{Data, Transaction},
    state::blockchain::node_rpc_service_client::NodeRpcServiceClient,
    time::{Poisson, now_unix_plus},
};
use clap::Parser;
use ed25519_dalek_blake2b::Keypair;
use hex::ToHex;
use rand::{RngCore, rngs::OsRng, thread_rng};
use tokio::time::sleep;
use tonic::{Request, transport::Channel};

const RATE: f32 = 2.;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    iterations: u32,
}

async fn gen_request(
    keys: &Keypair,
    client: &mut NodeRpcServiceClient<Channel>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    client
        .transaction(Request::new(
            Transaction::sign(
                Data::CreateAuction {
                    auction_id: OsRng.next_u32().to_string(),
                    from: OsRng.next_u32().to_string(),
                    start_amount: OsRng.next_u64(),
                    stop_time: now_unix_plus(Duration::from_secs(OsRng.next_u64()))?,
                },
                &keys.public.encode_hex::<String>(),
                0,
                &keys,
            )?
            .into(),
        ))
        .await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Args::parse();

    let mut client = NodeRpcServiceClient::connect(format!("http://127.0.0.1:{}", 3001)).await?;

    let keys = Keypair::generate(&mut OsRng);

    let mut poisson_distribution = {
        let mut seed: [u8; 32] = [0u8; 32];
        thread_rng().fill_bytes(&mut seed);
        Poisson::new(RATE, &seed)
    };

    client
        .transaction(Request::new(
            Transaction::sign(
                Data::CreateUserAccount {
                    public_key: keys.public.encode_hex(),
                },
                &keys.public.encode_hex::<String>(),
                0,
                &keys,
            )?
            .into(),
        ))
        .await?;

    println!("created account");

    for i in 0..(args.iterations as i32) {
        sleep(Duration::from_secs_f32(
            poisson_distribution.time_for_next_event(),
        ))
        .await;

        gen_request(&keys, &mut client).await?;

        println!("generated {:?}/{:?} requests", i + 1, args.iterations);
    }

    Ok(())
}
