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
    nonce: &mut u32,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let id = OsRng.next_u32().to_string();
    client
        .transaction(Request::new(
            Transaction::sign(
                Data::CreateAuction {
                    auction_id: id.clone(),
                    start_amount: OsRng.next_u64(),
                    stop_time: now_unix_plus(Duration::from_secs(OsRng.next_u64()))?,
                },
                &keys.public.encode_hex::<String>(),
                nonce.clone(),
                &keys,
            )?
            .into(),
        ))
        .await?;

    *nonce += 1;

    client
        .transaction(Request::new(
            Transaction::sign(
                Data::Bid {
                    auction_id: id.clone(),
                    amount: 10000,
                },
                &keys.public.encode_hex::<String>(),
                nonce.clone(),
                &keys,
            )?
            .into(),
        ))
        .await?;

    *nonce += 1;

    println!("{:?}", nonce);

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

    let mut nonce = 0;

    client
        .transaction(Request::new(
            Transaction::sign(
                Data::CreateUserAccount {
                    public_key: keys.public.encode_hex(),
                },
                &keys.public.encode_hex::<String>(),
                nonce,
                &keys,
            )?
            .into(),
        ))
        .await?;

    nonce += 1;

    println!("created account");

    for i in 0..(args.iterations as i32) {
        sleep(Duration::from_secs_f32(
            poisson_distribution.time_for_next_event(),
        ))
        .await;

        gen_request(&keys, &mut client, &mut nonce).await?;

        println!("generated {:?}/{:?} requests", i + 1, args.iterations);
    }

    Ok(())
}
