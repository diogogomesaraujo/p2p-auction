use std::{error::Error, time::Duration};

use crate::{
    blockchain::transaction::{Data, Transaction},
    state::blockchain::node_rpc_service_client::NodeRpcServiceClient,
    time::Poisson,
};
use async_trait::async_trait;
use ed25519_dalek_blake2b::Keypair;
use hex::ToHex;
use rand::{RngCore, thread_rng};
use tokio::time::sleep;
use tonic::{Request, transport::Channel};

pub mod honest;

#[async_trait]
pub trait Bot {
    fn name(&self) -> &'static str;

    async fn init(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        Ok(())
    }

    async fn step(&mut self) -> Result<(), Box<dyn Error + Send + Sync>>;
}

pub struct Context {
    pub client: NodeRpcServiceClient<Channel>,
    pub keys: Keypair,
    pub public_key: String,
    pub nonce: u32,
}

impl Context {
    pub async fn connect(port: u16, keys: Keypair) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let client = NodeRpcServiceClient::connect(format!("http://127.0.0.1:{port}")).await?;

        let public_key = keys.public.encode_hex::<String>();

        Ok(Self {
            client,
            keys,
            public_key,
            nonce: 0,
        })
    }

    pub async fn send(&mut self, data: Data) -> Result<(), Box<dyn Error + Send + Sync>> {
        let tx = Transaction::sign(data, &self.public_key, self.nonce, &self.keys)?;

        self.client.transaction(Request::new(tx.into())).await?;

        self.nonce += 1;

        Ok(())
    }

    pub async fn create_account(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.send(Data::CreateUserAccount {
            public_key: self.public_key.clone(),
        })
        .await
    }
}

pub async fn run_bot<B: Bot + Send>(
    bot: &mut B,
    iterations: u32,
    rate: f32,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut seed = [0u8; 32];
    thread_rng().fill_bytes(&mut seed);

    let mut poisson = Poisson::new(rate, &seed);

    bot.init().await?;

    println!("started bot: {}", bot.name());

    for i in 0..iterations {
        sleep(Duration::from_secs_f32(poisson.time_for_next_event())).await;

        match bot.step().await {
            Ok(_) => {
                println!("{} generated {}/{} requests", bot.name(), i + 1, iterations);
            }
            Err(e) => {
                eprintln!("{} failed on step {}: {}", bot.name(), i + 1, e);
            }
        }
    }

    Ok(())
}
