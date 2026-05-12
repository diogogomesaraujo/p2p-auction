use blocktion::{
    blockchain::transaction::{Data, Transaction},
    state::blockchain::node_rpc_service_client::NodeRpcServiceClient,
};
use ed25519_dalek_blake2b::Keypair;
use hex::ToHex;
use rand::rngs::OsRng;
use std::error::Error;
use tonic::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut client = NodeRpcServiceClient::connect(format!("http://127.0.0.1:{}", 3001)).await?;

    let keys = Keypair::generate(&mut OsRng);

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

    println!("success");

    Ok(())
}
