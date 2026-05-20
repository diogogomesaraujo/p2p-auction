use blocktion::{
    blockchain::transaction::{Data, Transaction},
    state::service::{TransactionResponse, node_rpc_service_client::NodeRpcServiceClient},
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

    let nonce = 0;

    let res = client
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

    let status = match res.into_inner() {
        TransactionResponse { status } if status == 0 => "success",
        _ => "failed",
    };

    println!("{}", status);

    Ok(())
}
