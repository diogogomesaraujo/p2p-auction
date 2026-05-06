use blocktion::state::blockchain::{
    CreateAccountRequest, TransactionRequest, node_rpc_service_client::NodeRpcServiceClient,
    transaction_request::Record,
};
use std::error::Error;
use tonic::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut client = NodeRpcServiceClient::connect(format!("http://localhost:{}", 3003)).await?;

    client
        .transaction(Request::new(TransactionRequest {
            signature: "sig".to_string(),
            from: "walter".to_string(),
            record: Some(Record::CreateAccountRequest(CreateAccountRequest {
                public_key: "walter".to_string(),
            })),
        }))
        .await?;

    println!("success");

    Ok(())
}
