use blocktion::{
    state::blockchain::{LongestChainRequest, node_rpc_service_client::NodeRpcServiceClient},
    time::Timestamp,
};
use clap::Parser;
use priority_queue::PriorityQueue;
use std::{collections::HashMap, error::Error};
use tonic::{Request, transport::Channel};

type Client = NodeRpcServiceClient<Channel>;
type Currency = u64;

const EXECUTE_AFTER_N_BLOCKS: u32 = 10;

struct ChainState {
    longest_chain: Vec<String>,
    last_executed: usize,
}

impl ChainState {
    async fn new(client: &mut Client) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(Self {
            longest_chain: request_longest_chain(client).await?,
            last_executed: 0,
        })
    }
}

struct BackendState {
    chain_state: ChainState,
    accounts: HashMap<String, Account>,
    auctions: HashMap<String, Auction>,
}

struct Account {
    id: String,
    funds: Currency,
}

struct Auction {
    id: String,
    bids: PriorityQueue<Bid, Currency>,
    stop_time: Timestamp,
}

struct Bid {
    from: String,
    amount: Currency,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    node_address: String,

    #[arg(long)]
    port: String,
}

async fn request_longest_chain(
    client: &mut Client,
) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    let longest_chain_response = client
        .longest_chain(Request::new(LongestChainRequest {}))
        .await?
        .into_inner();
    Ok(longest_chain_response.longest_chain)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Args::parse();

    let client = NodeRpcServiceClient::connect(args.node_address).await?;

    Ok(())
}
