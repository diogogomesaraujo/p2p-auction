use crate::blockchain::WorldState;
use crate::blockchain::block::Block;
use crate::blockchain::transaction::{Data, Transaction};
use crate::state::blockchain::node_rpc_service_server::{NodeRpcService, NodeRpcServiceServer};
use crate::state::blockchain::transaction_request::Record;
use crate::state::blockchain::{
    Bid, BlockInfoRequest, BlockInfoResponse, CreateAccount, CreateAuction, StopAuction,
    TransactionRequest, TransactionResponse,
};
use crate::{blockchain::Blockchain, reputation::INITIAL_PEER_SCORE, time::Timestamp};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::info;

#[derive(Debug, Clone)]
pub struct State {
    pub rpc_address: SocketAddr,
    pub peers: HashMap<PeerId, PeerInfo>,
    pub blockchain: Blockchain,
    pub received_blocks: HashMap<String, Block>,
    pub stage: Stage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub first_seen: Option<Timestamp>,
    pub last_seen: Option<Timestamp>,
    pub session_count: u32,
    pub blacklisted: bool,
    pub application_score: f64,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Stage {
    JustCreated,
    RequestedBlockchain,
    Initialized,
}

impl Default for PeerInfo {
    fn default() -> Self {
        Self {
            first_seen: None,
            last_seen: None,
            session_count: 0,
            blacklisted: false,
            application_score: INITIAL_PEER_SCORE,
        }
    }
}

impl State {
    pub fn init(rpc_address: &str, is_boot: bool) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(Self {
            peers: HashMap::new(),
            blockchain: Blockchain::new(u32::MAX)?, // ??? replace by an initial probe function
            received_blocks: HashMap::new(),
            rpc_address: SocketAddr::from_str(rpc_address)?,
            stage: match is_boot {
                true => Stage::Initialized,
                false => Stage::JustCreated,
            },
        })
    }
}

#[async_trait::async_trait]
pub trait Runnable {
    async fn run(self) -> Result<(), Box<dyn Error + Send + Sync>>;
}

#[async_trait::async_trait]
impl Runnable for Arc<RwLock<State>> {
    async fn run(self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let address = self.read().await.rpc_address;
        Server::builder()
            .add_service(NodeRpcServiceServer::new(self))
            .serve(address)
            .await?;
        Ok(())
    }
}

pub mod blockchain {
    tonic::include_proto!("node");
}

#[tonic::async_trait]
impl NodeRpcService for Arc<RwLock<State>> {
    async fn transaction(
        &self,
        request: Request<TransactionRequest>,
    ) -> Result<Response<TransactionResponse>, Status> {
        let t = request.into_inner();

        let record: Record = match t.record {
            Some(r) => r,
            None => return Ok(Response::new(TransactionResponse { status: 1 })),
        };

        let transaction = match record {
            Record::CreateAccountRequest(CreateAccount { public_key }) => {
                match Transaction::new(
                    Data::CreateUserAccount { public_key },
                    t.from,
                    0,
                    &t.signature,
                ) {
                    Ok(t) => t,
                    _ => return Ok(Response::new(TransactionResponse { status: 1 })),
                }
            }

            Record::CreateAuctionRequest(CreateAuction {
                auction_id,
                from,
                start_amount,
            }) => {
                match Transaction::new(
                    Data::CreateAuction {
                        auction_id,
                        from,
                        start_amount,
                    },
                    t.from,
                    0,
                    &t.signature,
                ) {
                    Ok(t) => t,
                    _ => return Ok(Response::new(TransactionResponse { status: 1 })),
                }
            }

            Record::StopAuctionRequest(StopAuction { auction_id }) => {
                match Transaction::new(Data::StopAuction { auction_id }, t.from, 0, &t.signature) {
                    Ok(t) => t,
                    _ => return Ok(Response::new(TransactionResponse { status: 1 })),
                }
            }

            Record::BidRequest(Bid {
                auction_id,
                from,
                amount,
            }) => {
                match Transaction::new(
                    Data::Bid {
                        auction_id,
                        from,
                        amount,
                    },
                    t.from,
                    0,
                    &t.signature,
                ) {
                    Ok(t) => t,
                    _ => return Ok(Response::new(TransactionResponse { status: 1 })),
                }
            }
        };

        info!(
            "Adding transaction {:?} to the blockchain's transaction pool.",
            transaction
        );

        match self
            .write()
            .await
            .blockchain
            .transaction_pool
            .add_transaction(transaction)
        {
            Ok(_) => {}
            _ => return Ok(Response::new(TransactionResponse { status: 1 })),
        };

        Ok(Response::new(TransactionResponse { status: 0 }))
    }

    async fn block_info(
        &self,
        request: Request<BlockInfoRequest>,
    ) -> Result<Response<BlockInfoResponse>, Status> {
        let request = request.into_inner();
        match self
            .read()
            .await
            .blockchain
            .get_block_from_hash(&request.hash)
        {
            Some(block) => Ok(Response::new(BlockInfoResponse {
                status: 0,
                block: Some(block.clone().into()),
                next_block_hash: self
                    .read()
                    .await
                    .blockchain
                    .get_next_block_hash(&request.hash),
            })),
            _ => Ok(Response::new(BlockInfoResponse {
                status: 1,
                block: None,
                next_block_hash: None,
            })),
        }
    }
}
