use crate::blockchain::block::Block;
use crate::blockchain::transaction::{Data, Transaction};
use crate::blockchain::{Blockchain, WorldState};
use crate::state::service::{
    AccountExistsRequest, AuctionExistsRequest, AuctionExistsResponse, StopAuction,
};
use service::node_rpc_service_server::{NodeRpcService, NodeRpcServiceServer};
use service::transaction_request::Record;
use service::{
    Account, AccountExistsResponse, Bid, BlockInfoRequest, BlockInfoResponse, CreateAuction,
    TransactionRequest, TransactionResponse,
};
use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::sync::Notify;
use tokio::sync::RwLock;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::info;

#[derive(Debug, Clone)]
pub struct State {
    pub rpc_address: SocketAddr,
    pub blockchain: Blockchain,
    pub received_blocks: HashMap<String, Block>,
    pub notifiers: HashMap<String, Arc<(Notify, AtomicBool)>>,
}

impl State {
    pub fn init(rpc_address: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(Self {
            rpc_address: SocketAddr::from_str(rpc_address)?,
            blockchain: Blockchain::new(u32::MAX)?,
            received_blocks: HashMap::new(),
            notifiers: HashMap::new(),
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

pub mod service {
    tonic::include_proto!("node");
}

#[tonic::async_trait]
impl NodeRpcService for Arc<RwLock<State>> {
    async fn auction_exists(
        &self,
        request: Request<AuctionExistsRequest>,
    ) -> Result<Response<AuctionExistsResponse>, Status> {
        let req = request.into_inner();
        let blocks = self.read().await.blockchain.blocks.clone();
        let b = blocks.into_iter().find(|b| {
            b.1.transactions.iter().any(|t| {
                if let Data::CreateAuction { auction_id, .. } = &t.record
                    && auction_id == &req.auction_id
                {
                    true
                } else {
                    false
                }
            })
        });
        match b {
            Some(b) => Ok(Response::new(AuctionExistsResponse {
                status: 0,
                block_hash: Some(b.1.hash.to_string()),
            })),
            _ => Ok(Response::new(AuctionExistsResponse {
                status: 0,
                block_hash: None,
            })),
        }
    }

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
            Record::CreateAccountRequest(Account { public_key }) => {
                match Transaction::new(
                    Data::CreateUserAccount { public_key },
                    t.from,
                    t.nonce,
                    &t.signature,
                ) {
                    Ok(t) => t,
                    _ => return Ok(Response::new(TransactionResponse { status: 1 })),
                }
            }

            Record::CreateAuctionRequest(CreateAuction {
                auction_id,
                start_amount,
                stop_time,
            }) => {
                match Transaction::new(
                    Data::CreateAuction {
                        auction_id,
                        start_amount,
                        stop_time,
                    },
                    t.from,
                    t.nonce,
                    &t.signature,
                ) {
                    Ok(t) => t,
                    _ => return Ok(Response::new(TransactionResponse { status: 1 })),
                }
            }

            Record::BidRequest(Bid { auction_id, amount }) => {
                match Transaction::new(
                    Data::Bid { auction_id, amount },
                    t.from,
                    t.nonce,
                    &t.signature,
                ) {
                    Ok(t) => t,
                    _ => return Ok(Response::new(TransactionResponse { status: 1 })),
                }
            }

            Record::StopAuctionRequest(StopAuction { auction_id }) => {
                match Transaction::new(
                    Data::StopAuction { auction_id },
                    t.from,
                    t.nonce,
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

        let tid = transaction.id.clone();

        let notify = Arc::new((Notify::new(), AtomicBool::new(false)));
        self.write()
            .await
            .notifiers
            .insert(tid.clone(), notify.clone());

        match self.write().await.blockchain.add_transaction(transaction) {
            Ok(_) => {}
            _ => return Ok(Response::new(TransactionResponse { status: 1 })),
        };

        notify.0.notified().await;

        self.write().await.notifiers.remove(&tid);

        let status = match notify.1.load(std::sync::atomic::Ordering::SeqCst) {
            true => 0,
            false => 1,
        };

        Ok(Response::new(TransactionResponse { status }))
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
            })),
            None => Ok(Response::new(BlockInfoResponse {
                status: 1,
                block: None,
            })),
        }
    }

    async fn account_exists(
        &self,
        request: Request<AccountExistsRequest>,
    ) -> Result<Response<AccountExistsResponse>, Status> {
        let public_key = match &request.into_inner().account {
            Some(account) => account.public_key.clone(),
            None => {
                return Ok(Response::new(AccountExistsResponse {
                    status: 1,
                    nonce: None,
                }));
            }
        };
        let nonce = match self.read().await.blockchain.get_account(&public_key) {
            Some(account) => Some(account.nonce),
            None => None,
        };
        Ok(Response::new(AccountExistsResponse { status: 0, nonce }))
    }
}
