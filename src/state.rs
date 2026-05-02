use crate::blockchain::transaction::{Data, Transaction};
use crate::state::blockchain::node_rpc_service_server::NodeRpcService;
use crate::state::blockchain::transaction_request::Record;
use crate::state::blockchain::{
    BidRequest, CreateAccountRequest, CreateAuctionRequest, StopAuctionRequest, TransactionRequest,
    TransactionResponse,
};
use crate::{blockchain::Blockchain, reputation::INITIAL_PEER_SCORE, time::Timestamp};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};

#[derive(Debug)]
pub struct State {
    pub peers: HashMap<PeerId, PeerInfo>,
    pub blockchain: Arc<RwLock<Blockchain>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub first_seen: Option<Timestamp>,
    pub last_seen: Option<Timestamp>,
    pub session_count: u32,
    pub blacklisted: bool,
    pub application_score: f64,
    pub orphan_blocks_sent: u32,
}

impl Default for PeerInfo {
    fn default() -> Self {
        Self {
            first_seen: None,
            last_seen: None,
            session_count: 0,
            blacklisted: false,
            application_score: INITIAL_PEER_SCORE,
            orphan_blocks_sent: 0,
        }
    }
}

impl State {
    pub fn init() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(Self {
            peers: HashMap::new(),
            blockchain: Arc::new(RwLock::new(Blockchain::new(u32::MAX)?)), // ??? replace by an initial probe function
        })
    }
}

pub mod blockchain {
    tonic::include_proto!("node");
}

#[tonic::async_trait]
impl NodeRpcService for State {
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
            Record::CreateAccountRequest(CreateAccountRequest { public_key }) => {
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

            Record::CreateAuctionRequest(CreateAuctionRequest {
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

            Record::StopAuctionRequest(StopAuctionRequest { auction_id }) => {
                match Transaction::new(Data::StopAuction { auction_id }, t.from, 0, &t.signature) {
                    Ok(t) => t,
                    _ => return Ok(Response::new(TransactionResponse { status: 1 })),
                }
            }

            Record::BidRequest(BidRequest {
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

        match self
            .blockchain
            .clone()
            .write()
            .await
            .transaction_pool
            .add_transaction(transaction)
        {
            Ok(_) => {}
            _ => return Ok(Response::new(TransactionResponse { status: 1 })),
        };

        Ok(Response::new(TransactionResponse { status: 0 }))
    }
}
