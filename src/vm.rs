use crate::{
    behaviour::DhtBehaviourEvent,
    blockchain::{
        block::Block,
        transaction::{Data, Transaction},
    },
    config::REQUEST_LONGEST_CHAIN_AFTER,
    runtime::Runtime,
    state::{Runnable, State},
    topic::BLOCKS,
};
use async_trait::async_trait;
use ed25519_dalek_blake2b::Keypair;
use hex::ToHex;
use libp2p::{StreamProtocol, futures::StreamExt};
use libp2p_gossipsub::IdentTopic;
use serde_json::to_vec;
use std::{error::Error, str::SplitWhitespace, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, BufReader, Stdin},
    sync::{RwLock, mpsc},
    time::sleep,
};
use tracing::error;

pub const BOOT_NODE_MULTIADDR: &str = "/dnsaddr/bootstrap.libp2p.io";
pub const LISTEN_ON: &str = "/ip4/0.0.0.0/tcp/0";

const NEW_BLOCK_SPEED: Duration = Duration::from_secs(3);

/// Trait that represents the RPC structure used for nodes (both boot nodes and regular ones).
#[async_trait]
pub trait VirtualMachine {
    /// Enum type that contains the different RPC calls an external node can make to the current one.
    type VirtualMachineAction;

    /// Function that executes an action according to the RPC call.
    fn match_action(
        args: &mut SplitWhitespace,
        runtime: &mut Runtime,
        rpc: Self::VirtualMachineAction,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Function that
    fn action_from_str(action_text: &str) -> Option<Self::VirtualMachineAction>;

    fn arg_parse(args: &mut SplitWhitespace) -> Result<String, Box<dyn Error + Send + Sync>> {
        match args.next() {
            Some(arg) => Ok(arg.to_string()),
            None => Err("Insufficient arguments".into()),
        }
    }

    fn remaining_args(args: &mut SplitWhitespace) -> Result<String, Box<dyn Error + Send + Sync>> {
        let rest = args.collect::<Vec<_>>().join(" ");
        if rest.is_empty() {
            Err("Insufficient arguments".into())
        } else {
            Ok(rest)
        }
    }

    fn execute_action(
        args: &mut SplitWhitespace,
        runtime: &mut Runtime,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let rpc = match Self::action_from_str(&Self::arg_parse(args)?) {
            Some(rpc) => rpc,
            None => return Err("Couldn't parse any argument".into()),
        };

        Self::match_action(args, runtime, rpc)?;
        Ok(())
    }

    async fn init(
        self,
        ipfs_proto_name: StreamProtocol,
        key: libp2p::identity::Keypair,
        rpc_address: &str,
    ) -> Result<Runtime, Box<dyn Error + Send + Sync>>;

    async fn run(
        runtime: &mut Runtime,
        keys: Keypair,
        buffer_reader: BufReader<Stdin>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // show blockchain
        {
            let state = runtime.state.clone();
            tokio::spawn(async move {
                loop {
                    sleep(Duration::from_secs(10)).await;
                    tracing::info!(
                        "Blockchain state is currently: {:?}",
                        state.read().await.blockchain.longest_chain
                    );
                }
            });
        }

        // rpc thread

        {
            let state = runtime.state.clone();
            tokio::spawn(async move {
                state.run().await?;
                Ok::<(), Box<dyn Error + Send + Sync>>(())
            });
        }

        // mine block thread

        let (tx, mut rx) = mpsc::unbounded_channel::<Block>();
        let (sync_tx, mut sync_rx) = mpsc::unbounded_channel::<()>();

        let tx = Arc::new(RwLock::new(tx));
        {
            let tx = tx.clone();
            let state = runtime.state.clone();
            let public_key: String = keys.public.encode_hex();
            tokio::spawn(async move {
                loop {
                    let block = {
                        let mut state = state.write().await;

                        let State {
                            blockchain,
                            notifiers,
                            ..
                        } = &mut *state;

                        match blockchain.propose_block(&public_key, notifiers) {
                            Ok(block) => block,
                            Err(_) => {
                                continue;
                            }
                        }
                    };

                    if tx.write().await.send(block).is_err() {
                        error!("Couldn't send the block.");
                    }

                    sleep(NEW_BLOCK_SPEED).await;
                }
            });
        }

        // After an arbitrary amount of time of not receiving blocks through gossip
        // ask a peer for longest hash chain. This protects against hostile gossip environments
        // and avoids stalling and thinking the blockchain is idle.
        {
            let state = runtime.state.clone();
            tokio::spawn(async move {
                loop {
                    sleep(REQUEST_LONGEST_CHAIN_AFTER).await;
                    let stale = {
                        let s = state.read().await;
                        match s.last_block_accepted {
                            Some(t) => t.elapsed() >= REQUEST_LONGEST_CHAIN_AFTER,
                            None => true,
                        }
                    };
                    if stale {
                        tracing::warn!("No block accepted recently — requesting longest chain.");
                        let _ = sync_tx.send(());
                    }
                }
            });
        }

        // add miner account

        runtime
            .state
            .write()
            .await
            .blockchain
            .transaction_pool
            .add_transaction(Transaction::sign(
                Data::CreateUserAccount {
                    public_key: keys.public.encode_hex::<String>(),
                },
                &keys.public.encode_hex::<String>(),
                0,
                &keys,
            )?)?;

        // handle incoming messages and proposed blocks

        let mut lines = buffer_reader.lines();

        loop {
            tokio::select! {
                Ok(Some(line)) = lines.next_line() => {
                    let mut args = line.split_whitespace();
                    Self::execute_action(&mut args, runtime)?;
                }

                event = runtime.swarm.select_next_some() => {
                    DhtBehaviourEvent::from_event(event, runtime).await?;
                }

                Some(block) = rx.recv() => {
                    tracing::info!("Proposing block: {:?}", block);
                    if let Err(e) = runtime.swarm
                        .behaviour_mut()
                        .gossip
                        .publish(IdentTopic::new(BLOCKS), to_vec(&block)?) {
                            tracing::error!("Couldn't publish block: {e}");
                            sleep(Duration::from_secs(1)).await;
                            tx.write().await.send(block)?;
                    }
                }

                Some(_) = sync_rx.recv() => {
                    let peers: Vec<_> = runtime.swarm.connected_peers().copied().collect();
                    if let Some(peer) = peers.first() {
                        runtime.swarm
                            .behaviour_mut()
                            .request_response
                            .send_request(peer, crate::behaviour::Request::LongestChainHashes);
                    }
                }
            }
        }
    }
}
