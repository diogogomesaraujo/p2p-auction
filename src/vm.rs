use crate::{
    behaviour::DhtBehaviourEvent,
    blockchain::{
        block::Block,
        transaction::{Data, Transaction},
    },
    runtime::Runtime,
    state::Runnable,
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
const FIX_CHAIN_DELAY: Duration = Duration::from_secs(15);
const REGISTER_MINER_DELAY: Duration = Duration::from_secs(4);

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
        // rpc thread
        {
            let state = runtime.state.clone();
            tokio::spawn(async move {
                state.run().await?;
                Ok::<(), Box<dyn Error + Send + Sync>>(())
            });
        }

        // fix chain thread
        {
            let state = runtime.state.clone();
            tokio::spawn(async move {
                loop {
                    if let Err(e) = state.write().await.blockchain.fix() {
                        error!("Couldn't fix the chain: {e}");
                    } else {
                        tracing::info!(
                            "Fixed chain successfully: {:?}",
                            state.read().await.blockchain.longest_chain
                        );
                    }
                    sleep(FIX_CHAIN_DELAY).await;
                }
            });
        }

        // mine block thread
        let (tx, mut rx) = mpsc::unbounded_channel::<Block>();
        let tx = Arc::new(RwLock::new(tx));
        {
            let tx = tx.clone();
            let state = runtime.state.clone();
            let public_key: String = keys.public.encode_hex();
            tokio::spawn(async move {
                loop {
                    let block = match state.write().await.blockchain.propose_block(&public_key) {
                        Ok(b) => b,
                        _ => continue,
                    };
                    if let Err(_) = tx.write().await.send(block) {
                        error!("Couldn't send the block.");
                    }
                    sleep(NEW_BLOCK_SPEED).await;
                }
            });
        }

        {
            let state = runtime.state.clone();

            tokio::spawn(async move {
                sleep(REGISTER_MINER_DELAY).await;
                if let Err(_) = state
                    .write()
                    .await
                    .blockchain
                    .transaction_pool
                    .add_transaction(
                        Transaction::sign(
                            Data::CreateUserAccount {
                                public_key: keys.public.encode_hex::<String>(),
                            },
                            &keys.public.encode_hex::<String>(),
                            0,
                            &keys,
                        )
                        .expect("shouldn't fail"),
                    )
                {
                    error!("Couldn't create the miner account");
                }

                sleep(Duration::from_secs(7)).await;

                let keys = Keypair::generate(&mut rand::rngs::OsRng);

                if let Err(_) = state
                    .write()
                    .await
                    .blockchain
                    .transaction_pool
                    .add_transaction(
                        Transaction::sign(
                            Data::CreateUserAccount {
                                public_key: keys.public.encode_hex(),
                            },
                            &keys.public.encode_hex::<String>(),
                            0,
                            &keys,
                        )
                        .expect("shouldn't fail"),
                    )
                {
                    error!("Couldn't create the miner account");
                }
            });
        }

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
            }
        }
    }
}
