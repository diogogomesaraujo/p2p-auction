use crate::{
    behaviour::DhtBehaviourEvent, blockchain::block::Block, runtime::Runtime, state::Runnable,
    topic::BLOCKS,
};
use async_trait::async_trait;
use libp2p::{StreamProtocol, futures::StreamExt, identity::Keypair};
use libp2p_gossipsub::IdentTopic;
use serde_json::to_vec;
use std::{error::Error, str::SplitWhitespace, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, BufReader, Stdin},
    sync::mpsc,
    time::sleep,
};
use tracing::error;

pub const BOOT_NODE_MULTIADDR: &str = "/dnsaddr/bootstrap.libp2p.io";
pub const LISTEN_ON: &str = "/ip4/0.0.0.0/tcp/0";

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
        key: Keypair,
        rpc_address: &str,
    ) -> Result<Runtime, Box<dyn Error + Send + Sync>>;

    async fn run(
        runtime: &mut Runtime,
        public_key: &str,
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

        // mine block thread
        let (tx, mut rx) = mpsc::unbounded_channel::<Block>();
        {
            let state = runtime.state.clone();
            let public_key = public_key.to_string();
            tokio::spawn(async move {
                loop {
                    let block = match state.write().await.blockchain.propose_block(&public_key) {
                        Ok(b) => b,
                        _ => continue,
                    };
                    if let Err(_) = tx.send(block) {
                        error!("Couldn't send the block.");
                    }
                    sleep(Duration::from_secs(2)).await;
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
                    runtime.swarm
                        .behaviour_mut()
                        .gossip
                        .publish(IdentTopic::new(BLOCKS), to_vec(&block)?)?;

                }
            }
        }
    }
}
