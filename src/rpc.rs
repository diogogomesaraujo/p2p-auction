use async_trait::async_trait;
use libp2p::{StreamProtocol, futures::StreamExt, identity::Keypair};
use std::{error::Error, str::SplitWhitespace};
use tokio::io::{AsyncBufReadExt, BufReader, Stdin};

use crate::{behaviour::MyBehaviourEvent, runtime::Runtime};

pub const BOOT_NODE_MULTIADDR: &str = "/dnsaddr/bootstrap.libp2p.io";
pub const LISTEN_ON: &str = "/ip4/0.0.0.0/tcp/0";

#[async_trait]
pub trait Rpc {
    type RpcAction;

    fn match_action(
        args: &mut SplitWhitespace,
        runtime: &mut Runtime,
        rpc: Self::RpcAction,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;

    fn action_from_str(action_text: &str) -> Option<Self::RpcAction>;

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
    ) -> Result<Runtime, Box<dyn Error + Send + Sync>>;

    async fn run(
        runtime: &mut Runtime,
        buffer_reader: BufReader<Stdin>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut lines = buffer_reader.lines();

        loop {
            tokio::select! {
                Ok(Some(line)) = lines.next_line() => {
                    let mut args = line.split_whitespace();
                    Self::execute_action(&mut args, runtime)?;
                }

                event = runtime.swarm.select_next_some() => {
                    MyBehaviourEvent::from_event(event, &mut runtime.swarm)?;
                }
            }
        }
    }
}
