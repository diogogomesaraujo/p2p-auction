use async_trait::async_trait;
use libp2p::{StreamProtocol, Swarm, futures::StreamExt, identity::Keypair};
use std::{error::Error, str::SplitWhitespace};
use tokio::io::{AsyncBufReadExt, BufReader, Stdin};

use crate::behaviour::{MyBehaviour, MyBehaviourEvent};

pub const BOOT_NODE_MULTIADDR: &str = "/dnsaddr/bootstrap.libp2p.io";
pub const LISTEN_ON: &str = "/ip4/0.0.0.0/tcp/0";

// TODO:
// Rpc actions currently trigger direct operations only.
// Later add policy-aware wrappers so actions can:
// - prefer trusted peers
// - avoid quarantined peers
// - trigger retries on alternate paths
// - enforce lookup/store cross-checking

#[async_trait]
pub trait Rpc: 'static {
    type RpcAction;

    fn match_action(
        args: &mut SplitWhitespace,
        swarm: &mut Swarm<MyBehaviour>,
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
        swarm: &mut Swarm<MyBehaviour>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let rpc = match Self::action_from_str(&Self::arg_parse(args)?) {
            Some(rpc) => rpc,
            None => return Err("Couldn't parse any argument".into()),
        };

        Self::match_action(args, swarm, rpc)?;

        Ok(())
    }

    async fn init(
        self,
        ipfs_proto_name: StreamProtocol,
        key: Keypair,
    ) -> Result<Swarm<MyBehaviour>, Box<dyn Error + Send + Sync>>;

    async fn run(
        swarm: &mut Swarm<MyBehaviour>,
        buffer_reader: BufReader<Stdin>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut lines = buffer_reader.lines();

        // TODO(CHURN):
        // This event loop currently has no periodic maintenance task.
        // Later add timed maintenance branches for:
        // - bucket refresh
        // - republish / refresh of local records
        // - trust decay
        // - quarantine expiry / blacklist maintenance
        // - stale peer cleanup

        loop {
            tokio::select! {
                Ok(Some(line)) = lines.next_line() => {
                    let mut args = line.split_whitespace();
                    Self::execute_action(&mut args, swarm)?;
                }

                event = swarm.select_next_some() => {
                    MyBehaviourEvent::from_event(event, swarm)?;
                }
            }
        }
    }
}
