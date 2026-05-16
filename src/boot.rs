use crate::{runtime::Runtime, vm::VirtualMachine};
use async_trait::async_trait;
use libp2p::{Multiaddr, PeerId, StreamProtocol, identity::Keypair};
use std::{error::Error, str::SplitWhitespace};
use tracing::info;

/// Struct that represents a boot node of the network.
/// Boot nodes serve as entry points and keep track of peers currently using the network.
pub struct BootNode {
    pub multi_address: Multiaddr,
}

pub enum VirtualMachineAction {
    Ping,
    RoutingTable,
}

impl BootNode {
    /// Function that creates a new boot node from a predetermined address.
    pub fn new(multi_address: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(Self {
            multi_address: multi_address.parse::<Multiaddr>()?,
        })
    }
}

#[async_trait]
impl VirtualMachine for BootNode {
    type VirtualMachineAction = VirtualMachineAction;

    fn action_from_str(action_text: &str) -> Option<Self::VirtualMachineAction> {
        match action_text {
            "PING" => Some(VirtualMachineAction::Ping),
            "ROUTING_TABLE" => Some(VirtualMachineAction::RoutingTable),
            _ => None,
        }
    }

    async fn init(
        self,
        ipfs_proto_name: StreamProtocol,
        key: Keypair,
        rpc_address: &str,
    ) -> Result<Runtime, Box<dyn Error + Send + Sync>> {
        let mut runtime = Runtime::init(ipfs_proto_name, key, rpc_address).await?;

        runtime.swarm.listen_on(self.multi_address)?;

        Ok(runtime)
    }

    fn match_action(
        args: &mut SplitWhitespace,
        runtime: &mut Runtime,
        rpc: VirtualMachineAction,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        match rpc {
            VirtualMachineAction::Ping => {
                let address = Self::arg_parse(args)?.parse::<Multiaddr>()?;
                runtime.swarm.dial(address)?;
            }

            VirtualMachineAction::RoutingTable => {
                info!(
                    "Current state of the routing table: {:?}",
                    runtime.swarm.connected_peers().collect::<Vec<&PeerId>>(),
                );
            }
        }

        Ok(())
    }
}
