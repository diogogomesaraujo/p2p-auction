use crate::{
    runtime::Runtime,
    vm::{LISTEN_ON, VirtualMachine},
};
use async_trait::async_trait;
use libp2p::{Multiaddr, PeerId, StreamProtocol, identity::Keypair, kad::KBucketKey};
use std::{error::Error, str::SplitWhitespace};
use tracing::info;

pub struct Node {
    pub bootstrap_nodes: Vec<(Multiaddr, PeerId)>,
}

pub enum VirtualMachineAction {
    Ping,
    FindNode,
    RoutingTable,
    ConnectedPeers,
}

impl Node {
    pub fn new(bootstrap_nodes: Vec<(Multiaddr, PeerId)>) -> Self {
        Self { bootstrap_nodes }
    }
}

#[async_trait]
impl VirtualMachine for Node {
    type VirtualMachineAction = VirtualMachineAction;

    fn action_from_str(action_text: &str) -> Option<Self::VirtualMachineAction> {
        match action_text {
            "PING" => Some(VirtualMachineAction::Ping),
            "FIND_NODE" => Some(VirtualMachineAction::FindNode),
            "ROUTING_TABLE" => Some(VirtualMachineAction::RoutingTable),
            "CONNECTED_PEERS" => Some(VirtualMachineAction::ConnectedPeers),
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

        for (bootstrap_addr, bootstrap_id) in &self.bootstrap_nodes {
            runtime
                .swarm
                .behaviour_mut()
                .kad
                .add_address(bootstrap_id, bootstrap_addr.clone());

            runtime.swarm.dial(*bootstrap_id)?;
        }

        runtime.swarm.listen_on(LISTEN_ON.parse()?)?;

        // is it needed ? if so pass bootstrap peers in state
        // then on connection established or ident or whatever with boot do it

        // if let Some(boot) = self.bootstrap_nodes.first() {
        //     runtime
        //         .swarm
        //         .behaviour_mut()
        //         .request_response
        //         .send_request(&boot.1, Request::LongestChainBlocks);
        // }

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

            VirtualMachineAction::FindNode => {
                let peer = Self::arg_parse(args)?.parse::<PeerId>()?;
                runtime.swarm.behaviour_mut().kad.get_closest_peers(peer);
            }

            VirtualMachineAction::ConnectedPeers => {
                info!(
                    "Peers currently connected: {:?}",
                    runtime.swarm.connected_peers().collect::<Vec<&PeerId>>(),
                );
            }

            VirtualMachineAction::RoutingTable => {
                let local_key = KBucketKey::from(*runtime.swarm.local_peer_id());

                for bucket in runtime.swarm.behaviour_mut().kad.kbuckets() {
                    for entry in bucket.iter() {
                        println!(
                            "Peer ID: {:?}, Distance {:?}",
                            entry.node.key.preimage(),
                            entry.node.key.distance(&local_key),
                        );
                    }
                }
            }
        }
        Ok(())
    }
}
