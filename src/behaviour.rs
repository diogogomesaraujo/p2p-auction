use libp2p::{
    Swarm, identify,
    kad::{self, GetRecordOk, PeerRecord, PutRecordOk, QueryResult, Record, store::MemoryStore},
    ping,
    swarm::{NetworkBehaviour, SwarmEvent},
};
use std::error::Error;
use tracing::{error, info};

use libp2p_gossipsub::{self as gossipsub};

use libp2p_gossipsub::{self};

use crate::{
    config::Config,
    gossip::{
        BlockAnnouncement, LivenessSummary, OverlayMetadata, ReputationSignal,
        SuspiciousPeerReport, Topic, TransactionAnnouncement,
    },
};

// similar to example from https://docs.rs/libp2p/latest/libp2p/swarm/trait.NetworkBehaviour.html
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "MyBehaviourEvent")]
pub struct MyBehaviour {
    pub kad: kad::Behaviour<MemoryStore>,
    pub ping: ping::Behaviour,
    pub identify: identify::Behaviour,
    pub gossip: gossipsub::Behaviour,
}

#[derive(Debug)]
pub enum MyBehaviourEvent {
    Kad(kad::Event),
    Ping(ping::Event),
    Identify(identify::Event),
    Gossip(gossipsub::Event),
}

impl From<kad::Event> for MyBehaviourEvent {
    fn from(event: kad::Event) -> Self {
        Self::Kad(event)
    }
}

impl From<ping::Event> for MyBehaviourEvent {
    fn from(event: ping::Event) -> Self {
        Self::Ping(event)
    }
}

impl From<identify::Event> for MyBehaviourEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(event)
    }
}

impl From<gossipsub::Event> for MyBehaviourEvent {
    fn from(event: gossipsub::Event) -> Self {
        Self::Gossip(event)
    }
}

impl MyBehaviourEvent {
    pub fn from_event(
        event: SwarmEvent<Self>,
        swarm: &mut Swarm<MyBehaviour>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                let config = Config::from(address, *swarm.local_peer_id());
                config.to_file()?;

                info!("Listening on {:?}.", config.address);
            }
            SwarmEvent::Behaviour(MyBehaviourEvent::Kad(kad::Event::RoutingUpdated {
                peer,
                addresses,
                ..
            })) => {
                info!("Routing table updated with peer id {peer:?}, and addresses {addresses:?}.");
            }
            SwarmEvent::Behaviour(MyBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                result,
                ..
            })) => {
                match result {
                    QueryResult::GetClosestPeers(Ok(ok)) => {
                        info!("The current closets peers: {:?}.", ok.peers);
                    }

                    QueryResult::GetClosestPeers(Err(e)) => {
                        error!("Couldn't find the node at {:?}.", e.key());
                    }

                    QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(PeerRecord {
                        record: Record { key, value, .. },
                        ..
                    }))) => {
                        info!(
                            "Successfully found value {} at {:?}.",
                            String::from_utf8(value)?,
                            key,
                        );
                    }
                    QueryResult::GetRecord(Err(e)) => {
                        error!("Failed to find value at {:?}.", e.key());
                    }

                    QueryResult::PutRecord(Ok(PutRecordOk { key })) => {
                        info!("Successfully stored the value at {:?}", key);
                    }
                    QueryResult::PutRecord(Err(e)) => {
                        error!("Failed to store the value requested at {:?}.", e.key());
                    }

                    // QueryResult::GetProviders(Ok(GetProvidersOk::FoundProviders { key, providers, .. })) => {
                    //     providers.iter().for_each(|provider| println!("Received GET_PROVIDER successful message: provider: {:?}, key: {:?}", provider, key));
                    // }
                    // QueryResult::GetProviders(Err(e)) => {
                    //     eprintln!("Received GET_PROVIDER error: {e}");
                    // }

                    // QueryResult::StartProviding(Ok(AddProviderOk{key})) => {
                    //     println!("Received PUT_PROVIDER successful message: key: {:?}", key);
                    // }
                    // QueryResult::StartProviding(Err(e)) => {
                    //     eprintln!("Received GET_PROVIDER error: {e}");
                    // }
                    _ => {}
                }
            }

            SwarmEvent::Behaviour(MyBehaviourEvent::Ping(event)) => {
                info!(
                    "Ping event: {}, {}, {:?}.",
                    event.connection,
                    event.peer.to_string(),
                    event.result
                );
            }

            SwarmEvent::Behaviour(MyBehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) => {
                for addr in info.listen_addrs {
                    swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                }

                let _ = swarm.behaviour_mut().kad.bootstrap();
            }

            SwarmEvent::Behaviour(MyBehaviourEvent::Gossip(gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            })) => {
                let topic = message.topic.as_str();

                info!(
                    "Received gossip message from {:?}, id {:?}, topic {}",
                    propagation_source, message_id, topic
                );

                match topic {
                    Topic::TRANSACTIONS => {
                        match serde_json::from_slice::<TransactionAnnouncement>(&message.data) {
                            Ok(msg) => info!("Transaction announcement: {:?}", msg),
                            Err(e) => error!("Invalid transaction payload: {e}"),
                        }
                    }

                    Topic::BLOCKS => {
                        match serde_json::from_slice::<BlockAnnouncement>(&message.data) {
                            Ok(msg) => info!("Block announcement: {:?}", msg),
                            Err(e) => error!("Invalid block payload: {e}"),
                        }
                    }

                    Topic::OVERLAY_META => {
                        match serde_json::from_slice::<OverlayMetadata>(&message.data) {
                            Ok(msg) => info!("Overlay metadata: {:?}", msg),
                            Err(e) => error!("Invalid overlay metadata payload: {e}"),
                        }
                    }

                    Topic::PEER_REPUTATION => {
                        match serde_json::from_slice::<ReputationSignal>(&message.data) {
                            Ok(msg) => info!("Peer reputation signal: {:?}", msg),
                            Err(e) => error!("Invalid reputation payload: {e}"),
                        }
                    }

                    Topic::SUSPICIOUS_PEERS => {
                        match serde_json::from_slice::<SuspiciousPeerReport>(&message.data) {
                            Ok(msg) => info!("Suspicious peer report: {:?}", msg),
                            Err(e) => error!("Invalid suspicious-peer payload: {e}"),
                        }
                    }

                    Topic::LIVENESS => {
                        match serde_json::from_slice::<LivenessSummary>(&message.data) {
                            Ok(msg) => info!("Liveness summary: {:?}", msg),
                            Err(e) => error!("Invalid liveness payload: {e}"),
                        }
                    }

                    _ => {}
                }
            }

            SwarmEvent::Behaviour(MyBehaviourEvent::Gossip(gossipsub::Event::Subscribed {
                peer_id,
                topic,
            })) => {
                info!("Peer {:?} subscribed to topic {}", peer_id, topic);
            }

            SwarmEvent::Behaviour(MyBehaviourEvent::Gossip(gossipsub::Event::Unsubscribed {
                peer_id,
                topic,
            })) => {
                info!("Peer {:?} unsubscribed from topic {}", peer_id, topic);
            }

            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                swarm
                    .behaviour_mut()
                    .kad
                    .add_address(&peer_id, endpoint.get_remote_address().clone());
            }

            _ => {}
        }

        Ok(())
    }
}
