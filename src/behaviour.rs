use crate::{
    blockchain::{block::Block, transaction::Transaction},
    runtime::Runtime,
    time::now_unix,
    topic::topic,
};
use libp2p::{
    identify,
    kad::{self, GetRecordOk, PeerRecord, Record},
    ping,
    swarm::{NetworkBehaviour, SwarmEvent},
};
use libp2p_gossipsub::{self as gossipsub};
use serde_json::from_slice;
use std::error::Error;
use tracing::{error, info, warn};

/// Struct that represents the `libp2p` primitives used to construct the DHT.
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "DhtBehaviourEvent")]
pub struct DhtBehaviour {
    pub kad: kad::Behaviour<kad::store::MemoryStore>,
    pub ping: ping::Behaviour,
    pub identify: identify::Behaviour,
    pub gossip: gossipsub::Behaviour,
}

/// Struct that represents a DHT event.
#[derive(Debug)]
pub enum DhtBehaviourEvent {
    Kad(kad::Event),
    Ping(ping::Event),
    Identify(Box<identify::Event>),
    Gossip(gossipsub::Event),
}

impl From<kad::Event> for DhtBehaviourEvent {
    fn from(event: kad::Event) -> Self {
        Self::Kad(event)
    }
}

impl From<ping::Event> for DhtBehaviourEvent {
    fn from(event: ping::Event) -> Self {
        Self::Ping(event)
    }
}

impl From<identify::Event> for DhtBehaviourEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(Box::new(event))
    }
}

impl From<gossipsub::Event> for DhtBehaviourEvent {
    fn from(event: gossipsub::Event) -> Self {
        Self::Gossip(event)
    }
}

impl DhtBehaviourEvent {
    /// Function that maps types of events to executable actions.
    pub fn from_event(
        event: SwarmEvent<DhtBehaviourEvent>,
        runtime: &mut Runtime,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {:?}.", address);
            }

            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                // GossipSub handles blacklisted peers in runtime automatically. So connections are silently refused.
                //
                // Explicitely blacklist peer if it is in the persistent state's blacklist
                if runtime
                    .state
                    .peers
                    .get(&peer_id)
                    .map_or(false, |p| p.blacklisted)
                {
                    runtime
                        .swarm
                        .behaviour_mut()
                        .gossip
                        .blacklist_peer(&peer_id);
                    warn!(
                        "Runtime blacklisted peer {:?} from persistent blacklist",
                        peer_id
                    );
                }

                let now = now_unix()?;

                let entry = runtime.state.peers.entry(peer_id).or_default();
                if entry.first_seen.is_none() {
                    entry.first_seen = Some(now);
                }
                entry.last_seen = Some(now);
                entry.session_count = entry.session_count.saturating_add(1);

                runtime
                    .swarm
                    .behaviour_mut()
                    .kad
                    .add_address(&peer_id, endpoint.get_remote_address().clone());
            }

            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                let now = now_unix()?;

                if let Some(cause) = &cause {
                    warn!("Connection to {:?} closed due to: {:?}", peer_id, cause)
                } else {
                    info!("Connection to {:?} closed cleanly.", peer_id)
                }

                if let Some(entry) = runtime.state.peers.get_mut(&peer_id) {
                    entry.last_seen = Some(now);
                }
            }

            SwarmEvent::Behaviour(DhtBehaviourEvent::Kad(event)) => match event {
                kad::Event::InboundRequest { request } => {
                    info!("Inbound Kademlia request: {:?}", request);
                }

                kad::Event::RoutingUpdated {
                    peer,
                    is_new_peer,
                    addresses,
                    bucket_range,
                    old_peer,
                } => {
                    info!(
                        "RoutingUpdated peer={peer:?} is_new_peer={is_new_peer} \
                         addresses={addresses:?} bucket_range={bucket_range:?} old_peer={old_peer:?}"
                    );

                    let now = now_unix()?;
                    let entry = runtime.state.peers.entry(peer).or_default();
                    if entry.first_seen.is_none() {
                        entry.first_seen = Some(now);
                    }
                    entry.last_seen = Some(now);
                }

                kad::Event::UnroutablePeer { peer } => {
                    info!("UnroutablePeer peer={peer:?}");

                    let now = now_unix()?;
                    let entry = runtime.state.peers.entry(peer).or_default();
                    if entry.first_seen.is_none() {
                        entry.first_seen = Some(now);
                    }
                    entry.last_seen = Some(now);
                }

                kad::Event::RoutablePeer { peer, address } => {
                    info!("RoutablePeer peer={peer:?} address={address:?}");

                    let now = now_unix()?;
                    let entry = runtime.state.peers.entry(peer).or_default();
                    if entry.first_seen.is_none() {
                        entry.first_seen = Some(now);
                    }
                    entry.last_seen = Some(now);
                    runtime
                        .swarm
                        .behaviour_mut()
                        .kad
                        .add_address(&peer, address);
                }

                kad::Event::PendingRoutablePeer { peer, address } => {
                    info!("PendingRoutablePeer peer={peer:?} address={address:?}");

                    let now = now_unix()?;
                    let entry = runtime.state.peers.entry(peer).or_default();
                    if entry.first_seen.is_none() {
                        entry.first_seen = Some(now);
                    }
                    entry.last_seen = Some(now);
                }

                kad::Event::ModeChanged { new_mode } => {
                    info!("Kademlia mode changed to {:?}", new_mode);
                }

                kad::Event::OutboundQueryProgressed {
                    id,
                    result,
                    stats,
                    step,
                } => {
                    info!("Kad query id={id:?} stats={stats:?} step={step:?}");

                    match result {
                        kad::QueryResult::Bootstrap(Ok(ok)) => {
                            info!("Bootstrap completed: {:?}", ok);
                        }
                        kad::QueryResult::Bootstrap(Err(err)) => {
                            error!("Bootstrap failed: {:?}", err);
                        }

                        kad::QueryResult::GetClosestPeers(Ok(ok)) => {
                            info!("Closest peers: {:?}", ok.peers);
                        }
                        kad::QueryResult::GetClosestPeers(Err(err)) => {
                            error!("Couldn't find the node at {:?}.", err.key());
                        }

                        kad::QueryResult::GetProviders(Ok(ok)) => match ok {
                            kad::GetProvidersOk::FoundProviders { key, providers } => {
                                info!("Providers for {:?}: {:?}", key, providers);
                            }
                            kad::GetProvidersOk::FinishedWithNoAdditionalRecord {
                                closest_peers,
                            } => {
                                info!(
                                    "No more providers found. Closest peers: {:?}",
                                    closest_peers
                                );
                            }
                        },
                        kad::QueryResult::GetProviders(Err(err)) => {
                            error!("GetProviders failed: {:?}", err);
                        }

                        kad::QueryResult::StartProviding(Ok(ok)) => {
                            info!("Started providing key {:?}", ok.key);
                        }
                        kad::QueryResult::StartProviding(Err(err)) => {
                            error!("StartProviding failed: {:?}", err);
                        }

                        kad::QueryResult::RepublishProvider(Ok(ok)) => {
                            info!("Republished provider record for key {:?}", ok.key);
                        }
                        kad::QueryResult::RepublishProvider(Err(err)) => {
                            error!("RepublishProvider failed: {:?}", err);
                        }

                        kad::QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(PeerRecord {
                            record: Record { key, value, .. },
                            ..
                        }))) => {
                            info!(
                                "Successfully found value {} at {:?}.",
                                String::from_utf8(value)?,
                                key,
                            );
                        }
                        kad::QueryResult::GetRecord(Ok(
                            GetRecordOk::FinishedWithNoAdditionalRecord { .. },
                        )) => {
                            info!("GetRecord finished without additional records.");
                        }
                        kad::QueryResult::GetRecord(Err(err)) => {
                            error!("Failed to find value at {:?}.", err.key());
                        }

                        kad::QueryResult::PutRecord(Ok(ok)) => {
                            info!("Successfully stored the value at {:?}", ok.key);
                        }
                        kad::QueryResult::PutRecord(Err(err)) => {
                            error!("PutRecord failed: {:?}", err);
                        }

                        kad::QueryResult::RepublishRecord(Ok(ok)) => {
                            info!("Republished record at {:?}", ok.key);
                        }
                        kad::QueryResult::RepublishRecord(Err(err)) => {
                            error!("RepublishRecord failed: {:?}", err);
                        }
                    }
                }
            },

            SwarmEvent::Behaviour(DhtBehaviourEvent::Ping(event)) => {
                info!(
                    "Ping event: {}, {}, {:?}.",
                    event.connection, event.peer, event.result
                );

                let now = now_unix()?;
                let entry = runtime.state.peers.entry(event.peer).or_default();
                if entry.first_seen.is_none() {
                    entry.first_seen = Some(now);
                }
                entry.last_seen = Some(now);
            }

            SwarmEvent::Behaviour(DhtBehaviourEvent::Identify(event)) => {
                if let identify::Event::Received { peer_id, info, .. } = *event {
                    let now = now_unix()?;
                    let entry = runtime.state.peers.entry(peer_id).or_default();
                    if entry.first_seen.is_none() {
                        entry.first_seen = Some(now);
                    }
                    entry.last_seen = Some(now);

                    for addr in info.listen_addrs {
                        runtime
                            .swarm
                            .behaviour_mut()
                            .kad
                            .add_address(&peer_id, addr);
                    }
                }
            }

            SwarmEvent::Behaviour(DhtBehaviourEvent::Gossip(gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            })) => {
                let t = message.topic.as_str();

                // GossipSub automatically rejects messages on unsubscribed topics (prevents probing/flooding)

                info!(
                    "Received gossip message from {:?}, id {:?}, topic {}",
                    propagation_source, message_id, t
                );

                match t {
                    topic::TRANSACTIONS => match from_slice::<Transaction>(&message.data) {
                        Ok(msg) => {
                            info!(
                                "Received transaction gossip ({} bytes) from {:?}.",
                                message.data.len(),
                                propagation_source
                            );

                            // Reward honest peer before processing so a valid-but-locally-rejected
                            // tx does not punish an honest peer.

                            if let Err(e) = runtime.submit_transaction(msg) {
                                error!("Failed to process gossiped transaction: {e}");
                            }
                        }
                        Err(e) => error!("Invalid transaction payload: {e}"),
                        // Penalise since malformed payload is always the sender's fault.
                        // If the peer is persistently malicious, blacklist it so gossipsub
                        // stops routing their messages entirely. (Might define a count for this type of events)
                    },

                    // For Blocks do a simmilar logic
                    topic::BLOCKS => match from_slice::<Block>(&message.data) {
                        Ok(msg) => {
                            info!(
                                "Received block gossip ({} bytes) from {:?}.",
                                message.data.len(),
                                propagation_source
                            );

                            if let Err(e) = runtime.accept_block(msg) {
                                error!(
                                    "Failed to process gossiped block from {:?}: {e}",
                                    propagation_source
                                );
                            }
                        }
                        Err(e) => error!("Invalid block payload: {e}"),
                    },

                    _ => {
                        info!("Received message for unknown topic {}", t);
                    }
                }
            }

            SwarmEvent::Behaviour(DhtBehaviourEvent::Gossip(gossipsub::Event::Subscribed {
                peer_id,
                topic,
            })) => {
                info!("Peer {:?} subscribed to topic {}", peer_id, topic);
            }

            SwarmEvent::Behaviour(DhtBehaviourEvent::Gossip(gossipsub::Event::Unsubscribed {
                peer_id,
                topic,
            })) => {
                info!("Peer {:?} unsubscribed from topic {}", peer_id, topic);
            }

            SwarmEvent::Behaviour(DhtBehaviourEvent::Gossip(gossipsub::Event::SlowPeer {
                peer_id,
                failed_messages,
            })) => {
                warn!(
                    "Slow peer {:?}: {:?} failed messages — penalising",
                    peer_id, failed_messages
                );
                // // decide application_score along with gossip configuration
                // runtime
                //     .swarm
                //     .behaviour_mut()
                //     .gossip
                //     .set_application_score(&peer_id, ());
            }

            _ => {}
        }

        Ok(())
    }
}
