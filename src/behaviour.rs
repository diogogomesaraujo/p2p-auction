use crate::{
    MAX_CONSECUTIVE_FAILURES,
    blockchain::{block::Block, transaction::Transaction},
    gossip::{Metadata, topic},
    runtime::Runtime,
    time::now_unix,
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

                    if let Some(_) = &cause {
                        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
                    } else {
                        entry.consecutive_failures = 0;
                    }

                    if entry.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                        warn!(
                            "Evicting {:?} after {} consecutive failures",
                            peer_id, entry.consecutive_failures
                        );
                        runtime.swarm.behaviour_mut().kad.remove_peer(&peer_id);
                        entry.is_in_routing_table = false;
                    }
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
                    entry.is_in_routing_table = true;
                    entry.is_routable_candidate = true;

                    if let Some(evicted) = old_peer
                        && let Some(old) = runtime.state.peers.get_mut(&evicted)
                    {
                        old.is_in_routing_table = false;
                    }
                }

                kad::Event::UnroutablePeer { peer } => {
                    info!("UnroutablePeer peer={peer:?}");

                    let now = now_unix()?;
                    let entry = runtime.state.peers.entry(peer).or_default();
                    if entry.first_seen.is_none() {
                        entry.first_seen = Some(now);
                    }
                    entry.last_seen = Some(now);
                    entry.is_routable_candidate = false;
                    entry.is_pending_routable = false;
                }

                kad::Event::RoutablePeer { peer, address } => {
                    info!("RoutablePeer peer={peer:?} address={address:?}");

                    let now = now_unix()?;
                    let entry = runtime.state.peers.entry(peer).or_default();
                    if entry.first_seen.is_none() {
                        entry.first_seen = Some(now);
                    }
                    entry.last_seen = Some(now);
                    entry.is_routable_candidate = true;

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
                    entry.is_pending_routable = true;
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

                    let now = now_unix()?;
                    for peer in runtime.state.peers.values_mut() {
                        peer.last_successful_kad_response = Some(now);
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

                match event.result {
                    Ok(_) => {
                        entry.last_successful_ping = Some(now);
                        entry.successful_pings = entry.successful_pings.saturating_add(1);
                        entry.consecutive_failures = 0;
                    }
                    Err(_) => {
                        entry.failed_pings = entry.failed_pings.saturating_add(1);
                        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
                    }
                }
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

                info!(
                    "Received gossip message from {:?}, id {:?}, topic {}",
                    propagation_source, message_id, t
                );

                match t {
                    topic::METADATA => match from_slice::<Metadata>(&message.data) {
                        Ok(msg) => {
                            if msg.peer_id == propagation_source.to_string() {
                                info!("Metadata: {:?}", msg)
                            } else {
                                error!(
                                    "Metadata payload discarded. Peer {:?} impersonated {}.",
                                    propagation_source, msg.peer_id
                                )
                            }
                        }
                        Err(e) => error!("Invalid metadata payload: {e}"),
                    },

                    topic::TRANSACTIONS => match from_slice::<Transaction>(&message.data) {
                        Ok(msg) => {
                            info!(
                                "Received transaction gossip ({} bytes) from {:?}.",
                                message.data.len(),
                                propagation_source
                            );

                            msg.validate()?;

                            if !runtime.state.blockchain.transaction_mempool.contains(&msg) {
                                runtime
                                    .state
                                    .blockchain
                                    .transaction_mempool
                                    .add_transaction(msg)?;
                            }
                        }
                        Err(e) => error!("Invalid transaction payload: {e}"),
                    },

                    topic::BLOCKS => match from_slice::<Block>(&message.data) {
                        Ok(msg) => {
                            info!(
                                "Received block gossip ({} bytes) from {:?}.",
                                message.data.len(),
                                propagation_source
                            );
                            if !msg.verify()? {
                                error!(
                                    "Received invalid block from {:?}, discarding.",
                                    propagation_source
                                );
                            } else {
                                runtime.state.blockchain.accept_block(msg)?;
                            }
                        }
                        Err(e) => error!("Invalid block payload: {e}"),
                    },

                    topic::PEER_REPUTATION => {
                        info!(
                            "Received peer reputation update ({} bytes) from {:?}.",
                            message.data.len(),
                            propagation_source
                        );
                        todo!("deserialize reputation report, update PeerInfo score")
                    }

                    topic::SUSPICIOUS_PEERS => {
                        info!(
                            "Received suspicious peer report ({} bytes) from {:?}.",
                            message.data.len(),
                            propagation_source
                        );
                        todo!(
                            "deserialize report, increment consecutive_failures for reported peer"
                        )
                    }

                    topic::LIVENESS => {
                        info!(
                            "Received liveness heartbeat ({} bytes) from {:?}.",
                            message.data.len(),
                            propagation_source
                        );
                        let now = now_unix()?;
                        if let Some(entry) = runtime.state.peers.get_mut(&propagation_source) {
                            entry.last_seen = Some(now);
                        }
                    }

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

            _ => {}
        }

        Ok(())
    }
}
