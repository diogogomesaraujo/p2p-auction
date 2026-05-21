use crate::{blockchain::block::Block, runtime::Runtime, topic};
use libp2p::{
    PeerId, identify, kad, ping, request_response,
    swarm::{NetworkBehaviour, SwarmEvent},
};
use libp2p_gossipsub::{self as gossipsub};
use serde::{Deserialize, Serialize};
use serde_json::from_slice;
use std::error::Error;
use tracing::{debug, error, info, warn};

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    LongestChainBlocks,
    LongestChainHashes,
    BlocksByHashes(Vec<String>),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    LongestChainBlocks(Vec<Block>),
    LongestChainHashes(Vec<String>),
    BlocksByHashes(Vec<Block>),
}

/// Struct that represents the `libp2p` primitives used to construct the DHT.
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "DhtBehaviourEvent")]
pub struct DhtBehaviour {
    pub kad: kad::Behaviour<kad::store::MemoryStore>,
    pub ping: ping::Behaviour,
    pub identify: identify::Behaviour,
    pub gossip: gossipsub::Behaviour,
    pub request_response: request_response::cbor::Behaviour<Request, Response>,
}

/// Struct that represents a DHT event.
#[derive(Debug)]
pub enum DhtBehaviourEvent {
    Kad(kad::Event),
    Ping(ping::Event),
    Identify(Box<identify::Event>),
    Gossip(gossipsub::Event),
    RequestResponse(request_response::Event<Request, Response>),
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

impl From<request_response::Event<Request, Response>> for DhtBehaviourEvent {
    fn from(event: request_response::Event<Request, Response>) -> Self {
        Self::RequestResponse(event)
    }
}

impl DhtBehaviourEvent {
    /// Function that maps types of events to executable actions.
    pub async fn from_event(
        event: SwarmEvent<DhtBehaviourEvent>,
        runtime: &mut Runtime,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {:?}.", address);
            }

            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                debug!(
                    "Connected to {:?}. Connected peers: {:?}",
                    peer_id,
                    runtime.swarm.connected_peers().collect::<Vec<&PeerId>>()
                );
            }

            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                if let Some(cause) = &cause {
                    warn!("Connection to {:?} closed due to: {:?}", peer_id, cause);
                } else {
                    info!("Connection to {:?} closed cleanly.", peer_id);
                }
            }

            SwarmEvent::Behaviour(DhtBehaviourEvent::Kad(event)) => match event {
                kad::Event::InboundRequest { request } => {
                    debug!("Inbound Kademlia request: {:?}", request);
                }

                kad::Event::RoutingUpdated {
                    peer,
                    is_new_peer,
                    addresses,
                    bucket_range,
                    old_peer,
                } => {
                    debug!(
                        "RoutingUpdated peer={peer:?} is_new_peer={is_new_peer} \
                         addresses={addresses:?} bucket_range={bucket_range:?} old_peer={old_peer:?}"
                    );
                    debug!(
                        "Connected peers: {:?}",
                        runtime.swarm.connected_peers().collect::<Vec<&PeerId>>()
                    );
                }

                kad::Event::UnroutablePeer { peer } => {
                    debug!("No listening address found for peer {peer:?}");
                }

                kad::Event::RoutablePeer { peer, address } => {
                    debug!("Found routable peer {peer:?} address={address:?}");

                    runtime
                        .swarm
                        .behaviour_mut()
                        .kad
                        .add_address(&peer, address);
                }

                kad::Event::PendingRoutablePeer { peer, address } => {
                    debug!("Pending routable peer={peer:?} address={address:?}");
                }

                kad::Event::ModeChanged { new_mode } => {
                    debug!("Kademlia mode changed to {:?}", new_mode);
                }

                kad::Event::OutboundQueryProgressed {
                    id,
                    result,
                    stats,
                    step,
                } => {
                    debug!("Kad query id={id:?} stats={stats:?} step={step:?}");
                    match result {
                        kad::QueryResult::Bootstrap(Ok(ok)) => {
                            info!("Bootstrap completed: {:?}", ok);
                        }
                        kad::QueryResult::Bootstrap(Err(err)) => {
                            warn!("Bootstrap failed: {:?}", err);
                        }
                        kad::QueryResult::GetClosestPeers(Ok(ok)) => {
                            info!("Closest peers: {:?}", ok.peers);
                        }
                        kad::QueryResult::GetClosestPeers(Err(err)) => {
                            warn!("Couldn't find the node at {:?}.", err.key());
                        }
                        _ => {}
                    }
                }
            },

            SwarmEvent::Behaviour(DhtBehaviourEvent::Ping(event)) => {
                debug!(
                    "Ping: {}, {}, {:?}.",
                    event.connection, event.peer, event.result
                );

                if let Err(e) = event.result {
                    warn!("Ping failed for peer {:?}: {:?}", event.peer, e);
                }
            }

            SwarmEvent::Behaviour(DhtBehaviourEvent::Identify(event)) => {
                if let identify::Event::Received { peer_id, info, .. } = *event {
                    for addr in info.listen_addrs {
                        runtime
                            .swarm
                            .behaviour_mut()
                            .kad
                            .add_address(&peer_id, addr);
                    }
                }
            }
            SwarmEvent::Behaviour(DhtBehaviourEvent::Gossip(event)) => match event {
                gossipsub::Event::Message {
                    propagation_source,
                    message_id,
                    message,
                } if message.topic.as_str() == topic::BLOCKS => {
                    // PoW gate: reject blocks whose signed source PeerId was not mined
                    match message.source {
                        Some(source) if !crate::key::verify_peer_id(&source) => {
                            warn!(
                                "Rejecting block from {:?}: source PeerId does not satisfy PoW difficulty.",
                                source
                            );
                            return Ok(());
                        }
                        None => {
                            warn!(
                                "Rejecting block from {:?}: no source PeerId on signed message.",
                                propagation_source
                            );
                            return Ok(());
                        }
                        _ => {}
                    }

                    info!(
                        "Received block through gossip from {:?}, id {:?}",
                        propagation_source, message_id
                    );

                    match from_slice::<Block>(&message.data) {
                        Ok(block) => {
                            if let Err(e) = runtime
                                .accept_block_from_gossip(block, propagation_source)
                                .await
                            {
                                error!(
                                    "Failed to accept block through gossip from {:?}: {e}",
                                    propagation_source
                                );
                            }
                        }
                        Err(e) => {
                            error!("Malformed block from {:?}: {e}", propagation_source);
                        }
                    }
                }

                gossipsub::Event::Message {
                    propagation_source,
                    message_id,
                    message,
                } => {
                    debug!(
                        "Ignoring gossip message from {:?}, id {:?}, topic {:?}",
                        propagation_source, message_id, message.topic
                    );
                }

                gossipsub::Event::GossipsubNotSupported { peer_id } => {
                    warn!("Gossipsub not supported by {:?}", peer_id);
                }

                gossipsub::Event::SlowPeer {
                    peer_id,
                    failed_messages,
                } => {
                    warn!(
                        "Slow peer {:?}: {:?} failed messages",
                        peer_id, failed_messages
                    );
                }

                gossipsub::Event::Subscribed { peer_id, topic } => {
                    info!("Peer {:?} subscribed to topic {}", peer_id, topic);
                }

                gossipsub::Event::Unsubscribed { peer_id, topic } => {
                    debug!("Peer {:?} unsubscribed from topic {}", peer_id, topic);
                }
            },

            SwarmEvent::Behaviour(DhtBehaviourEvent::RequestResponse(event)) => match event {
                request_response::Event::Message { peer, message, .. } => match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => {
                        let response = match request {
                            Request::LongestChainBlocks => {
                                info!("Longest chain of blocks request from peer {:?}", peer);
                                let longest_chain =
                                    runtime.state.read().await.blockchain.longest_chain.clone();
                                let blocks = runtime.state.read().await.blockchain.blocks.clone();
                                Response::LongestChainBlocks(
                                    longest_chain
                                        .iter()
                                        .filter_map(|h| blocks.get(h).cloned())
                                        .collect(),
                                )
                            }

                            Request::LongestChainHashes => {
                                info!("Longest chain of hashes request from peer {:?}", peer);
                                let hashes =
                                    runtime.state.read().await.blockchain.longest_chain.clone();
                                Response::LongestChainHashes(hashes)
                            }

                            Request::BlocksByHashes(hashes) => {
                                info!("List of blocks by their hash request from peer {:?}", peer);

                                let chain =
                                    runtime.state.read().await.blockchain.longest_chain.clone();
                                let blocks = runtime.state.read().await.blockchain.blocks.clone();

                                Response::BlocksByHashes(
                                    chain
                                        .into_iter()
                                        .filter(|h| hashes.contains(h))
                                        .filter_map(|h| blocks.get(&h).cloned())
                                        .collect(),
                                )
                            }
                        };
                        if let Err(e) = runtime
                            .swarm
                            .behaviour_mut()
                            .request_response
                            .send_response(channel, response)
                        {
                            error!("Failed to send response to {:?}: {:?}", peer, e);
                        }
                    }
                    request_response::Message::Response { response, .. } => match response {
                        Response::BlocksByHashes(blocks) => {
                            info!("Received requested blocks from {:?}", peer);
                            for b in blocks {
                                if let Err(e) = runtime.accept_block_from_r_r(b, peer).await {
                                    warn!("Failed to accept requested block from {:?}: {e}", peer);
                                }
                            }
                        }

                        Response::LongestChainBlocks(blocks) => {
                            info!("Received longest chain of blocks from peer {:?}", peer);
                            for b in blocks {
                                if let Err(e) = runtime.accept_block_from_r_r(b, peer).await {
                                    warn!(
                                        "Failed to accept longest-chain block from {:?}: {e}",
                                        peer
                                    );
                                }
                            }
                        }

                        Response::LongestChainHashes(hashes) => {
                            info!("Received longest chain of hashes from peer {:?}", peer);

                            let blocks = runtime.state.read().await.blockchain.blocks.clone();

                            let missing: Vec<String> = hashes
                                .into_iter()
                                .filter(|h| !blocks.contains_key(h))
                                .collect();

                            if !missing.is_empty() {
                                runtime
                                    .swarm
                                    .behaviour_mut()
                                    .request_response
                                    .send_request(&peer, Request::BlocksByHashes(missing));
                            }
                        }
                    },
                },
                request_response::Event::OutboundFailure { peer, error, .. } => {
                    warn!("Outbound request failure to {:?}: {:?}", peer, error);
                }

                request_response::Event::InboundFailure { peer, error, .. } => {
                    warn!("Inbound request failure from {:?}: {:?}", peer, error);
                }

                request_response::Event::ResponseSent { peer, .. } => {
                    debug!("Response sent to {:?}", peer);
                }
            },
            _ => {}
        }

        Ok(())
    }
}
