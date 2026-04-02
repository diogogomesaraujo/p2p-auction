use libp2p::{
    Swarm, identify,
    kad::{self, GetRecordOk, PeerRecord, PutRecordOk, QueryResult, Record, store::MemoryStore},
    ping,
    swarm::{NetworkBehaviour, SwarmEvent},
};
use std::error::Error;
use tracing::{error, info};

use libp2p_gossipsub::{self as gossipsub};

use crate::{
    config::Config,
    gossip::{
        BlockAnnouncement, LivenessSummary, OverlayMetadata, ReputationSignal,
        SuspiciousPeerReport, Topic, TransactionAnnouncement,
    },
};

// TODO(TRUST):
// Add a local trust / reputation structure accessible from event handling.
// Example later:
// - reputation_table: HashMap<PeerId, PeerReputation>
// - suspicion_table: HashMap<PeerId, SuspicionState>
// - quarantined_peers: HashSet<PeerId>
// For now this is missing completely.
//
// TODO(CHURN):
// Add local bookkeeping for:
// - last_seen per peer
// - last_successful_response per peer
// - last_record_republish time
// - bucket refresh timestamps
//
// TODO(ECLIPSE + SYBIL):
// Before accepting peers into the routing table, introduce admission checks:
// - subnet diversity
// - per-prefix / per-bucket limits
// - identity age preference
// - possibly resource / PoW checks later

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "MyBehaviourEvent")]
pub struct MyBehaviour {
    pub kad: kad::Behaviour<MemoryStore>,
    pub ping: ping::Behaviour,
    pub identify: identify::Behaviour,
    pub gossip: gossipsub::Behaviour,
    // TODO(TRUST):
    // This behaviour currently has no peer scoring or trust memory.
    // Later add a custom component / shared state for:
    // - peer reputation scores
    // - suspicion counts
    // - quarantine / blacklist state
    //
    // Example direction:
    // pub trust: TrustManager,
}

#[derive(Debug)]
pub enum MyBehaviourEvent {
    Kad(kad::Event),
    Ping(ping::Event),
    Identify(Box<identify::Event>),
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
        Self::Identify(event.into())
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

                // TODO(ANTI-IMPERSONATION):
                // Persist local node identity + address binding in a stable local record.
                // Later use this to sign overlay metadata and maintain peer history across restarts.
            }

            SwarmEvent::Behaviour(MyBehaviourEvent::Kad(kad::Event::RoutingUpdated {
                peer,
                addresses,
                ..
            })) => {
                info!("Routing table updated with peer id {peer:?}, and addresses {addresses:?}.");

                // TODO(TRUST):
                // On successful routing-table presence, initialize or update local reputation entry.
                // Example:
                // - if first seen -> create default neutral score
                // - bump "availability" / "responsiveness" if repeatedly useful
                //
                // TODO(ECLIPSE):
                // Do not blindly accept routing updates forever.
                // Later enforce:
                // - bucket diversity
                // - subnet diversity
                // - max peers per prefix
                // - prefer long-lived peers over newly seen peers
            }

            SwarmEvent::Behaviour(MyBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                result,
                ..
            })) => {
                match result {
                    QueryResult::GetClosestPeers(Ok(ok)) => {
                        info!("The current closest peers: {:?}.", ok.peers);

                        // TODO(ECLIPSE + BYZANTINE):
                        // Lookup results should not be trusted blindly.
                        // Later:
                        // - perform multiple disjoint lookups
                        // - cross-check peers returned by different paths
                        // - prefer trusted peers when choosing next hop
                        // - downscore peers that repeatedly return poisoned routing info
                    }

                    QueryResult::GetClosestPeers(Err(e)) => {
                        error!("Couldn't find the node at {:?}.", e.key());

                        // TODO(TRUST + CHURN):
                        // Failed lookups should affect peer availability / trust.
                        // Later:
                        // - decrement reputation of peers that timeout or fail repeatedly
                        // - mark them as temporarily unreliable under churn
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

                        // TODO(BYZANTINE):
                        // This currently accepts the first returned record.
                        // Later:
                        // - compare responses from multiple peers
                        // - require confidence / quorum for sensitive records
                        // - validate signatures / hashes where applicable
                        // - penalize peers that return conflicting or malformed records
                    }

                    QueryResult::GetRecord(Err(e)) => {
                        error!("Failed to find value at {:?}.", e.key());

                        // TODO(CHURN):
                        // Missing records under churn should trigger:
                        // - retry via alternate peers
                        // - possible bucket refresh
                        // - record republish if we are responsible
                    }

                    QueryResult::PutRecord(Ok(PutRecordOk { key })) => {
                        info!("Successfully stored the value at {:?}", key);

                        // TODO(CHURN):
                        // Record storage currently has no replication / expiration lifecycle.
                        // Later implement:
                        // - replication factor policy (k replicas or quorum-based)
                        // - expiration / TTL
                        // - periodic republish / refresh
                        // - ownership tracking for records we should republish
                    }

                    QueryResult::PutRecord(Err(e)) => {
                        error!("Failed to store the value requested at {:?}.", e.key());

                        // TODO(TRUST + BYZANTINE):
                        // Store failures should be attributed when possible.
                        // Later:
                        // - retry through different peers
                        // - prefer trusted peers for storage
                        // - penalize peers that accept then fail or stall repeatedly
                    }

                    _ => {}
                }
            }

            SwarmEvent::Behaviour(MyBehaviourEvent::Ping(event)) => {
                info!(
                    "Ping event: {}, {}, {:?}.",
                    event.connection, event.peer, event.result
                );

                // TODO(CHURN + TRUST):
                // Use ping success/failure as one of the main liveness signals.
                // Later:
                // - bump score on success
                // - increment suspicion on repeated failure
                // - quarantine peers that flap / stall too much
                // - track last_seen / RTT / availability window
            }

            // should be fixed. only bootstrap once and at most periodically -> as it is is overkill. see slides
            SwarmEvent::Behaviour(MyBehaviourEvent::Identify(event)) => {
                if let identify::Event::Received { peer_id, info, .. } = *event {
                    // TODO(ANTI-IMPERSONATION):
                    // Validate metadata more strictly here.
                    // Later:
                    // - verify signed overlay metadata
                    // - keep persistent trust binding for this PeerId
                    // - validate claimed listen addresses as much as possible
                    //
                    // TODO(ECLIPSE + SYBIL):
                    // Do NOT add every identified peer blindly.
                    // Before insertion, enforce:
                    // - subnet diversity
                    // - per-prefix cap
                    // - identity age preference
                    // - optional costly admission / PoW later

                    for addr in info.listen_addrs {
                        swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                    }

                    // TODO(CHURN):
                    // Bucket refresh should be scheduled deliberately, not triggered on every identify.
                    // Replace this eager bootstrap with:
                    // - initial bootstrap once at startup
                    // - periodic bootstrap / bucket refresh timer
                    // - refresh stale buckets only when needed
                }
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

                // TODO(TRUST):
                // Before processing gossip payloads, check whether propagation_source is:
                // - trusted
                // - neutral
                // - suspicious / quarantined
                // Then decide whether to accept, deprioritize, or ignore the message.
                //
                // TODO(LEDGER SUPPORT):
                // Add anti-spam filtering here:
                // - drop oversized / malformed payloads
                // - rate-limit frequent publishers
                // - require validation hooks per topic

                match topic {
                    Topic::TRANSACTIONS => {
                        match serde_json::from_slice::<TransactionAnnouncement>(&message.data) {
                            Ok(msg) => {
                                info!("Transaction announcement: {:?}", msg);

                                // TODO(LEDGER SUPPORT):
                                // This is only infrastructure for later ledger layer.
                                // Add:
                                // - basic schema validation
                                // - anti-spam / dedup
                                // - optional hash/content-addressed indexing hook
                            }
                            Err(e) => error!("Invalid transaction payload: {e}"),
                        }
                    }

                    Topic::BLOCKS => {
                        match serde_json::from_slice::<BlockAnnouncement>(&message.data) {
                            Ok(msg) => {
                                info!("Block announcement: {:?}", msg);

                                // TODO(LEDGER SUPPORT):
                                // Add content-addressed lookup hook:
                                // - announced block hash/id should map to later retrieval
                                // - keep only overlay-side dissemination logic here
                            }
                            Err(e) => error!("Invalid block payload: {e}"),
                        }
                    }

                    Topic::OVERLAY_META => {
                        match serde_json::from_slice::<OverlayMetadata>(&message.data) {
                            Ok(msg) => {
                                info!("Overlay metadata: {:?}", msg);

                                // TODO(ANTI-IMPERSONATION):
                                // Overlay metadata should be signed and verified.
                                // The metadata must be bound to the sender's PeerId.
                                //
                                // TODO(TRUST):
                                // Persist peer metadata history:
                                // - first seen
                                // - last seen
                                // - role changes
                                // - protocol support consistency
                            }
                            Err(e) => error!("Invalid overlay metadata payload: {e}"),
                        }
                    }

                    Topic::PEER_REPUTATION => {
                        match serde_json::from_slice::<ReputationSignal>(&message.data) {
                            Ok(msg) => {
                                info!("Peer reputation signal: {:?}", msg);

                                // TODO(TRUST):
                                // Do not trust remote reputation blindly.
                                // Later:
                                // - weight reports by reporter trust
                                // - apply bounded score deltas
                                // - prevent gossip-based reputation abuse
                                // - decay old penalties / rewards over time
                            }
                            Err(e) => error!("Invalid reputation payload: {e}"),
                        }
                    }

                    Topic::SUSPICIOUS_PEERS => {
                        match serde_json::from_slice::<SuspiciousPeerReport>(&message.data) {
                            Ok(msg) => {
                                info!("Suspicious peer report: {:?}", msg);

                                // TODO(TRUST + BYZANTINE):
                                // Convert reports into local suspicion tracking only after validation.
                                // Example later:
                                // - require repeated independent reports
                                // - combine with direct local observations
                                // - quarantine only above threshold
                            }
                            Err(e) => error!("Invalid suspicious-peer payload: {e}"),
                        }
                    }

                    Topic::LIVENESS => {
                        match serde_json::from_slice::<LivenessSummary>(&message.data) {
                            Ok(msg) => {
                                info!("Liveness summary: {:?}", msg);

                                // TODO(CHURN):
                                // Use liveness summaries as soft signals only.
                                // They should complement, not replace, direct observations.
                            }
                            Err(e) => error!("Invalid liveness payload: {e}"),
                        }
                    }

                    _ => {
                        info!("Received message for unknown topic {}", topic);

                        // TODO(ANTI-SPAM):
                        // Unknown or repeated garbage topics should affect sender reputation
                        // if this becomes abusive.
                    }
                }
            }

            SwarmEvent::Behaviour(MyBehaviourEvent::Gossip(gossipsub::Event::Subscribed {
                peer_id,
                topic,
            })) => {
                info!("Peer {:?} subscribed to topic {}", peer_id, topic);

                // TODO(TRUST):
                // Track topic subscriptions as weak metadata.
                // Useful later for:
                // - role inference
                // - spam detection
                // - peer behaviour profiling
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
                // TODO(ECLIPSE + SYBIL):
                // Connection establishment should not automatically imply routing-table admission.
                // Before add_address / promotion, apply:
                // - peer scoring
                // - diversity constraints
                // - identity age / stability checks
                // - optional address ownership validation

                swarm
                    .behaviour_mut()
                    .kad
                    .add_address(&peer_id, endpoint.get_remote_address().clone());

                // TODO(TRUST):
                // Initialize peer history here:
                // - first connected at
                // - connection count
                // - last successful session
            }

            _ => {}
        }

        Ok(())
    }
}
