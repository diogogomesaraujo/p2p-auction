use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder,
    futures::StreamExt,
    identify,
    identity::Keypair,
    kad::{
        self, GetRecordOk, Mode, PeerRecord, PutRecordOk, QueryResult, Record, store::MemoryStore,
    },
    noise, ping,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use std::{error::Error, time::Duration};
use tokio::io::{AsyncBufReadExt, BufReader, Stdin};

//simmilar to example from https://docs.rs/libp2p/latest/libp2p/swarm/trait.NetworkBehaviour.html
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "MyBehaviourEvent")]
pub struct MyBehaviour {
    pub kad: kad::Behaviour<MemoryStore>,
    pub ping: ping::Behaviour,
    pub identify: identify::Behaviour,
}

#[derive(Debug)]
pub enum MyBehaviourEvent {
    Kad(kad::Event),
    Ping(ping::Event),
    Identify(identify::Event),
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

pub async fn kad_instance_init(
    ipfs_proto_name: StreamProtocol,
    key: Keypair,
    bootstrap_nodes: &[&str],
) -> Result<Swarm<MyBehaviour>, Box<dyn Error + Send + Sync>> {
    let mut swarm = SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_dns()?
        .with_behaviour(|key| {
            let local_id = key.public().to_peer_id();

            let mut kad_cfg = kad::Config::new(ipfs_proto_name.clone());
            kad_cfg.set_query_timeout(Duration::from_secs(60));

            let store = kad::store::MemoryStore::new(key.public().to_peer_id());

            let kad = kad::Behaviour::with_config(local_id, store, kad_cfg);

            let ping = ping::Behaviour::new(
                ping::Config::new()
                    .with_interval(Duration::from_secs(10))
                    .with_timeout(Duration::from_secs(3)),
            );

            let identify = identify::Behaviour::new(identify::Config::new(
                ipfs_proto_name.to_string(),
                key.public(),
            ));

            Ok(MyBehaviour {
                kad,
                ping,
                identify,
            })
        })?
        .build();

    for node in bootstrap_nodes {
        swarm.behaviour_mut().kad.add_address(
            &node.parse::<PeerId>()?,
            "/dnsaddr/bootstrap.libp2p.io".parse()?,
        );
    }

    swarm.behaviour_mut().kad.set_mode(Some(Mode::Server));
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    Ok(swarm)
}

pub async fn kad_run(
    swarm: &mut Swarm<MyBehaviour>,
    buffer_reader: BufReader<Stdin>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut lines = buffer_reader.lines();
    loop {
        tokio::select! {
            Ok(Some(line)) = lines.next_line() => {
                let mut args = line.split_whitespace();
                match args.next() {
                    Some("PING") => {
                        let address = match args.next() {
                            Some(addr) => addr.parse::<Multiaddr>()?,
                            None => {
                                eprintln!("Expected address");
                                continue;
                            }
                        };

                        swarm.dial(address)?;
                    }

                    Some("STORE") => {
                        let key = match args.next() {
                            Some(key) => kad::RecordKey::new(&key),
                            None => {
                                eprintln!("Expected key");
                                continue;
                            }
                        };

                        let value = match args.next() {
                            Some(value) => value.as_bytes().to_vec(),
                            None => {
                                eprintln!("Expected value");
                                continue;
                            }
                        };

                        let record = kad::Record {
                            key,
                            value,
                            publisher: None,
                            expires: None,
                        };

                        swarm.behaviour_mut()
                            .kad
                            .put_record(record, kad::Quorum::One)?;
                    }

                    Some("FIND_NODE") => {
                        let peer = match args.next() {
                            Some(peer) => peer.parse::<PeerId>()?,
                            None => {
                                eprintln!("Expected peer id");
                                continue;
                            }
                        };

                        swarm.behaviour_mut().kad.get_closest_peers(peer);
                    }

                    Some("FIND_VALUE") => {
                        let key = match args.next() {
                            Some(key) => kad::RecordKey::new(&key),
                            None => {
                                eprintln!("Expected key");
                                continue;
                            }
                        };

                        swarm.behaviour_mut().kad.get_record(key);
                    }

                    _ => {}
                }
            }

            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => println!("Listening on {address:?}"),
                    SwarmEvent::Behaviour(MyBehaviourEvent::Kad(kad::Event::RoutingUpdated { peer, is_new_peer, addresses, ..})) => {
                        println!("Routing table updated: {peer:?}, is it a new peer? {is_new_peer}, addresses: {addresses:?}");
                    },
                    SwarmEvent::Behaviour(MyBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { result, .. })) => {
                        match result {
                            QueryResult::GetClosestPeers(Ok(ok)) => {
                                println!("FIND_NODE result: {:?}", ok.peers);
                            }

                            QueryResult::GetClosestPeers(Err(e)) => {
                                eprintln!("FIND_NODE error: {}", e);
                            }

                            QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(
                                PeerRecord { record: Record { key, value, .. }, .. }
                            ))) => {
                                println!("Received FIND_VALUE successful response: key: {:?}, value: {}", key, String::from_utf8(value)?);
                            }
                            QueryResult::GetRecord(Err(e)) => {
                                eprintln!("Received FIND_VALUE error: {e}");
                            }

                            QueryResult::PutRecord(Ok(PutRecordOk{key})) => {
                                println!("Received STORE successful response: key: {:?}", key);
                            }
                            QueryResult::PutRecord(Err(e)) => {
                                eprintln!("Received STORE error: {e}");
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
                    },

                    SwarmEvent::Behaviour(MyBehaviourEvent::Ping(event)) => {
                            println!("PING event: {event:?}");
                    },

                    SwarmEvent::Behaviour(MyBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                        for addr in info.listen_addrs {
                            swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                        }

                        let _ = swarm.behaviour_mut().kad.bootstrap();
                    },

                    _ => {}
                }
            }
        }
    }
}
