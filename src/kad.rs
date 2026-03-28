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
use std::{error::Error, str::SplitWhitespace, time::Duration};
use tokio::io::{AsyncBufReadExt, BufReader, Stdin};

pub const BOOT_NODE_MULTIADDR: &str = "/dnsaddr/bootstrap.libp2p.io";
pub const LISTEN_ON: &str = "/ip4/0.0.0.0/tcp/0";

//similar to example from https://docs.rs/libp2p/latest/libp2p/swarm/trait.NetworkBehaviour.html
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

impl MyBehaviourEvent {
    pub fn from_event(
        event: SwarmEvent<Self>,
        swarm: &mut Swarm<MyBehaviour>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => println!("Listening on {address:?}"),
            SwarmEvent::Behaviour(MyBehaviourEvent::Kad(kad::Event::RoutingUpdated {
                peer,
                is_new_peer,
                addresses,
                ..
            })) => {
                println!(
                    "Routing table updated: {peer:?}, is it a new peer? {is_new_peer}, addresses: {addresses:?}"
                );
            }
            SwarmEvent::Behaviour(MyBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                result,
                ..
            })) => {
                match result {
                    QueryResult::GetClosestPeers(Ok(ok)) => {
                        println!("FIND_NODE result: {:?}", ok.peers);
                    }

                    QueryResult::GetClosestPeers(Err(e)) => {
                        eprintln!("FIND_NODE error: {}", e);
                    }

                    QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(PeerRecord {
                        record: Record { key, value, .. },
                        ..
                    }))) => {
                        println!(
                            "Received FIND_VALUE successful response: key: {:?}, value: {}",
                            key,
                            String::from_utf8(value)?
                        );
                    }
                    QueryResult::GetRecord(Err(e)) => {
                        eprintln!("Received FIND_VALUE error: {e}");
                    }

                    QueryResult::PutRecord(Ok(PutRecordOk { key })) => {
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
            }

            SwarmEvent::Behaviour(MyBehaviourEvent::Ping(event)) => {
                println!("PING event: {event:?}");
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

pub enum Rpc {
    Ping,
    Store,
    FindNode,
    FindValue,
}

impl Rpc {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "PING" => Some(Self::Ping),
            "STORE" => Some(Self::Store),
            "FIND_VALUE" => Some(Self::FindValue),
            "FIND_NODE" => Some(Self::FindNode),
            _ => None,
        }
    }

    pub fn run(
        args: &mut SplitWhitespace,
        swarm: &mut Swarm<MyBehaviour>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let arg_parse =
            |args: &mut SplitWhitespace| -> Result<String, Box<dyn Error + Send + Sync>> {
                match args.next() {
                    Some(arg) => Ok(arg.to_string()),
                    None => Err("Insufficient arguments".into()),
                }
            };

        let rpc = match Self::from_str(&arg_parse(args)?) {
            Some(rpc) => rpc,
            None => return Err("Couldn't parse any argument".into()),
        };

        match rpc {
            Self::Ping => {
                let address = arg_parse(args)?.parse::<Multiaddr>()?;
                swarm.dial(address)?;
            }

            Self::Store => {
                let key = kad::RecordKey::new(&arg_parse(args)?);
                let value = arg_parse(args)?.as_bytes().to_vec();

                let record = kad::Record {
                    key,
                    value,
                    publisher: None,
                    expires: None,
                };

                swarm
                    .behaviour_mut()
                    .kad
                    .put_record(record, kad::Quorum::One)?;
            }

            Self::FindNode => {
                let peer = arg_parse(args)?.parse::<PeerId>()?;
                swarm.behaviour_mut().kad.get_closest_peers(peer);
            }

            Self::FindValue => {
                let key = kad::RecordKey::new(&arg_parse(args)?);
                swarm.behaviour_mut().kad.get_record(key);
            }
        }

        Ok(())
    }
}

pub async fn init(
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
            kad_cfg.set_periodic_bootstrap_interval(Some(Duration::from_secs(300)));

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
        let bootstrap_addr = node.parse()?;

        swarm
            .behaviour_mut()
            .kad
            .add_address(&bootstrap_addr, BOOT_NODE_MULTIADDR.parse()?);
        swarm.dial(bootstrap_addr)?;
    }

    swarm.behaviour_mut().kad.set_mode(Some(Mode::Server));
    swarm.listen_on(LISTEN_ON.parse()?)?;
    // swarm
    //     .behaviour_mut()
    //     .kad
    //     .get_closest_peers(swarm.local_peer_id());

    Ok(swarm)
}

pub async fn run(
    swarm: &mut Swarm<MyBehaviour>,
    buffer_reader: BufReader<Stdin>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut lines = buffer_reader.lines();
    loop {
        tokio::select! {
            Ok(Some(line)) = lines.next_line() => {
                let mut args = line.split_whitespace();
                Rpc::run(&mut args, swarm)?;
            }

            event = swarm.select_next_some() => {
                MyBehaviourEvent::from_event(event, swarm)?;
            }
        }
    }
}
