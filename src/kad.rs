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
use std::{error::Error, fs::File, io::Write, str::SplitWhitespace, time::Duration};
use tokio::io::{AsyncBufReadExt, BufReader, Stdin};
use tracing::{error, info};

pub const BOOT_NODE_MULTIADDR: &str = "/dnsaddr/bootstrap.libp2p.io";
pub const LISTEN_ON: &str = "/ip4/0.0.0.0/tcp/0";
pub const CONFIG_DIR: &str = "config";

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
    RoutingTable,
}

impl Rpc {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "PING" => Some(Self::Ping),
            "STORE" => Some(Self::Store),
            "FIND_VALUE" => Some(Self::FindValue),
            "FIND_NODE" => Some(Self::FindNode),
            "ROUTING_TABLE" => Some(Self::RoutingTable),
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

            Self::RoutingTable => {
                info!(
                    "Current state of the routing table: {:?}",
                    swarm.connected_peers().collect::<Vec<&PeerId>>(),
                );
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

pub struct Config {
    pub address: Multiaddr,
    pub peer_id: PeerId,
}

impl Config {
    pub fn from(address: Multiaddr, peer_id: PeerId) -> Self {
        Self { address, peer_id }
    }

    pub fn to_file(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut file = File::create(format!("{CONFIG_DIR}/{}", self.peer_id.to_string()))?;
        file.write(format!("{} {}\n", self.address, self.peer_id).as_bytes())?;

        Ok(())
    }
}
