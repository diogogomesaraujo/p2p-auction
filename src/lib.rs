use libp2p::{
    StreamProtocol, Swarm, SwarmBuilder,
    futures::StreamExt,
    identity::Keypair,
    kad::{
        self, AddProviderOk, Behaviour, Event, GetProvidersOk, GetRecordOk, Mode, PeerRecord,
        PutRecordOk, QueryResult, Record, store::MemoryStore,
    },
    noise,
    swarm::SwarmEvent,
    tcp, yamux,
};
use std::{error::Error, time::Duration};
use tokio::io::{AsyncBufReadExt, BufReader, Stdin};

pub async fn kad_instance_init(
    ipfs_proto_name: StreamProtocol,
    key: Keypair,
) -> Result<Swarm<Behaviour<MemoryStore>>, Box<dyn Error>> {
    let mut swarm = SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_dns()?
        .with_behaviour(|key| {
            let mut cfg = kad::Config::new(ipfs_proto_name);
            cfg.set_query_timeout(Duration::from_mins(1));
            let store = kad::store::MemoryStore::new(key.public().to_peer_id());
            kad::Behaviour::with_config(key.public().to_peer_id(), store, cfg)
        })?
        .build();

    swarm.behaviour_mut().set_mode(Some(Mode::Server));
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    Ok(swarm)
}

pub async fn kad_run(
    swarm: &mut Swarm<Behaviour<MemoryStore>>,
    buffer_reader: BufReader<Stdin>,
) -> Result<(), Box<dyn Error>> {
    let mut lines = buffer_reader.lines();
    loop {
        tokio::select! {
            Ok(Some(line)) = lines.next_line() => {
                let mut args = line.split_whitespace();
                match args.next() {
                    Some("GET_VALUE") => {}
                    Some("PUT_VALUE") => {}
                    Some("GET_PROVIDER") => {}
                    Some("PUT_PROVIDER") => {}
                    _ => {}
                }
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(Event::OutboundQueryProgressed { result, .. }) => {
                        match result {
                            QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(
                                PeerRecord { record: Record { key, value, .. }, .. }
                            ))) => {
                                println!("Received GET_VALUE successful response: key: {:?}, value: {:?}", key, value);
                            }
                            QueryResult::GetRecord(Err(e)) => {
                                eprintln!("Received GET_VALUE error: {e}");
                            }

                            QueryResult::PutRecord(Ok(PutRecordOk{key})) => {
                                println!("Received PUT_VALUE successful response: key: {:?}", key);
                            }
                            QueryResult::PutRecord(Err(e)) => {
                                eprintln!("Received PUT_VALUE error: {e}");
                            }

                            QueryResult::GetProviders(Ok(GetProvidersOk::FoundProviders { key, providers, .. })) => {
                                providers.iter().for_each(|provider| println!("Received GET_PROVIDER successful message: provider: {:?}, key: {:?}", provider, key));
                            }
                            QueryResult::GetProviders(Err(e)) => {
                                eprintln!("Received GET_PROVIDER error: {e}");
                            }

                            QueryResult::StartProviding(Ok(AddProviderOk{key})) => {
                                println!("Received PUT_PROVIDER successful message: key: {:?}", key);
                            }
                            QueryResult::StartProviding(Err(e)) => {
                                eprintln!("Received GET_PROVIDER error: {e}");
                            }

                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}
