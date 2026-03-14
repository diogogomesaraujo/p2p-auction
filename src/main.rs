use libp2p::{
    Multiaddr, StreamProtocol, SwarmBuilder,
    futures::StreamExt,
    identity,
    kad::{self, Record, RecordKey},
    noise, tcp, yamux,
};
use std::{error::Error, time::Duration};

const IPFS_PROTO_NAME: StreamProtocol = StreamProtocol::new("/ipfs/kad/1.0.0");

const BOOT_NODES: [&str; 4] = [
    "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let _ = tracing_subscriber::fmt().try_init()?;

    let self_key = identity::Keypair::generate_ed25519();

    let mut swarm = SwarmBuilder::with_existing_identity(self_key.clone())
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_dns()?
        .with_behaviour(|key| {
            let mut cfg = kad::Config::new(IPFS_PROTO_NAME);
            cfg.set_query_timeout(Duration::from_mins(1));
            let store = kad::store::MemoryStore::new(key.public().to_peer_id());
            kad::Behaviour::with_config(key.public().to_peer_id(), store, cfg)
        })?
        .build();

    for boot_node in &BOOT_NODES {
        swarm
            .behaviour_mut()
            .add_address(&boot_node.parse()?, "/dnsaddr/bootstrap.libp2p.io".parse()?);
    }

    swarm
        .behaviour_mut()
        .get_closest_peers(self_key.public().to_peer_id());
    swarm.dial(OTHER_PEER.parse::<Multiaddr>()?)?;

    loop {
        let event = swarm.select_next_some().await;

        match event {
            libp2p::swarm::SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::PutRecord(Ok(ok)),
                ..
            }) => {
                println!("Correctly put record near:\n{:?}", ok.key);
            }
            libp2p::swarm::SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::PutRecord(Err(e)),
                ..
            }) => {
                println!("Failed to put record near:\n{:?}", e);
            }
            libp2p::swarm::SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::GetClosestPeers(Ok(ok)),
                ..
            }) => {
                println!("Closest Peers:\n{:?}", ok.peers);
                swarm.behaviour_mut().put_record(
                    Record {
                        key: RecordKey::new(&"key".as_bytes().to_vec()),
                        value: "value".as_bytes().to_vec(),
                        publisher: Some(self_key.public().to_peer_id()),
                        expires: None,
                    },
                    kad::Quorum::One,
                )?;
            }
            _ => {}
        }
    }
}
