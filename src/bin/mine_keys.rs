use blocktion::key::{PEER_ID_DIFFICULTY, get_key};
use libp2p::PeerId;
use std::error::Error;
use std::fs::remove_file;
use tracing_subscriber::fmt;

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    fmt().try_init().ok();

    let paths = [
        "config/boot1",
        "config/node1",
        "config/node2",
        "config/node3",
        "config/node4",
    ];

    for path in paths {
        // delete any stale key first
        let _ = remove_file(path);

        println!("Mining {path} at difficulty {PEER_ID_DIFFICULTY}...");
        let key = get_key(path)?;
        let peer_id = PeerId::from_public_key(&key.public());
        println!("  {path} -> {peer_id}");
    }

    Ok(())
}
