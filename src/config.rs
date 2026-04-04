use libp2p::{Multiaddr, PeerId};
use std::error::Error;

pub const CONFIG_DIR: &str = "config";

pub struct Config {
    pub address: Multiaddr,
    pub peer_id: PeerId,
}

impl Config {
    pub fn from(address: Multiaddr, peer_id: PeerId) -> Self {
        Self { address, peer_id }
    }

    pub fn to_file(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        // let mut file = File::create(format!("{CONFIG_DIR}/{}", self.peer_id.to_string()))?;
        // file.write(format!("{} {}\n", self.address, self.peer_id).as_bytes())?;

        Ok(())
    }
}
