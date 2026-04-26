use crate::{
    blockchain::{Blockchain, transaction::Mempool},
    time::{Timestamp, now_unix},
};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_vec_pretty};
use std::{
    collections::HashMap,
    error::Error,
    fs::{create_dir_all, read, write},
    path::Path,
};

pub const STATE_FILE: &str = "config/local.json";

#[derive(Debug)]
pub struct State {
    pub local: Local,
    pub peers: HashMap<PeerId, PeerInfo>,
    pub blockchain: Blockchain,
    pub mempool: Mempool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerInfo {
    pub first_seen: Option<u64>,
    pub last_seen: Option<u64>,
    pub last_successful_ping: Option<u64>,
    pub last_successful_kad_response: Option<u64>,
    pub successful_pings: u32,
    pub failed_pings: u32,
    pub consecutive_failures: u32,
    pub session_count: u32,
    pub is_routable_candidate: bool,
    pub is_pending_routable: bool,
    pub is_in_routing_table: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Local {
    pub value_records: Vec<ValueRecord>,
    pub provider_records: Vec<ProviderRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueRecord {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub quorum: usize,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRecord {
    pub key: Vec<u8>,
    pub announced_at: Timestamp,
}

impl State {
    pub fn init() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(Self {
            local: Local::load()?,
            peers: HashMap::new(),
            mempool: Mempool::new(),
            blockchain: Blockchain::new(u32::MAX)?, // ??? replace by an initial probe function
        })
    }
}

impl Local {
    pub fn load() -> Result<Self, Box<dyn Error + Send + Sync>> {
        if !Path::new(STATE_FILE).exists() {
            return Ok(Self::default());
        }

        let bytes = read(STATE_FILE)?;
        Ok(from_slice(&bytes)?)
    }

    pub fn save(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Some(parent) = Path::new(STATE_FILE).parent() {
            create_dir_all(parent)?;
        }

        let bytes = to_vec_pretty(self)?;
        write(STATE_FILE, bytes)?;
        Ok(())
    }

    pub fn remember_value_record(
        &mut self,
        key: Vec<u8>,
        value: Vec<u8>,
        quorum: usize,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.value_records.retain(|r| r.key != key);
        self.value_records.push(ValueRecord {
            key,
            value,
            quorum,
            created_at: now_unix()?,
        });
        Ok(())
    }

    pub fn remember_provider_record(
        &mut self,
        key: Vec<u8>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.provider_records.retain(|r| r.key != key);
        self.provider_records.push(ProviderRecord {
            key,
            announced_at: now_unix()?,
        });
        Ok(())
    }
}
