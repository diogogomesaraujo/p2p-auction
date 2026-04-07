use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_vec_pretty};
use std::{
    collections::HashMap,
    fs::{create_dir_all, read, write},
    io::{self, Error, ErrorKind, Result},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub const STATE_FILE: &str = "config/node_state.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentValueRecord {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub quorum: usize,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentProviderRecord {
    pub key: Vec<u8>,
    pub announced_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersistentState {
    pub owned_value_records: Vec<PersistentValueRecord>,
    pub owned_provider_records: Vec<PersistentProviderRecord>,
}

impl PersistentState {
    pub fn load() -> Result<Self> {
        if !Path::new(STATE_FILE).exists() {
            return Ok(Self::default());
        }

        let bytes = read(STATE_FILE)?;
        from_slice(&bytes).map_err(|e| Error::new(ErrorKind::InvalidData, e))
    }

    pub fn save(&self) -> Result<()> {
        if let Some(parent) = Path::new(STATE_FILE).parent() {
            create_dir_all(parent)?;
        }

        let bytes = to_vec_pretty(self).map_err(|e| Error::new(io::ErrorKind::InvalidData, e))?;
        write(STATE_FILE, bytes)
    }

    pub fn remember_value_record(&mut self, key: Vec<u8>, value: Vec<u8>, quorum: usize) {
        self.owned_value_records.retain(|r| r.key != key);
        self.owned_value_records.push(PersistentValueRecord {
            key,
            value,
            quorum,
            created_at_unix: now_unix(),
        });
    }

    pub fn remember_provider_record(&mut self, key: Vec<u8>) {
        self.owned_provider_records.retain(|r| r.key != key);
        self.owned_provider_records.push(PersistentProviderRecord {
            key,
            announced_at_unix: now_unix(),
        });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerRuntimeState {
    pub first_seen_unix: Option<u64>,
    pub last_seen_unix: Option<u64>,
    pub last_successful_ping_unix: Option<u64>,
    pub last_successful_kad_response_unix: Option<u64>,
    pub successful_pings: u32,
    pub failed_pings: u32,
    pub consecutive_failures: u32,
    pub session_count: u32,
    pub is_routable_candidate: bool,
    pub is_pending_routable: bool,
    pub is_in_routing_table: bool,
}

#[derive(Debug, Default)]
pub struct State {
    pub persistent: PersistentState,
    pub peers: HashMap<PeerId, PeerRuntimeState>,
}

impl State {
    pub fn load() -> Result<Self> {
        Ok(Self {
            persistent: PersistentState::load()?,
            peers: HashMap::new(),
        })
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before UNIX_EPOCH")
        .as_secs()
}
