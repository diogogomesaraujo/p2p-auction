use crate::{behaviour::DhtBehaviour, state::State};
use libp2p::{
    Swarm,
    kad::{Quorum, Record, RecordKey},
};
use std::{error::Error, num::NonZeroUsize};

pub struct Runtime {
    pub swarm: Swarm<DhtBehaviour>,
    pub state: State,
}

impl Runtime {
    pub fn new(swarm: Swarm<DhtBehaviour>, state: State) -> Self {
        Self { swarm, state }
    }

    pub fn load_from_local(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        for rec in &self.state.local.value_records {
            let record = Record {
                key: RecordKey::new(&rec.key),
                value: rec.value.clone(),
                publisher: None,
                expires: None,
            };

            self.swarm.behaviour_mut().kad.put_record(
                record,
                Quorum::N(
                    NonZeroUsize::new(rec.quorum)
                        .ok_or("Stored quorum must be greater than zero")?,
                ),
            )?;
        }

        for rec in &self.state.local.provider_records {
            self.swarm
                .behaviour_mut()
                .kad
                .start_providing(RecordKey::new(&rec.key))?;
        }

        let _ = self.swarm.behaviour_mut().kad.bootstrap();

        Ok(())
    }
}
