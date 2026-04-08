use libp2p::{
    Swarm,
    kad::{Quorum, Record, RecordKey},
};
use std::{error::Error, num::NonZeroUsize};

use crate::{behaviour::MyBehaviour, state::State};

pub struct Runtime {
    pub swarm: Swarm<MyBehaviour>,
    pub state: State,
}

impl Runtime {
    pub fn new(swarm: Swarm<MyBehaviour>, state: State) -> Self {
        Self { swarm, state }
    }

    pub fn restore_owned_state(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        for rec in &self.state.persistent.persistent_value_records {
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

        for rec in &self.state.persistent.persistent_provider_records {
            self.swarm
                .behaviour_mut()
                .kad
                .start_providing(RecordKey::new(&rec.key))?;
        }

        let _ = self.swarm.behaviour_mut().kad.bootstrap();

        Ok(())
    }
}
