use rand::{Rng, SeedableRng, rngs::StdRng};
use std::{
    error::Error,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub type Timestamp = u64;

pub fn now_unix() -> Result<Timestamp, Box<dyn Error + Send + Sync>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub fn now_unix_plus(added_time: Duration) -> Result<Timestamp, Box<dyn Error + Send + Sync>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + added_time.as_secs())
}

pub struct Poisson<R: Rng + ?Sized> {
    pub rng: Box<R>,
    pub rate: f32,
}

impl Poisson<StdRng> {
    pub fn new(rate: f32, seed: &[u8; 32]) -> Self {
        Self {
            rng: Box::new(StdRng::from_seed(*seed)),
            rate,
        }
    }
    pub fn time_for_next_event(&mut self) -> f32 {
        -(1.0f32 - self.rng.r#gen::<f32>()).ln() / self.rate
    }
}
