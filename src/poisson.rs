use rand::{Rng, SeedableRng, rngs::StdRng};

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
