use crate::poisson::Poisson;
use rand::rngs::StdRng;

#[async_trait::async_trait]
pub trait ArtificialBehaviour {
    const RATE: f32;

    async fn run(&self);
}
