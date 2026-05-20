use std::error::Error;

use crate::{
    blockchain::transaction::Data,
    bot::{Bot, Context},
};
use async_trait::async_trait;

/// Attacker that submits the maximum number of valid bids per step
/// Gossip can't ban since they are legit transactions. Tests whether honest
/// txs still get included in blocks under sustained pressure from a seemingly
/// non malicious node.
pub struct FloodBot {
    pub ctx: Context,
    pub burst_ammount: u32,
}

impl FloodBot {
    pub fn new(ctx: Context, bursts_per_step: u32) -> Self {
        Self {
            ctx,
            burst_ammount: bursts_per_step,
        }
    }
}

#[async_trait]
impl Bot for FloodBot {
    fn name(&self) -> &'static str {
        "flood-bot"
    }

    async fn init(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.ctx.create_account().await
    }

    async fn step(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        for _ in 0..self.burst_ammount {
            let _ = self
                .ctx
                .send(Data::Bid {
                    auction_id: "flood-target".to_string(),
                    amount: 1,
                })
                .await;
        }
        Ok(())
    }
}
