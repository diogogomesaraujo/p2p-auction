use std::error::Error;

use crate::{
    blockchain::transaction::Data,
    bot::{Bot, Context},
};
use async_trait::async_trait;

/// Attakcer places bids that exceed the account's
/// funded balance (START_FUNDS = 1000). Unless we implement
/// propper balance management attacker will succeed.
pub struct OverbidBot {
    pub ctx: Context,
}

impl OverbidBot {
    pub fn new(ctx: Context) -> Self {
        Self { ctx }
    }
}

#[async_trait]
impl Bot for OverbidBot {
    fn name(&self) -> &'static str {
        "overbid-bot"
    }

    async fn init(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.ctx.create_account().await
    }

    async fn step(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.ctx
            .send(Data::Bid {
                auction_id: "overbid-target".to_string(),
                amount: 1_000_000,
            })
            .await
    }
}
