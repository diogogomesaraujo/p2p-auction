use std::error::Error;

use crate::{
    blockchain::transaction::{Data, Transaction},
    bot::{Bot, Context},
};
use async_trait::async_trait;
use tonic::Request;

/// Attacher that submits two distinct transactions with same from
/// and nonce in rapid succession.
pub struct DoubleSpendBot {
    pub ctx: Context,
}

impl DoubleSpendBot {
    pub fn new(ctx: Context) -> Self {
        Self { ctx }
    }
}

#[async_trait]
impl Bot for DoubleSpendBot {
    fn name(&self) -> &'static str {
        "double-spend-bot"
    }

    async fn init(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.ctx.create_account().await
    }

    async fn step(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let n = self.ctx.nonce;

        let a = Transaction::sign(
            Data::Bid {
                auction_id: "ds-a".to_string(),
                amount: 1_000,
            },
            &self.ctx.public_key,
            n,
            &self.ctx.keys,
        )?;
        let b = Transaction::sign(
            Data::Bid {
                auction_id: "ds-b".to_string(),
                amount: 1_000,
            },
            &self.ctx.public_key,
            n,
            &self.ctx.keys,
        )?;

        let _ = self.ctx.client.transaction(Request::new(a.into())).await;
        let _ = self.ctx.client.transaction(Request::new(b.into())).await;

        self.ctx.nonce += 1;
        Ok(())
    }
}
