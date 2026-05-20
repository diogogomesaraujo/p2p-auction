use std::error::Error;

use crate::{
    blockchain::transaction::{Data, Transaction},
    bot::{Bot, Context, expected_accept, expected_reject},
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
        self.ctx.create_account().await?;
        Ok(())
    }

    async fn step(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let n = self.ctx.nonce;

        let a = Transaction::sign(
            Data::CreateAuction {
                auction_id: "ds-a".to_string(),
                start_amount: 1_000,
                stop_time: u64::MAX,
            },
            &self.ctx.public_key,
            n,
            &self.ctx.keys,
        )?;

        let b = Transaction::sign(
            Data::CreateAuction {
                auction_id: "ds-b".to_string(),
                start_amount: 1_000,
                stop_time: u64::MAX,
            },
            &self.ctx.public_key,
            n,
            &self.ctx.keys,
        )?;

        let first = self.ctx.client.transaction(Request::new(a.into())).await;
        expected_accept(first, self.name(), "first double-spend transaction")?;

        let second = self.ctx.client.transaction(Request::new(b.into())).await;
        expected_reject(second, self.name(), "double-spend transaction")?;

        self.ctx.nonce += 1;

        Ok(())
    }
}
