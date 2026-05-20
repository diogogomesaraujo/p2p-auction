use std::error::Error;

use crate::{
    blockchain::transaction::{Data, Transaction},
    bot::{Bot, Context},
};
use async_trait::async_trait;
use tonic::Request;

/// Bot that submits txs with deliberately out of order nonces
/// without first using nonces the nonces in the gaps. A correct node
/// should queue or reject these until the missing nonces appear.
pub struct NonceSkipBot {
    pub ctx: Context,
    next_skip: u32,
}

impl NonceSkipBot {
    pub fn new(ctx: Context) -> Self {
        Self {
            ctx,
            next_skip: 100,
        }
    }
}

#[async_trait]
impl Bot for NonceSkipBot {
    fn name(&self) -> &'static str {
        "nonce-skip-bot"
    }

    async fn init(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.ctx.create_account().await
    }

    async fn step(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let bogus_nonce = self.next_skip;
        self.next_skip += 10;

        let tx = Transaction::sign(
            Data::Bid {
                auction_id: "nonce-skip".to_string(),
                amount: 1,
            },
            &self.ctx.public_key,
            bogus_nonce,
            &self.ctx.keys,
        )?;
        let _ = self.ctx.client.transaction(Request::new(tx.into())).await;
        Ok(())
    }
}
