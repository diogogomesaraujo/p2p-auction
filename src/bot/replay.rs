use std::error::Error;

use crate::{
    blockchain::transaction::{Data, Transaction},
    bot::{Bot, Context, expected_accept, expected_reject},
};
use async_trait::async_trait;
use tonic::Request;

/// Attacker that signs one bid transaction up front, then resubmits the
/// exact same signed bytes on every step. A correct node must reject every
/// resubmission after the first confirmation.
pub struct ReplayBot {
    pub ctx: Context,
    cached: Option<Transaction>, // The single signed transaction we will replay forever.
    auction_id: String,          // Auction id used by the replayed bid.
    submitted_once: bool,
}

impl ReplayBot {
    pub fn new(ctx: Context) -> Self {
        Self {
            ctx,
            cached: None,
            auction_id: "replay-target".to_string(),
            submitted_once: false,
        }
    }
}

#[async_trait]
impl Bot for ReplayBot {
    fn name(&self) -> &'static str {
        "replay-attack-bot"
    }

    async fn init(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.ctx.create_account().await?;

        let data = Data::Bid {
            auction_id: self.auction_id.clone(),
            amount: 500,
        };

        let tx = Transaction::sign(data, &self.ctx.public_key, self.ctx.nonce, &self.ctx.keys)?;
        self.cached = Some(tx);

        Ok(())
    }

    async fn step(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let tx = match &self.cached {
            Some(t) => t.clone(),
            None => return Err("ReplayBot not initialised".into()),
        };

        let result = self.ctx.client.transaction(Request::new(tx.into())).await;

        if self.submitted_once {
            expected_reject(result, self.name(), "replayed transaction")?;
        } else {
            expected_accept(result, self.name(), "original transaction")?;
            self.submitted_once = true;
            self.ctx.nonce += 1;
        }

        Ok(())
    }
}
