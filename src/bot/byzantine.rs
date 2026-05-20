use std::{error::Error, time::Duration};

use crate::{
    blockchain::transaction::{Data, Transaction},
    bot::{Bot, Context, expected_accept, expected_reject},
    time::now_unix_plus,
};
use async_trait::async_trait;
use rand::{Rng, rngs::OsRng};
use tonic::Request;

/// Attacker that behaves correctly roughly half the time, but
/// here and there flips a byte in the signature before submitting.
/// We don't currently implement stake so handling might not be great.
pub struct ByzantineBot {
    pub ctx: Context,
    pub corruption_rate: f32, // [0..1]
}

impl ByzantineBot {
    pub fn new(ctx: Context, corruption_rate: f32) -> Self {
        Self {
            ctx,
            corruption_rate: corruption_rate.clamp(0.0, 1.0),
        }
    }
}

#[async_trait]
impl Bot for ByzantineBot {
    fn name(&self) -> &'static str {
        "byzantine-bot"
    }

    async fn init(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.ctx.create_account().await?;
        Ok(())
    }

    async fn step(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let data = Data::CreateAuction {
            auction_id: OsRng.r#gen::<u32>().to_string(),
            start_amount: 100,
            stop_time: now_unix_plus(Duration::from_secs(60))?,
        };

        let mut tx = Transaction::sign(data, &self.ctx.public_key, self.ctx.nonce, &self.ctx.keys)?;

        let corrupt = OsRng.r#gen::<f32>() < self.corruption_rate;

        if corrupt {
            let mut s = tx.signature.clone();
            let first = s.remove(0);
            let flipped = match first {
                '0' => '1',
                _ => '0',
            };
            s.insert(0, flipped);
            tx.signature = s;

            let result = self.ctx.client.transaction(Request::new(tx.into())).await;
            expected_reject(result, self.name(), "corrupted-signature transaction")?;
        } else {
            let result = self.ctx.client.transaction(Request::new(tx.into())).await;
            expected_accept(result, self.name(), "valid byzantine transaction")?;
            self.ctx.nonce += 1;
        }

        Ok(())
    }
}
