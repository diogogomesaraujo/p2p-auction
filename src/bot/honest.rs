use std::{error::Error, time::Duration};

use crate::{
    blockchain::transaction::Data,
    bot::{Bot, Context},
    time::now_unix_plus,
};
use async_trait::async_trait;
use rand::{RngCore, rngs::OsRng};

pub struct HonestBot {
    pub ctx: Context,
}

#[async_trait]
impl Bot for HonestBot {
    fn name(&self) -> &'static str {
        "honest-bot"
    }

    async fn init(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.ctx.create_account().await
    }

    async fn step(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let auction_id = OsRng.next_u32().to_string();

        self.ctx
            .send(Data::CreateAuction {
                auction_id: auction_id.clone(),
                start_amount: OsRng.next_u64(),
                stop_time: now_unix_plus(Duration::from_secs(60))?,
            })
            .await?;

        self.ctx
            .send(Data::Bid {
                auction_id,
                amount: 10_000,
            })
            .await?;

        Ok(())
    }
}
