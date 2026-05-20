use std::{
    error::Error,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    blockchain::transaction::Data,
    bot::{Bot, Context, expected_reject},
};
use async_trait::async_trait;
use rand::{Rng, rngs::OsRng};

/// Attacker that creates auctions whose stop_time is in
/// the past, and bids on auctions that should already be closed.
pub struct PastAuctionBot {
    pub ctx: Context,
}

impl PastAuctionBot {
    pub fn new(ctx: Context) -> Self {
        Self { ctx }
    }
}

#[async_trait]
impl Bot for PastAuctionBot {
    fn name(&self) -> &'static str {
        "past-auction-bot"
    }

    async fn init(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.ctx.create_account().await?;
        Ok(())
    }

    async fn step(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let auction_id = OsRng.r#gen::<u32>().to_string();

        let past_stop = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs().saturating_sub(3600),
            Err(_) => 0,
        };

        let create_result = self
            .ctx
            .send(Data::CreateAuction {
                auction_id: auction_id.clone(),
                start_amount: 10,
                stop_time: past_stop,
            })
            .await;

        expected_reject(create_result, self.name(), "past auction creation")?;

        let bid_result = self
            .ctx
            .send(Data::Bid {
                auction_id,
                amount: 50,
            })
            .await;

        expected_reject(bid_result, self.name(), "bid on past auction")?;

        Ok(())
    }
}
