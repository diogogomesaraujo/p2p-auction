use std::error::Error;

use crate::{
    blockchain::transaction::Data,
    bot::{Bot, Context},
};
use async_trait::async_trait;
use ed25519_dalek_blake2b::Keypair;
use hex::ToHex;
use rand::rngs::OsRng;

/// Attacker that at each step, generates a brand-new keypair, opens a fresh
/// account, and immediately bids from it. Over many iterations this is
/// equivalent to one attacker pretending to be hundreds of independent users.
pub struct SybilBot {
    pub ctx: Context,
    pub identities_per_step: u32,
    auction_id: String,
}

impl SybilBot {
    pub fn new(ctx: Context, identities_per_step: u32) -> Self {
        Self {
            ctx,
            identities_per_step,
            auction_id: "sybil-target".to_string(),
        }
    }
}

#[async_trait]
impl Bot for SybilBot {
    fn name(&self) -> &'static str {
        "sybil-attack-bot"
    }

    async fn init(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        Ok(())
    }

    async fn step(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        for _ in 0..self.identities_per_step {
            let keys = Keypair::generate(&mut OsRng);
            let public_key: String = keys.public.encode_hex();

            let original_pk = std::mem::replace(&mut self.ctx.public_key, public_key);
            let original_keys = std::mem::replace(&mut self.ctx.keys, keys);
            let original_nonce = std::mem::replace(&mut self.ctx.nonce, 0);

            let _ = self.ctx.create_account().await;
            let _ = self
                .ctx
                .send(Data::Bid {
                    auction_id: self.auction_id.clone(),
                    amount: 100,
                })
                .await;

            self.ctx.public_key = original_pk;
            self.ctx.keys = original_keys;
            self.ctx.nonce = original_nonce;
        }
        Ok(())
    }
}
