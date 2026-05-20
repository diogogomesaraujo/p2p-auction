use std::error::Error;

use crate::{
    blockchain::transaction::{Data, Transaction},
    bot::{Bot, Context, expected_rejection},
};
use async_trait::async_trait;
use ed25519_dalek_blake2b::Keypair;
use hex::ToHex;
use rand::rngs::OsRng;
use tonic::Request;

/// Attacker that signs a bid with the attacker's own key but rewrites
/// from to a different victim's public key before submission.
pub struct ForgeBot {
    pub ctx: Context,
    /// Public key of the impersonated victim.
    victim_pk: String,
}

impl ForgeBot {
    pub fn new(ctx: Context) -> Self {
        // Fabricate a plausible looking victim public key,
        let fake = Keypair::generate(&mut OsRng);
        Self {
            ctx,
            victim_pk: fake.public.encode_hex::<String>(),
        }
    }
}

#[async_trait]
impl Bot for ForgeBot {
    fn name(&self) -> &'static str {
        "forge-bot"
    }

    async fn init(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.ctx.create_account().await?;
        Ok(())
    }

    async fn step(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let data = Data::Bid {
            auction_id: "forge-target".to_string(),
            amount: 9_999,
        };

        let mut tx = Transaction::sign(data, &self.ctx.public_key, self.ctx.nonce, &self.ctx.keys)?;
        tx.from = self.victim_pk.clone();

        let result = self.ctx.client.transaction(Request::new(tx.into())).await;
        expected_rejection(result, "forged sender transaction")?;

        Ok(())
    }
}
