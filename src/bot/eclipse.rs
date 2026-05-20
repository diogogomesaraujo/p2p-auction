use std::error::Error;

use crate::{
    blockchain::transaction::Data,
    bot::{Bot, Context},
};
use async_trait::async_trait;
use ed25519_dalek_blake2b::Keypair;
use hex::ToHex;
use rand::rngs::OsRng;

/// Attacker that saturates the target node's gRPC and gossip by creating a high
/// volume of fresh accounts from many keypairs over a single connection.
/// Combined with --port pointing at one victim node, this approximates monopolising
/// its inbound transaction channel — the gRPC equivalent of eclipsing.
///
/// TODO:
/// True transport-layer eclipse is outside what a single-port bot can do;
/// for that, spawn many nodes and dial only the victim.
pub struct EclipseBot {
    pub ctx: Context,
    pub burst: u32,
}

impl EclipseBot {
    pub fn new(ctx: Context, burst: u32) -> Self {
        Self { ctx, burst }
    }
}

#[async_trait]
impl Bot for EclipseBot {
    fn name(&self) -> &'static str {
        "eclipse-flood-bot"
    }

    async fn init(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        Ok(())
    }

    async fn step(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut accepted = 0;

        for _ in 0..self.burst {
            let keys = Keypair::generate(&mut OsRng);
            let public_key: String = keys.public.encode_hex();

            let original_pk = std::mem::replace(&mut self.ctx.public_key, public_key);
            let original_keys = std::mem::replace(&mut self.ctx.keys, keys);
            let original_nonce = std::mem::replace(&mut self.ctx.nonce, 0);

            let result = self
                .ctx
                .send(Data::CreateUserAccount {
                    public_key: self.ctx.public_key.clone(),
                })
                .await;

            if result.is_ok() {
                accepted += 1;
            }

            self.ctx.public_key = original_pk;
            self.ctx.keys = original_keys;
            self.ctx.nonce = original_nonce;
        }

        if accepted == 0 {
            return Err(
                "eclipse/account-flood bot generated no accepted account transactions.".into(),
            );
        }

        Ok(())
    }
}
