use blocktion::bot::{
    Context, byzantine::ByzantineBot, double_spend::DoubleSpendBot, eclipse::EclipseBot,
    flood::FloodBot, forge::ForgeBot, honest::HonestBot, nonce_skip::NonceSkipBot,
    overbid::OverbidBot, past_auction::PastAuctionBot, replay::ReplayBot, run_bot, sybil::SybilBot,
};
use clap::Parser;
use ed25519_dalek_blake2b::Keypair;
use rand::rngs::OsRng;
use std::error::Error;

const RATE: f32 = 2.0;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    iterations: u32,

    #[arg(long, default_value_t = 3001)]
    port: u16,

    #[arg(long, default_value = "honest")]
    bot: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let keys = Keypair::generate(&mut OsRng);
    let ctx = Context::connect(args.port, keys).await?;

    match args.bot.as_str() {
        "honest" => {
            let mut bot = HonestBot { ctx };
            run_bot(&mut bot, args.iterations, RATE).await?;
        }
        "replay" => {
            let mut bot = ReplayBot::new(ctx);
            run_bot(&mut bot, args.iterations, RATE).await?;
        }
        "sybil" => {
            let mut bot = SybilBot::new(ctx, 5);
            run_bot(&mut bot, args.iterations, RATE).await?;
        }
        "forge" => {
            let mut bot = ForgeBot::new(ctx);
            run_bot(&mut bot, args.iterations, RATE).await?;
        }
        "double_spend" => {
            let mut bot = DoubleSpendBot::new(ctx);
            run_bot(&mut bot, args.iterations, RATE).await?;
        }
        "nonce_skip" => {
            let mut bot = NonceSkipBot::new(ctx);
            run_bot(&mut bot, args.iterations, RATE).await?;
        }
        "eclipse" => {
            let mut bot = EclipseBot::new(ctx, 20);
            run_bot(&mut bot, args.iterations, RATE).await?;
        }
        "byzantine" => {
            let mut bot = ByzantineBot::new(ctx, 0.5);
            run_bot(&mut bot, args.iterations, RATE).await?;
        }
        "flood" => {
            let mut bot = FloodBot::new(ctx, 50);
            run_bot(&mut bot, args.iterations, RATE).await?;
        }
        "overbid" => {
            let mut bot = OverbidBot::new(ctx);
            run_bot(&mut bot, args.iterations, RATE).await?;
        }
        "past_auction" => {
            let mut bot = PastAuctionBot::new(ctx);
            run_bot(&mut bot, args.iterations, RATE).await?;
        }

        other => {
            return Err(format!("unknown bot: {other}").into());
        }
    }

    Ok(())
}
