use blocktion::bot::{Context, honest::HonestBot, run_bot};
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

        other => {
            return Err(format!("unknown bot: {other}").into());
        }
    }

    Ok(())
}
