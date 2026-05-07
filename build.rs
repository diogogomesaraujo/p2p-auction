use std::error::Error;

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tonic_prost_build::compile_protos("proto/node.proto")?;
    Ok(())
}
