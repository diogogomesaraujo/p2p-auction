use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    tonic_prost_build::compile_protos("proto/node.proto")?;
    Ok(())
}
