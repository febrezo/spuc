// TEST_CARGO_AGENT
use anyhow::Result;

pub(crate) fn run() -> Result<()> {
    let crate_version = env!("CARGO_PKG_VERSION");
    println!("{crate_version}");
    Ok(())
}
