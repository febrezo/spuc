use anyhow::Result;

use crate::commands::sigma_runtime::sigma_runtime_info;
use crate::commands::sigma_targets::dynamic_sigma_targets;

pub(crate) fn status() -> Result<()> {
    let info = sigma_runtime_info();
    println!("sigma_binary={}", info.binary);
    println!("installed={}", info.installed);
    println!("operational={}", info.operational);
    if let Some(warning) = &info.warning {
        println!("warning={warning}");
    }
    if info.compatible_backends.is_empty() {
        println!("compatible_backends=none");
    } else {
        println!(
            "compatible_backends={}",
            info.compatible_backends.join(", ")
        );
    }
    Ok(())
}

pub(crate) fn list_targets() -> Result<()> {
    let targets = dynamic_sigma_targets();
    if targets.is_empty() {
        println!("No dynamic sigma targets detected.");
        return Ok(());
    }
    for target in targets {
        println!("{target}");
    }
    Ok(())
}
