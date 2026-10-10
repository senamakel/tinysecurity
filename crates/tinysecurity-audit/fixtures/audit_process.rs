//! Real process boundary for stable audit locks and independently recovered tails.
use fs4::FileExt;
use std::io::{Read, Write};
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode, path] if mode == "hold" => {
            let lock = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)?;
            FileExt::try_lock(&lock)?;
            println!("locked");
            std::io::stdout().flush()?;
            let mut release = [0_u8; 1];
            std::io::stdin().read_exact(&mut release)?;
        }
        [mode, path, request] if mode == "append" => {
            let batch: tinysecurity_bus::AuditSinkRequest2 = serde_json::from_str(request)?;
            let sink = tinysecurity_audit::JsonlSink::open(std::path::Path::new(path), 10000, 3)?;
            let receipt = sink.append(&batch)?;
            batch.verify_receipt(&receipt)?;
            println!("committed");
        }
        _ => return Err("invalid fixture invocation".into()),
    }
    Ok(())
}
