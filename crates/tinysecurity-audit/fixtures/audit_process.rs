//! Real process boundary for stable audit locks and independently recovered tails.
use fs4::FileExt;
use sha2::{Digest, Sha256};
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
        [mode, path, request] if mode == "partial-before-commit" || mode == "commit-before-ack" => {
            crash_phase(mode, std::path::Path::new(path), request)?;
        }
        _ => return Err("invalid fixture invocation".into()),
    }
    Ok(())
}

fn crash_phase(
    mode: &str,
    path: &std::path::Path,
    request: &str,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let batch: tinysecurity_bus::AuditSinkRequest2 = serde_json::from_str(request)?;
    let sink = tinysecurity_audit::JsonlSink::open(path, 10000, 3)?;
    if mode == "partial-before-commit" {
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.with_file_name("audit.lock"))?;
        FileExt::try_lock(&lock)?;
        // Inject an incomplete header as a deterministic short-write crash state.
        // This tests process recovery, not power-loss or a timing-sensitive kill.
        let payload = serde_json::to_vec(&batch)?;
        let mut partial = u64::try_from(payload.len())?.to_be_bytes().to_vec();
        partial.extend_from_slice(&Sha256::digest(&payload)[..12]);
        let mut journal = std::fs::OpenOptions::new()
            .append(true)
            .open(path.with_file_name("audit.journal"))?;
        journal.write_all(&partial)?;
        journal.sync_all()?;
        println!("partial");
        wait_for_crash()?;
    } else {
        let receipt = sink.append(&batch)?;
        batch.verify_receipt(&receipt)?;
        // The parent's external acknowledgement is deliberately withheld even
        // though the actual engine has synced and returned its exact receipt.
        println!("synced");
        wait_for_crash()?;
    }
    Ok(())
}
fn wait_for_crash() -> std::io::Result<()> {
    std::io::stdout().flush()?;
    let mut release = [0_u8; 1];
    std::io::stdin().read_exact(&mut release)
}
