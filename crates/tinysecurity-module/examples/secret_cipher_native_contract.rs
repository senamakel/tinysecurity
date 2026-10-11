//! Actual loaded cdylib master/cipher proof with fixed authenticated callbacks.
#[path = "secret_cipher_native_contract/fixture.rs"]
mod fixture;
#[path = "approval_native_contract/namespace.rs"]
mod namespace;
use std::path::PathBuf;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let library = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("native cipher requires library")?,
    )
    .canonicalize()?;
    if let Some(mode) = std::env::args().nth(2) {
        return fixture::run(&library, mode.parse()?).await;
    }
    let original_hash = tinybus::module::sha256_file(&library)?;
    let executable = std::env::current_exe()?;
    for mode in 0..=17 {
        let output = std::process::Command::new(&executable)
            .arg(&library)
            .arg(mode.to_string())
            .output()?;
        if !output.status.success() {
            // Fixture diagnostics contain only static modes/status, never payloads.
            eprintln!("native cipher mode={mode} failed");
            std::io::Write::write_all(&mut std::io::stderr(), &output.stderr)?;
            return Err("native cipher boundary failed".into());
        }
        println!("native master/cipher mode={mode}: passed");
    }
    assert_eq!(original_hash, tinybus::module::sha256_file(&library)?);
    println!("native master/cipher: authenticated confidential loaded module boundaries passed");
    Ok(())
}
