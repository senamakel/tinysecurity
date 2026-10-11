//! Actual loaded sandbox planning contract; this does not launch isolated processes.
use std::{path::PathBuf, time::Duration};
use tinybus::{Connection, broker::Broker, module::ModuleHost, transport::memory::MemoryBus};
use tinysecurity_bus::{ModuleConfig, PolicyInfo, names};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let library = PathBuf::from(std::env::args().nth(1).ok_or("native library required")?).canonicalize()?;
    let name = library.file_name().and_then(|n| n.to_str()).ok_or("library encoding")?;
    std::fs::write(library.parent().ok_or("library parent")?.join("modules.toml"),
        format!("\"{name}\" = \"{}\"\n", tinybus::module::sha256_file(&library)?))?;
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let task = broker.spawn(bus.clone());
    let host = ModuleHost::new(broker);
    let client = Connection::connect(bus.connect().await?).await?;
    let mut config = serde_json::to_value(ModuleConfig {
        trusted_host: client.unique_name().map(|n| n.as_str().to_owned()),
        ..Default::default()
    })?;
    config["sandbox"] = serde_json::json!({"scopes": []});
    host.load_file_with_config(&library, config)?;
    let info: PolicyInfo = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(proxy) = client.proxy(names::INTERFACE, names::OBJECT_PATH, names::INTERFACE) {
                if let Ok(info) = proxy.call::<PolicyInfo>(names::methods::POLICY_INFO, ()).await {
                    break info;
                }
            }
            tokio::task::yield_now().await;
        }
    }).await?;
    assert!(info.capabilities.iter().any(|method| method == "Plan2"));
    task.abort();
    println!("native sandbox: accepted trusted initialization and actual planning dispatch advertised");
    Ok(())
}
