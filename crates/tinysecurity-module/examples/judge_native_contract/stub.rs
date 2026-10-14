//! Literal loopback fixture with bounded HTTP reads, response controls and shutdown.
use std::sync::{Arc, Mutex};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
pub(super) struct Stub {
    pub(super) endpoint: String,
    pub(super) requests: Arc<Mutex<Vec<serde_json::Value>>>,
    pub(super) response: Arc<Mutex<(u16, String)>>,
    #[allow(dead_code)] // only the standalone native example delays replies
    pub(super) delay_ms: Arc<std::sync::atomic::AtomicU64>,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}
pub(super) fn response(scores: [f64; 3]) -> String {
    serde_json::json!({"model":"jev-latest","answers":{"intent":{"type":"noul","noul":scores[0]},"reversible":{"type":"noul","noul":scores[1]},"exfiltrate":{"type":"noul","noul":scores[2]}},"usage":{"input_tokens":1,"output_tokens":1}}).to_string()
}
impl Stub {
    pub(super) async fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let endpoint = format!("http://{}/jev", listener.local_addr()?);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let response = Arc::new(Mutex::new((200, response([1.0, 1.0, 0.0]))));
        let (stop, mut stopped) = oneshot::channel();
        let captured = Arc::clone(&requests);
        let replies = Arc::clone(&response);
        let delay_ms = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let delays = Arc::clone(&delay_ms);
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    accepted = listener.accept() => {
                        let Ok((stream,_)) = accepted else { break; };
                        let _ = tokio::time::timeout(std::time::Duration::from_secs(2),exchange(stream,&captured,&replies,&delays)).await;
                    }
                }
            }
        });
        Ok(Self {
            endpoint,
            requests,
            response,
            delay_ms,
            stop,
            task,
        })
    }
    pub(super) async fn shutdown(self) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self.stop.send(());
        tokio::time::timeout(std::time::Duration::from_secs(3), self.task).await??;
        Ok(())
    }
}
async fn exchange(
    mut stream: TcpStream,
    requests: &Mutex<Vec<serde_json::Value>>,
    response: &Mutex<(u16, String)>,
    delay_ms: &std::sync::atomic::AtomicU64,
) -> std::io::Result<()> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 || bytes.len() + n > 65_536 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        bytes.extend_from_slice(&chunk[..n]);
        if let Some(end) = bytes.windows(4).position(|s| s == b"\r\n\r\n") {
            break end + 4;
        }
    };
    let headers = String::from_utf8_lossy(&bytes[..header_end]).to_ascii_lowercase();
    if !headers.contains("authorization: bearer fake-judge-key") {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    let len = headers
        .lines()
        .find_map(|s| s.strip_prefix("content-length: "))
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|n| *n <= 60_000)
        .ok_or(std::io::ErrorKind::InvalidData)?;
    while bytes.len() < header_end + len {
        let n = stream.read(&mut chunk).await?;
        if n == 0 || bytes.len() + n > 65_536 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        bytes.extend_from_slice(&chunk[..n]);
    }
    let value = serde_json::from_slice(&bytes[header_end..header_end + len])
        .map_err(|_| std::io::ErrorKind::InvalidData)?;
    {
        let mut requests = requests.lock().map_err(|_| std::io::ErrorKind::Other)?;
        if requests.len() >= 100 {
            return Err(std::io::ErrorKind::OutOfMemory.into());
        }
        requests.push(value);
    }
    let delay = delay_ms.load(std::sync::atomic::Ordering::SeqCst);
    if delay > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
    }
    let (status, body) = response
        .lock()
        .map_err(|_| std::io::ErrorKind::Other)?
        .clone();
    let reply = format!(
        "HTTP/1.1 {status} fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(reply.as_bytes()).await?;
    stream.shutdown().await
}
