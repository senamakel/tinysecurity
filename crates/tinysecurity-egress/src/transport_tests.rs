use super::*;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tinysecurity_bus::{EgressPolicyId, SubjectScope, TransportAuthorization};

// This test-only executor demonstrates consumption of the pinning contract.
// Generic production HTTP belongs to TinyTools. Loopback fixture sockets are
// never authorized through the production agent floor.
fn connect_exact(addresses: &[SocketAddr]) -> std::io::Result<TcpStream> {
    for address in addresses {
        if let Ok(stream) = TcpStream::connect_timeout(address, Duration::from_secs(2)) {
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            stream.set_write_timeout(Some(Duration::from_secs(2)))?;
            return Ok(stream);
        }
    }
    Err(std::io::Error::other("approved sockets unavailable"))
}
fn fixture_authorization(
    hostname: &str,
    address: SocketAddr,
    scheme: &str,
) -> TransportAuthorization {
    TransportAuthorization {
        authorization_id: "test-owned".into(),
        fingerprint: "test-owned-fixture".into(),
        url: format!("{scheme}://{hostname}:{}/fixture", address.port()),
        hostname: hostname.into(),
        port: address.port(),
        addresses: vec![address],
        subject: SubjectScope {
            user: "test".into(),
            workspace: "test".into(),
            agent: "test".into(),
        },
        policy_id: EgressPolicyId("test-owned-only".into()),
        generation: 1,
        expires_at_ms: u64::MAX,
    }
}
fn authorized_connection(authorization: &TransportAuthorization) -> std::io::Result<TcpStream> {
    let endpoint = url::Url::parse(&authorization.url).map_err(std::io::Error::other)?;
    if endpoint.host_str() != Some(authorization.hostname.as_str())
        || endpoint.port_or_known_default() != Some(authorization.port)
        || authorization
            .addresses
            .iter()
            .any(|address| address.port() != authorization.port)
    {
        return Err(std::io::Error::other("authority mismatch"));
    }
    connect_exact(&authorization.addresses)
}
fn request(authorization: &TransportAuthorization) -> String {
    format!(
        "GET /fixture HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        authorization.hostname, authorization.port
    )
}
#[derive(Debug)]
struct RebindingDns(AtomicUsize);
impl Resolver for RebindingDns {
    fn resolve(
        &self,
        _: &str,
        _: Duration,
        _: usize,
    ) -> std::result::Result<Vec<std::net::IpAddr>, ResolveFailure> {
        let previous = self.0.fetch_add(1, Ordering::SeqCst);
        if previous == 0 {
            Ok(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                8, 8, 8, 8,
            ))])
        } else {
            Err(ResolveFailure)
        }
    }
}
#[test]
fn pinned_transport_never_performs_second_dns_lookup_and_preserves_host()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let resolver = RebindingDns(AtomicUsize::new(0));
    let addresses = resolver
        .resolve("fixture.test", Duration::from_secs(1), 64)
        .map_err(|_| "failed initial resolution")?;
    assert_eq!(addresses.len(), 1);
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let socket = listener.local_addr()?;
    let server = std::thread::spawn(move || -> std::io::Result<String> {
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        let mut input = [0; 4096];
        let size = stream.read(&mut input)?;
        stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
        Ok(String::from_utf8_lossy(&input[..size]).into_owned())
    });
    // Fixture-only socket substitution: no production allow_private option exists.
    let authorization = fixture_authorization("fixture.test", socket, "http");
    let mut stream = authorized_connection(&authorization)?;
    stream.write_all(request(&authorization).as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    assert!(response.starts_with("HTTP/1.1 302"));
    let received = server.join().map_err(|_| "fixture panic")??;
    assert!(received.contains(&format!("Host: fixture.test:{}\r\n", socket.port())));
    assert_eq!(resolver.0.load(Ordering::SeqCst), 1);
    // No redirect follow, second resolver or system DNS exists in this executor.
    Ok(())
}
fn server_config() -> std::result::Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    let cert =
        rustls::pki_types::CertificateDer::from(include_bytes!("fixtures/cert.der").to_vec());
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        include_bytes!("fixtures/key.der").to_vec(),
    ));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)?,
    ))
}
fn client_config() -> std::result::Result<Arc<rustls::ClientConfig>, Box<dyn std::error::Error>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(
        include_bytes!("fixtures/cert.der").to_vec(),
    ))?;
    Ok(Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth(),
    ))
}
#[test]
fn pinned_https_preserves_sni_and_hostname_verification()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for hostname in ["fixture.test", "wrong.test"] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let config = server_config()?;
        let server = std::thread::spawn(move || -> std::io::Result<(String, String)> {
            let (mut socket, _) = listener.accept()?;
            socket.set_read_timeout(Some(Duration::from_secs(2)))?;
            socket.set_write_timeout(Some(Duration::from_secs(2)))?;
            let mut connection =
                rustls::ServerConnection::new(config).map_err(std::io::Error::other)?;
            let mut stream = rustls::Stream::new(&mut connection, &mut socket);
            let mut input = [0; 4096];
            let read = stream.read(&mut input);
            if let Ok(size) = read {
                stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )?;
                stream.flush()?;
                return Ok((
                    stream.conn.server_name().unwrap_or_default().into(),
                    String::from_utf8_lossy(&input[..size]).into_owned(),
                ));
            }
            Err(std::io::Error::other("TLS fixture refused"))
        });
        let authorization = fixture_authorization(hostname, address, "https");
        let mut socket = authorized_connection(&authorization)?;
        let name = rustls::pki_types::ServerName::try_from(authorization.hostname.clone())?;
        let mut connection = rustls::ClientConnection::new(client_config()?, name)?;
        let mut stream = rustls::Stream::new(&mut connection, &mut socket);
        let result = stream
            .write_all(request(&authorization).as_bytes())
            .and_then(|()| stream.flush())
            .and_then(|()| {
                let mut buf = [0; 4096];
                stream.read(&mut buf).map(|_| ())
            });
        let received = server.join().map_err(|_| "fixture panic")?;
        if hostname == "fixture.test" {
            result?;
            let (sni, input) = received?;
            assert_eq!(sni, hostname);
            assert!(input.contains(&format!("Host: {hostname}:{}\r\n", address.port())));
        } else {
            assert!(result.is_err());
            assert!(received.is_err());
        }
    }
    Ok(())
}
