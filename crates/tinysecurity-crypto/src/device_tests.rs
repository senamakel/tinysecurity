use super::*;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

fn schedule() -> Result<SessionKeys> {
    SessionKeys::derive(&[1; 32], &[2; 32], PublicKey([3; 32]), PublicKey([4; 32]))
}
fn fixture(name: &str) -> TestResult<Vec<u8>> {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../tests/fixtures/device_legacy_wire.json"))?;
    Ok(URL_SAFE_NO_PAD.decode(fixture[name].as_str().ok_or("fixture must be a string")?)?)
}
#[test]
fn authenticated_v2_nonce_cannot_be_replayed() -> TestResult {
    let mut server = Tunnel::new(Role::Server, schedule()?);
    let frame = fixture("frame_v2")?;
    assert_eq!(&*server.open(&frame)?, b"legacy device frame");
    assert!(
        server.open(&frame).is_err(),
        "authenticated nonce must not be replayed"
    );
    Ok(())
}

#[test]
fn frozen_host_v2_v3_v4_bytes_authenticate_and_reencrypt_identically() -> TestResult {
    let frame = fixture("frame_v2")?;
    let keys = schedule()?;
    assert_eq!(
        seal_nonce(
            &keys.c2s,
            &[2],
            &[],
            b"legacy device frame",
            frame[1..25].try_into()?
        )?,
        frame
    );
    let mut hsalt = [0; 64];
    hsalt[..32].copy_from_slice(&[3; 32]);
    hsalt[32..].copy_from_slice(&[4; 32]);
    let key = keys::derive(&[1; 32], &hsalt, b"openhuman-tunnel/v3/handshake")?;
    let handshake = fixture("handshake_v3")?;
    assert_eq!(
        &*open(&key, &handshake, 33, 3, &handshake[..33])?,
        b"legacy handshake"
    );
    assert_eq!(
        seal_nonce(
            &key,
            &handshake[..33],
            &handshake[..33],
            b"legacy handshake",
            &[5; 24]
        )?,
        handshake
    );
    let ack_key = keys::derive(&[1; 32], &[3; 32], b"openhuman-tunnel/v3/handshake-ack")?;
    let aad = [&[4][..], &[3; 32]].concat();
    let ack = fixture("ack_v4")?;
    assert_eq!(
        &*open(&ack_key, &ack, 1, 4, &aad)?,
        b"legacy acknowledgement"
    );
    assert_eq!(
        seal_nonce(&ack_key, &[4], &aad, b"legacy acknowledgement", &[6; 24])?,
        ack
    );
    for (wire, k, header, marker, aad) in [
        (handshake, key, 33, 3, hsalt[..32].to_vec()),
        (ack, ack_key, 1, 4, aad),
    ] {
        let mut bad_tag = wire.clone();
        *bad_tag.last_mut().ok_or("fixture must contain a tag")? ^= 1;
        let original_aad = if header == 33 {
            wire[..33].to_vec()
        } else {
            aad
        };
        assert_eq!(
            open(&k, &bad_tag, header, marker, &original_aad),
            Err(Error::Authentication)
        );
        let mut bad_aad = original_aad.clone();
        bad_aad[0] ^= 1;
        assert_eq!(
            open(&k, &wire, header, marker, &bad_aad),
            Err(Error::Authentication)
        );
    }
    Ok(())
}
#[test]
fn failed_tags_do_not_consume_nonce_and_direction_prevents_reflection() -> TestResult {
    let frame = fixture("frame_v2")?;
    let mut server = Tunnel::new(Role::Server, schedule()?);
    let mut tampered = frame.clone();
    *tampered.last_mut().ok_or("fixture must contain a tag")? ^= 1;
    assert_eq!(server.open(&tampered), Err(Error::Authentication));
    assert_eq!(&*server.open(&frame)?, b"legacy device frame");
    assert_eq!(server.open(&frame), Err(Error::Replay));
    assert_eq!(server.authenticated_nonces.len(), 1);
    let mut client = Tunnel::new(Role::Client, schedule()?);
    assert_eq!(client.open(&frame), Err(Error::Authentication));
    let reflected = server.seal(b"directional reflection")?;
    assert_eq!(server.open(&reflected), Err(Error::Authentication));
    assert_eq!(&*client.open(&reflected)?, b"directional reflection");
    Ok(())
}
#[test]
fn only_authenticated_nonces_count_toward_exact_128_frame_window() -> TestResult {
    let keys = schedule()?;
    let mut receiver = Tunnel::new(Role::Server, schedule()?);
    let frames: Vec<_> = (0..129)
        .map(|i| {
            let mut nonce = [0; 24];
            nonce[0] = i;
            seal_nonce(&keys.c2s, &[2], &[], b"window", &nonce)
        })
        .collect::<Result<Vec<_>>>()?;
    for frame in &frames[..128] {
        assert!(receiver.open(frame).is_ok());
    }
    assert_eq!(receiver.authenticated_nonces.len(), 128);
    for frame in &frames[..128] {
        assert_eq!(receiver.open(frame), Err(Error::Replay));
    }
    let mut invalid = frames[128].clone();
    *invalid.last_mut().ok_or("fixture must contain a tag")? ^= 1;
    for _ in 0..129 {
        assert_eq!(receiver.open(&invalid), Err(Error::Authentication));
    }
    assert_eq!(receiver.open(&frames[0]), Err(Error::Replay));
    assert!(receiver.open(&frames[128]).is_ok());
    assert_eq!(receiver.open(&frames[1]), Err(Error::Replay));
    assert!(receiver.open(&frames[0]).is_ok());
    assert_eq!(receiver.authenticated_nonces.len(), 128);
    Ok(())
}
#[test]
fn rejects_wrong_versions_malformed_frames_and_oversize_before_crypto() -> TestResult {
    let mut receiver = Tunnel::new(Role::Server, schedule()?);
    for length in [0, 1, 24, 25, 40] {
        assert_eq!(receiver.open(&vec![2; length]), Err(Error::InvalidInput));
    }
    for version in [0, 1, 3, 4, 255] {
        let mut frame = fixture("frame_v2")?;
        frame[0] = version;
        assert_eq!(receiver.open(&frame), Err(Error::InvalidInput));
    }
    assert_eq!(
        receiver.open(&vec![2; MAX_MESSAGE_BYTES + 42]),
        Err(Error::Limit)
    );
    assert_eq!(
        receiver.seal(&vec![0; MAX_MESSAGE_BYTES + 1]),
        Err(Error::Limit)
    );
    let frame = Tunnel::new(Role::Client, schedule()?).seal(&vec![0; MAX_MESSAGE_BYTES])?;
    assert_eq!(receiver.open(&frame)?.len(), MAX_MESSAGE_BYTES);
    Ok(())
}
fn pair(value: u8) -> Result<KeyPair> {
    KeyPair::from_secret(Zeroizing::new([value; 32]))
}
#[test]
fn full_native_exchange_preserves_handshake_ack_and_both_frame_directions() -> TestResult {
    let core = pair(11)?;
    let client = pair(12)?;
    let server_ephemeral = pair(13)?;
    let client_ephemeral = pair(14)?;
    let handshake = client_ephemeral.seal_handshake(core.public_key(), b"handshake bytes")?;
    assert_eq!(handshake[0], 3);
    let (public, opened) = core.open_handshake(&handshake)?;
    assert_eq!(public, client_ephemeral.public_key());
    assert_eq!(&*opened, b"handshake bytes");
    let ack = core.seal_ack(public, b"ack bytes")?;
    assert_eq!(ack[0], 4);
    assert_eq!(
        &*client_ephemeral.open_ack(core.public_key(), &ack)?,
        b"ack bytes"
    );
    let core_keys = core.session_keys(
        client.public_key(),
        &server_ephemeral,
        public,
        public,
        server_ephemeral.public_key(),
    )?;
    let client_keys = client.session_keys(
        core.public_key(),
        &client_ephemeral,
        server_ephemeral.public_key(),
        public,
        server_ephemeral.public_key(),
    )?;
    let mut core_tunnel = Tunnel::new(Role::Server, core_keys);
    let mut client_tunnel = Tunnel::new(Role::Client, client_keys);
    assert_eq!(&*core_tunnel.open(&client_tunnel.seal(b"")?)?, b"");
    assert_eq!(
        &*client_tunnel.open(&core_tunnel.seal(b"reply")?)?,
        b"reply"
    );
    assert_eq!(format!("{core_tunnel:?}"), "Tunnel([REDACTED])");
    Ok(())
}
#[test]
fn bootstrap_rejects_bad_tags_headers_wrong_peer_and_work_bounds() -> TestResult {
    let core = pair(11)?;
    let client = pair(12)?;
    let wrong = pair(13)?;
    let handshake = client.seal_handshake(core.public_key(), b"hello")?;
    let ack = core.seal_ack(client.public_key(), b"ack")?;
    let mut bad = handshake.clone();
    bad[1] ^= 1;
    assert!(core.open_handshake(&bad).is_err());
    *bad.last_mut().ok_or("fixture must contain a tag")? ^= 1;
    assert!(core.open_handshake(&bad).is_err());
    assert!(wrong.open_handshake(&handshake).is_err());
    assert!(client.open_ack(wrong.public_key(), &ack).is_err());
    assert!(wrong.open_ack(core.public_key(), &ack).is_err());
    for marker in [1, 2, 4] {
        let mut bad = handshake.clone();
        bad[0] = marker;
        assert!(core.open_handshake(&bad).is_err());
    }
    let mut bad_ack = ack.clone();
    *bad_ack.last_mut().ok_or("fixture must contain a tag")? ^= 1;
    assert!(client.open_ack(core.public_key(), &bad_ack).is_err());
    bad_ack[0] = 3;
    assert!(client.open_ack(core.public_key(), &bad_ack).is_err());
    assert!(core.open_handshake(&[]).is_err());
    assert!(client.open_ack(core.public_key(), &[]).is_err());
    assert!(
        core.open_handshake(&vec![3; MAX_MESSAGE_BYTES + 74])
            .is_err()
    );
    assert!(
        client
            .open_ack(core.public_key(), &vec![4; MAX_MESSAGE_BYTES + 42])
            .is_err()
    );
    for result in [
        client.seal_handshake(core.public_key(), &vec![0; MAX_MESSAGE_BYTES + 1]),
        core.seal_ack(client.public_key(), &vec![0; MAX_MESSAGE_BYTES + 1]),
        client.seal_handshake(PublicKey([0; 32]), b""),
        core.seal_ack(PublicKey([0; 32]), b""),
    ] {
        assert!(result.is_err());
    }
    let mut low_order = [0; 32];
    low_order[0] = 1;
    let malicious = [&[3][..], &low_order, &[0; 40]].concat();
    assert!(core.open_handshake(&malicious).is_err());
    Ok(())
}
