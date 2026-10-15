//! Version 1.4 scoped contracts leave legacy strict version 1 shapes intact.
use serde_json::Value;
use tinysecurity_bus::*;
macro_rules! golden {
    ($type:ty,$name:ident) => {
        #[test]
        fn $name() -> std::result::Result<(), Box<dyn std::error::Error>> {
            let values: Value = serde_json::from_str(include_str!("fixtures/v1_4.json"))?;
            let value = values[stringify!($type)].clone();
            let decoded: $type = serde_json::from_value(value.clone())?;
            assert_eq!(serde_json::to_value(decoded)?, value);
            Ok(())
        }
    };
}
golden!(EgressPolicy, scoped_policy_wire);
golden!(ScopedEgressRequest, scoped_request_wire);
golden!(ScopedEgressResponse, scoped_response_wire);
golden!(ConsumeEgressAuthorizationRequest, consume_wire);
#[test]
fn scoped_contracts_reject_legacy_or_invocation_authority_fields() {
    assert!(
        serde_json::from_str::<ScopedEgressRequest>(
            r#"{"url":"https://example.com","redirect_from":null}"#
        )
        .is_err()
    );
    assert!(serde_json::from_str::<EgressPolicy>(r#"{"owner":{"user":"u","workspace":"w","agent":"a"},"ceiling":"full","privacy":"standard","destinations":[],"data_categories":[],"local_capabilities":[],"validity_ms":1000,"allow_private":true}"#).is_err());
}
#[test]
fn open_public_and_preflight_fields_round_trip_and_stay_off_the_legacy_wire()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"owner":{"user":"u","workspace":"w","agent":"a"},"ceiling":"full","privacy":"standard","destinations":[],"data_categories":["user_content"],"local_capabilities":[],"validity_ms":1000,"open_public":true,"preflight_transports":["browser","proxy"]}"#;
    let policy: EgressPolicy = serde_json::from_str(json)?;
    assert!(policy.open_public);
    assert_eq!(
        policy.preflight_transports,
        [EgressTransport::Browser, EgressTransport::Proxy]
    );
    assert_eq!(
        serde_json::to_value(&policy)?,
        serde_json::from_str::<Value>(json)?
    );
    let closed = EgressPolicy {
        open_public: false,
        preflight_transports: vec![],
        ..policy
    };
    let wire = serde_json::to_value(&closed)?;
    assert!(wire.get("open_public").is_none() && wire.get("preflight_transports").is_none());
    Ok(())
}
