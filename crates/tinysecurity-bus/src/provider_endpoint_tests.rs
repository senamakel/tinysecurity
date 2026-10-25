use super::*;

#[test]
fn provider_endpoint_request_is_bounded_and_host_only() {
    assert!(
        ProviderEndpointRequest2 {
            host: "[::1]".into()
        }
        .validate()
        .is_ok()
    );
    for host in ["", "has white space", "host\nname"] {
        assert!(
            ProviderEndpointRequest2 { host: host.into() }
                .validate()
                .is_err()
        );
    }
    assert!(
        ProviderEndpointRequest2 {
            host: "a".repeat(MAX_PROVIDER_HOST_BYTES + 1)
        }
        .validate()
        .is_err()
    );
}

#[test]
fn provider_endpoint_request_and_response_have_stable_wire_shapes() {
    let request = ProviderEndpointRequest2 {
        host: "localhost".into(),
    };
    let encoded = serde_json::to_value(&request).unwrap();
    assert_eq!(encoded, serde_json::json!({"host": "localhost"}));
    assert_eq!(
        serde_json::from_value::<ProviderEndpointRequest2>(encoded).unwrap(),
        request
    );

    let response = ProviderEndpointResponse2 {
        locality: ProviderEndpointLocality2::OnDevice,
    };
    let encoded = serde_json::to_value(&response).unwrap();
    assert_eq!(encoded, serde_json::json!({"locality": "on_device"}));
    assert_eq!(
        serde_json::from_value::<ProviderEndpointResponse2>(encoded).unwrap(),
        response
    );
}

#[test]
fn provider_endpoint_locality_has_stable_wire_names_and_method() {
    assert_eq!(
        serde_json::to_value(ProviderEndpointLocality2::OnDevice).unwrap(),
        serde_json::json!("on_device")
    );
    assert_eq!(
        serde_json::to_value(ProviderEndpointLocality2::External).unwrap(),
        serde_json::json!("external")
    );
    assert_eq!(
        crate::names::methods::CLASSIFY_PROVIDER_ENDPOINT2,
        "ClassifyProviderEndpoint2"
    );
    assert!(crate::names::METHODS.contains(&crate::names::methods::CLASSIFY_PROVIDER_ENDPOINT2));
    assert_eq!(crate::CONTRACT_VERSION, (1, 32));
    assert!(crate::is_compatible((1, 32)));
    assert!(!crate::is_compatible((1, 31)));
}
