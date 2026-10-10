use super::*;
#[test]
fn debug_and_bounds_are_content_free() -> Result<()> {
    let registry = Redactor::new(&RedactorConfig::default())?;
    assert_eq!(format!("{registry:?}"), "Redactor([REDACTED])");
    assert!(bounded(&"x".repeat(MAX_INPUT + 1)).is_err());
    assert!(output_bounded(&"x".repeat(MAX_OUTPUT + 1)).is_err());
    for input in [
        "https://host/path",
        "host/path",
        "redis://user:private@host:123/a?private#secret",
    ] {
        for mode in [
            RedactMode::Endpoint,
            RedactMode::EndpointOrigin,
            RedactMode::EndpointHost,
        ] {
            let out = registry.redact(&RedactRequest {
                text: input.into(),
                mode: mode.clone(),
            })?;
            assert!(!out.text.contains("private"));
            assert!(!out.text.contains("secret"));
            assert_eq!(
                registry
                    .redact(&RedactRequest {
                        text: out.text.clone(),
                        mode
                    })?
                    .text,
                out.text
            );
        }
    }
    assert!(
        registry
            .scan_prompt(&ScanPromptRequest {
                text: "x".repeat(MAX_INPUT + 1)
            })
            .is_err()
    );
    for (name, definition) in [("", "{}"), ("safe", "[]"), ("safe", "{invalid")] {
        assert!(
            registry
                .scan_tool_definition(&ScanToolDefinitionRequest {
                    name: name.into(),
                    definition_json: definition.into()
                })
                .is_err()
        );
    }
    assert!(
        registry
            .scan_tool_definition(&ScanToolDefinitionRequest {
                name: "a".repeat(257),
                definition_json: "{}".into()
            })
            .is_err()
    );
    Ok(())
}
