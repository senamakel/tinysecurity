//! Complete original operation checks; host classification cannot bypass inspection.
use tinysecurity_bus::{
    DataCategory, EgressPolicy, Error, PrivacyMode, RedactMode, RedactRequest, Result,
    ScopedEgressRequest,
};
use tinysecurity_redact::Redactor;
pub(crate) fn check(
    policy: &EgressPolicy,
    request: &ScopedEgressRequest,
    redactor: &Redactor,
) -> Result<()> {
    if !["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        .contains(&request.method.as_str())
    {
        return Err(Error::InvalidArguments);
    }
    if request.payload.len() > 65_536
        || request.headers.len() > 64
        || request.transformation.is_some()
        || request.category == DataCategory::Unknown
        || !policy.data_categories.contains(&request.category)
    {
        return Err(Error::InvalidArguments);
    }
    let mut header_bytes = 0;
    for header in &request.headers {
        header_bytes += header.name.len() + header.value.len();
        if header_bytes > 16384
            || header.name.is_empty()
            || header.name.len() > 64
            || header.value.len() > 4096
            || !header
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
            || header.value.chars().any(char::is_control)
            || !header.value.is_ascii()
            || [
                "host",
                "connection",
                "proxy-authorization",
                "proxy-connection",
                "transfer-encoding",
                "content-length",
                "upgrade",
            ]
            .iter()
            .any(|name| header.name.eq_ignore_ascii_case(name))
        {
            return Err(Error::InvalidArguments);
        }
    }
    if policy.privacy == PrivacyMode::LocalOnly && request.local_capability.is_none() {
        return Err(Error::InvalidArguments);
    }
    if policy.privacy == PrivacyMode::Sensitive {
        if matches!(
            request.category,
            DataCategory::Credentials | DataCategory::Identifiers
        ) {
            return Err(Error::InvalidArguments);
        }
        reject_changed(&request.payload, redactor, false)?;
        // Inspect the ORIGINAL complete URL, including query/fragment, before
        // canonicalization. Decode path text as well so %40 cannot hide an email.
        reject_changed(&request.url, redactor, true)?;
        let decoded = percent_encoding::percent_decode_str(&request.url)
            .decode_utf8()
            .map_err(|_| Error::InvalidArguments)?;
        reject_changed(&decoded, redactor, true)?;
        for header in &request.headers {
            if [
                "authorization",
                "cookie",
                "set-cookie",
                "x-api-key",
                "x-user-id",
                "x-email",
            ]
            .iter()
            .any(|name| header.name.eq_ignore_ascii_case(name))
            {
                return Err(Error::InvalidArguments);
            }
            reject_changed(
                &format!("{}={}", header.name, header.value),
                redactor,
                false,
            )?;
        }
    }
    Ok(())
}
fn reject_changed(input: &str, redactor: &Redactor, endpoint: bool) -> Result<()> {
    let result = redactor.redact(&RedactRequest {
        text: input.to_owned(),
        mode: RedactMode::Text,
    })?;
    let original = if endpoint {
        input.trim_end_matches('/')
    } else {
        input
    };
    if result.text != original {
        return Err(Error::InvalidArguments);
    }
    Ok(())
}
