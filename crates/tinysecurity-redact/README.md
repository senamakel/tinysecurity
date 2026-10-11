# Native redaction and semantic scanning

`Redactor` compiles one immutable registry at SDK initialization. Hosts link
`tinysecurity-bus` and invoke `Redact`, `ScanPrompt` and `ScanToolDefinition`;
they never link this crate. Exact credentials live only in `RedactorConfig`
`Secret` values and are absent from `PolicyInfo`, errors and Debug output.
Initialization serialization carries plaintext across the trusted loader
boundary and must never be logged.

Text preserves diagnostics, timestamps and ordinary tokenizer/medical/legal
prose while removing known token formats, credential assignments, email,
validated identifiers, URL capabilities and native home prefixes. Cards need
both an issuer prefix and Luhn validation; IBANs need mod-97 validation. These
local patterns reduce accidental disclosure and do not detect every identifier
or establish that arbitrary text is safe for publication.

Structured arguments use approval count/type markers for sensitive content
keys; structured log arguments redact credential keys without hiding ordinary
content. Both scan unknown fields, keys and embedded JSON. Key collisions retain
all values under numbered sanitized keys. BrowserResult protects only the
`pending.token` UUID in an explicit `NeedsConfirmation` document, with the rest
of the document scrubbed normally. An exact configured credential is never
exempted. The trusted host selects this result surface only for its browser
confirmation response; page content must use Text or structured log mode.

Endpoint retains path; EndpointOrigin retains scheme/host/port; EndpointHost
retains hostname. All strip userinfo, query and fragment. Configured literals in a retained
endpoint part suppress the entire endpoint to `[REDACTED]`. This is formatting,
not URL authorization, DNS resolution or egress protection. IdentifierHash
matches SHA-256's first eight hex characters; LegacyMask keeps four Unicode
characters followed by `***` (short inputs become `***`). Already formatted
hashes/masks are fixed points. These explicit historical modes deliberately
reveal a small identifier/prefix and must not replace Text for credentials.

Input is capped at 65536 UTF-8 bytes, output at 131072 bytes and JSON traversal
at 32 levels, including embedded JSON. Configuration accepts at most 128 exact
literals, 4–4096 bytes each, totaling at most 16384 bytes. Literals intersecting
output marker templates (including their counts) are rejected to preserve idempotence. Malformed structured
input/endpoints and limit failures return content-free errors; callers must
suppress the payload, never fall back to displaying or logging the original.
SDK reinitialization validates the complete candidate before activating it;
failed initialization leaves the old generation and scoped registries intact.

Semantic scans inspect original text and complete tool JSON, including names,
keys and unknown metadata, before lexical sanitation or redaction. Invisible
instruction controls and credential/hidden-prompt exfiltration block; instruction
overrides are suspicious. Clean is contextual evidence, never authorization.
The current policy denies blocked content and denies suspicious content with
approval-unavailable, without manufacturing a durable approval identity.

TinyMCP owns protocol lexical controls/fences and UTF-8 field truncation.
TinySkills owns package/frontmatter/resource scanning and exact-document
acknowledgment. Neither is reimplemented here. Host composition must retain
those original findings, run semantic scans on original content, then apply
owner sanitation. Redacting an instruction or credential does not clear a
blocked package or authorize a tool. During host migration, unavailable-module
logging must suppress payloads or retain its established minimum floor; this
owner change does not remove any host floor.
