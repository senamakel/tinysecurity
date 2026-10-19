//! Confidential per-frame operations over a previously approved native tunnel.

use serde::{Deserialize, Serialize};

/// Seal or open one bounded frame through a tunnel handle returned by approved device work.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeviceFrameOperation2 {
    /// Encrypt plaintext as a version-two tunnel frame.
    Seal {
        /// Confidential plaintext, bounded by the configured device limit.
        plaintext: Vec<u8>,
    },
    /// Authenticate and decrypt a version-two tunnel frame.
    Open {
        /// Confidential frame, bounded by the configured device limit.
        frame: Vec<u8>,
    },
}

/// Confidential frame request using an opaque tunnel handle from `ExecuteDevice2`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceFrameRequest2 {
    /// Existing registered device scope that owns the handle.
    pub scope_id: String,
    /// Opaque tunnel capability returned by an approved `DeviceOperation2::Tunnel`.
    pub handle: String,
    /// Exact host execution instance, bounded to 128 bytes.
    pub call_id: String,
    /// One seal or open operation; no keys or caller identity are accepted.
    pub operation: DeviceFrameOperation2,
}

/// Confidential frame result; opening returns plaintext only over the trusted bus link.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceFrameResponse2 {
    /// Sealed frame or authenticated plaintext.
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for DeviceFrameOperation2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceFrameOperation2([REDACTED])")
    }
}
impl std::fmt::Debug for DeviceFrameRequest2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceFrameRequest2([REDACTED])")
    }
}
impl std::fmt::Debug for DeviceFrameResponse2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceFrameResponse2([REDACTED])")
    }
}

#[cfg(test)]
#[path = "device_frame_tests.rs"]
mod tests;
