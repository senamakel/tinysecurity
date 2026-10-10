//! Cross-process ordered JSONL storage: one complete batch per committed line.
use crate::{
    Error, Result,
    rotation::{Directory, sibling},
};
use fs4::FileExt;
use std::{
    fmt,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use tinysecurity_bus::{AuditEventReceipt2, AuditSinkRequest2, AuditSinkResponse2};
/// Restricted native sink with a stable lock across rotation and restarts.
///
/// Rotation retains archives and fails when the configured archive bound fills.
/// Unsupported native restriction facilities fail closed.
pub struct JsonlSink {
    redactor: tinysecurity_redact::Redactor,
    directory: Directory,
    name: PathBuf,
    max_bytes: u64,
    max_archives: u32,
}
impl fmt::Debug for JsonlSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JsonlSink([REDACTED])")
    }
}
impl JsonlSink {
    /// Open a sink below a trusted restricted directory; never harden broad existing files.
    ///
    /// # Errors
    /// Rejects relative/unsafe paths, insecure files, unavailable restriction facilities
    /// or invalid rotation limits. Creates the restricted stable lock before any data.
    pub fn open(path: &Path, max_bytes: u64, max_archives: u32) -> Result<Self> {
        let redactor =
            tinysecurity_redact::Redactor::new(&tinysecurity_bus::RedactorConfig::default())
                .map_err(|_| Error::Sanitation)?;
        Self::with_redactor(path, max_bytes, max_archives, redactor)
    }
    /// Open storage with the active immutable policy registry.
    ///
    /// # Errors
    /// Rejects unsafe paths, rotation limits or unavailable restriction facilities.
    pub fn with_redactor(
        path: &Path,
        max_bytes: u64,
        max_archives: u32,
        redactor: tinysecurity_redact::Redactor,
    ) -> Result<Self> {
        if max_bytes == 0 || max_archives == 0 || max_archives > 1024 {
            return Err(Error::Permissions);
        }
        let directory = Directory::open(path.parent().ok_or(Error::Permissions)?)?;
        let name: PathBuf = path.file_name().ok_or(Error::Permissions)?.into();
        directory
            .file(&sibling(&name, ".lock"))?
            .sync_all()
            .map_err(|_| Error::Storage)?;
        directory.sync()?;
        Ok(Self {
            redactor,
            directory,
            name,
            max_bytes,
            max_archives,
        })
    }
    /// Append the complete sanitized batch, or reconcile an identical previous attempt.
    ///
    /// A full JSON line is one atomic logical batch. An incomplete final line is
    /// truncated during recovery; a partial batch is never acknowledged. Data and
    /// directory sync precede every receipt, including recovered retries.
    ///
    /// # Errors
    /// Rejects malformed sequencing, conflicts, unsafe files, busy cross-process lock,
    /// exhausted rotation or indeterminate I/O. Retry exactly the same request after I/O.
    pub fn append(&self, batch: &AuditSinkRequest2) -> Result<AuditSinkResponse2> {
        batch.validate().map_err(|_| Error::Conflict)?;
        let clean = crate::sanitize(batch, &self.redactor)?;
        let lock = self.directory.file(&sibling(&self.name, ".lock"))?;
        FileExt::try_lock(&lock).map_err(|error| match error {
            fs4::TryLockError::WouldBlock => Error::Busy,
            fs4::TryLockError::Error(_) => Error::Storage,
        })?;
        // File drop releases the OS lock on every error; there is no process Mutex.
        self.append_locked(&clean)
    }
    fn append_locked(&self, batch: &AuditSinkRequest2) -> Result<AuditSinkResponse2> {
        let mut recovered = Vec::new();
        let mut archive_index = 1;
        for index in 1..=self.max_archives {
            let name = sibling(&self.name, &format!(".{index}"));
            // Archives are create/open restricted empty files until used. This avoids
            // unsafe pathname existence checks and keeps every operation fd-relative.
            let mut archive = self.directory.file(&name)?;
            let rows = recover(&mut archive)?;
            if rows.is_empty() {
                archive_index = index;
                break;
            }
            recovered.extend(rows);
            archive_index = index.checked_add(1).ok_or(Error::Storage)?;
        }
        let mut current = self.directory.file(&self.name)?;
        recovered.extend(recover(&mut current)?);
        let mut tail = 0;
        let mut replay = false;
        for row in &recovered {
            row.validate().map_err(|_| Error::Storage)?;
            if row.scope != batch.scope
                || row.stream_id != batch.stream_id
                || row.expected_tail != tail
            {
                return Err(Error::Conflict);
            }
            tail = row.events.last().ok_or(Error::Storage)?.sequence;
            if row == batch {
                replay = true;
            }
        }
        if replay {
            current.sync_all().map_err(|_| Error::Storage)?;
            self.directory.sync()?;
            return Ok(receipt(batch));
        }
        if batch.expected_tail != tail {
            return Err(Error::Conflict);
        }
        let mut line = serde_json::to_vec(batch).map_err(|_| Error::Sanitation)?;
        line.push(b'\n');
        let length = u64::try_from(line.len()).map_err(|_| Error::Sanitation)?;
        if length > self.max_bytes {
            return Err(Error::Storage);
        }
        let size = current.metadata().map_err(|_| Error::Storage)?.len();
        if size > 0 && size.checked_add(length).ok_or(Error::Storage)? > self.max_bytes {
            if archive_index > self.max_archives {
                return Err(Error::Storage);
            }
            drop(current);
            self.directory.rotate(
                &self.name,
                &sibling(&self.name, &format!(".{archive_index}")),
            )?;
            current = self.directory.file(&self.name)?;
        }
        current.seek(SeekFrom::End(0)).map_err(|_| Error::Storage)?;
        current.write_all(&line).map_err(|_| Error::Storage)?;
        current.sync_all().map_err(|_| Error::Storage)?;
        self.directory.sync()?;
        Ok(receipt(batch))
    }
}
fn recover(file: &mut File) -> Result<Vec<AuditSinkRequest2>> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|_| Error::Storage)?;
    let committed = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    if committed < bytes.len() {
        file.set_len(u64::try_from(committed).map_err(|_| Error::Storage)?)
            .map_err(|_| Error::Storage)?;
        file.sync_all().map_err(|_| Error::Storage)?;
    }
    bytes[..committed]
        .split(|byte| *byte == b'\n')
        .filter(|row| !row.is_empty())
        .map(|row| serde_json::from_slice(row).map_err(|_| Error::Storage))
        .collect()
}
fn receipt(batch: &AuditSinkRequest2) -> AuditSinkResponse2 {
    AuditSinkResponse2 {
        scope: batch.scope.clone(),
        stream_id: batch.stream_id.clone(),
        events: batch
            .events
            .iter()
            .map(|event| AuditEventReceipt2 {
                sequence: event.sequence,
                event_id: event.event_id.clone(),
            })
            .collect(),
        new_tail: batch
            .events
            .last()
            .map_or(batch.expected_tail, |event| event.sequence),
    }
}
#[cfg(test)]
#[path = "sink_tests.rs"]
mod tests;
