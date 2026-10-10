//! Stable bounded journal authority with reconstructable ordered JSONL views.
use crate::{
    Error, Result,
    rotation::{Directory, sibling},
};
use fs4::FileExt;
use std::{
    fmt,
    fs::File,
    io::{Seek, SeekFrom, Write},
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
    journal_bytes: u64,
    journal_events: u64,
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
        let journal_bytes = max_bytes
            .checked_mul(u64::from(max_archives) + 1)
            .and_then(|size| size.checked_add(65536))
            .ok_or(Error::Permissions)?;
        Self::with_journal_capacity(
            path,
            max_bytes,
            max_archives,
            journal_bytes,
            (u64::from(max_archives) + 1) * 128,
            redactor,
        )
    }
    /// Open with explicit hard authoritative journal byte and event capacities.
    ///
    /// Journal bytes are never reclaimed without a separately proven checkpoint.
    /// # Errors
    /// Rejects unsafe storage and invalid capacities before accepting any batch.
    pub fn with_journal_capacity(
        path: &Path,
        max_bytes: u64,
        max_archives: u32,
        journal_bytes: u64,
        journal_events: u64,
        redactor: tinysecurity_redact::Redactor,
    ) -> Result<Self> {
        if max_bytes == 0
            || max_archives == 0
            || max_archives > 1024
            || journal_bytes == 0
            || journal_bytes == u64::MAX
            || journal_events == 0
        {
            return Err(Error::Permissions);
        }
        let directory = Directory::open(path.parent().ok_or(Error::Permissions)?)?;
        let name: PathBuf = path.file_name().ok_or(Error::Permissions)?.into();
        for suffix in [".lock", ".journal"] {
            directory
                .file(&sibling(&name, suffix))?
                .sync_all()
                .map_err(|_| Error::Storage)?;
        }
        directory.sync()?;
        Ok(Self {
            redactor,
            directory,
            name,
            max_bytes,
            max_archives,
            journal_bytes,
            journal_events,
        })
    }
    /// Append the complete sanitized batch, or reconcile an identical previous attempt.
    ///
    /// A self-validating journal frame is one logical batch. An incomplete final
    /// frame is discarded whole and synced during recovery. JSONL files contain
    /// reconstructable projections; only journal sync establishes the commit.
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
        let mut journal = self.directory.file(&sibling(&self.name, ".journal"))?;
        let recovered = crate::journal::recover(&mut journal, self.journal_bytes)?;
        let mut tail = 0;
        let mut replay = false;
        let mut event_ids = std::collections::BTreeSet::new();
        for row in &recovered {
            row.validate().map_err(|_| Error::Storage)?;
            if row.scope != batch.scope
                || row.stream_id != batch.stream_id
                || row.expected_tail != tail
            {
                return Err(Error::Conflict);
            }
            for event in &row.events {
                if !event_ids.insert(&event.event_id) {
                    return Err(Error::Conflict);
                }
            }
            tail = row.events.last().ok_or(Error::Storage)?.sequence;
            if row == batch {
                replay = true;
            }
        }
        if replay {
            let _ = self.project(&recovered);
            return Ok(receipt(batch));
        }
        if batch.expected_tail != tail
            || batch
                .events
                .iter()
                .any(|event| event_ids.contains(&event.event_id))
        {
            return Err(Error::Conflict);
        }
        let frame = crate::journal::frame(batch)?;
        let size = journal.metadata().map_err(|_| Error::Storage)?.len();
        let events = recovered.iter().try_fold(0_u64, |count, row| {
            count
                .checked_add(u64::try_from(row.events.len()).map_err(|_| Error::Storage)?)
                .ok_or(Error::Storage)
        })?;
        if size
            .checked_add(u64::try_from(frame.len()).map_err(|_| Error::Storage)?)
            .ok_or(Error::Storage)?
            > self.journal_bytes
            || events
                .checked_add(u64::try_from(batch.events.len()).map_err(|_| Error::Storage)?)
                .ok_or(Error::Storage)?
                > self.journal_events
        {
            return Err(Error::Storage);
        }
        let mut line = serde_json::to_vec(batch).map_err(|_| Error::Sanitation)?;
        line.push(b'\n');
        let length = u64::try_from(line.len()).map_err(|_| Error::Storage)?;
        if length > self.max_bytes {
            return Err(Error::Storage);
        }
        // Rebuild only previously committed data, and perform any rotation before
        // committing the candidate. An open-handle rotation failure cannot commit it.
        let (mut current, archive_index) = self.project(&recovered)?;
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
        crate::journal::append(&mut journal, &frame)?;
        // The stable journal is now authoritative. Projection failure cannot roll
        // back its commit or produce committed=false; the next attempt rebuilds it.
        let _ = current
            .seek(SeekFrom::End(0))
            .and_then(|_| current.write_all(&line))
            .and_then(|()| current.sync_all());
        let _ = self.directory.sync();
        Ok(receipt(batch))
    }
    fn project(&self, records: &[AuditSinkRequest2]) -> Result<(File, u32)> {
        let mut chunks: Vec<Vec<u8>> = vec![Vec::new()];
        for row in records {
            let mut line = serde_json::to_vec(row).map_err(|_| Error::Storage)?;
            line.push(b'\n');
            if u64::try_from(line.len()).map_err(|_| Error::Storage)? > self.max_bytes {
                return Err(Error::Storage);
            }
            let last = chunks.last_mut().ok_or(Error::Storage)?;
            if u64::try_from(last.len() + line.len()).map_err(|_| Error::Storage)? > self.max_bytes
            {
                chunks.push(line);
            } else {
                last.extend(line);
            }
        }
        if chunks.len() > usize::try_from(self.max_archives).map_err(|_| Error::Storage)? + 1 {
            return Err(Error::Storage);
        }
        let current_index = chunks.len() - 1;
        for index in 0..=self.max_archives {
            let name = if index == 0 {
                self.name.clone()
            } else {
                sibling(&self.name, &format!(".{index}"))
            };
            let mut file = self.directory.file(&name)?;
            let contents = if index == 0 {
                &chunks[current_index][..]
            } else {
                chunks
                    .get(usize::try_from(index - 1).map_err(|_| Error::Storage)?)
                    .filter(|_| usize::try_from(index).is_ok_and(|i| i <= current_index))
                    .map_or(&[][..], Vec::as_slice)
            };
            file.set_len(0).map_err(|_| Error::Storage)?;
            file.write_all(contents).map_err(|_| Error::Storage)?;
            file.sync_all().map_err(|_| Error::Storage)?;
        }
        self.directory.sync()?;
        Ok((
            self.directory.file(&self.name)?,
            u32::try_from(chunks.len()).map_err(|_| Error::Storage)?,
        ))
    }
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
#[cfg(all(test, unix))]
#[path = "sink_tests.rs"]
mod tests;
#[cfg(all(test, windows))]
#[path = "sink_windows_tests.rs"]
mod windows_tests;
