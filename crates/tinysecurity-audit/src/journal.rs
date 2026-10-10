//! Bounded append-only authority; projections never determine durable receipts.
use crate::{Error, Result};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
};
use tinysecurity_bus::AuditSinkRequest2;
const HEADER: usize = 40;
const COMMIT: &[u8; 8] = b"TSACMT02";
pub(crate) fn frame(batch: &AuditSinkRequest2) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec(batch).map_err(|_| Error::Sanitation)?;
    let length = u64::try_from(payload.len()).map_err(|_| Error::Storage)?;
    let mut bytes = Vec::with_capacity(HEADER + payload.len() + COMMIT.len());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&Sha256::digest(&payload));
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(COMMIT);
    Ok(bytes)
}
pub(crate) fn recover(file: &mut File, capacity: u64) -> Result<Vec<AuditSinkRequest2>> {
    file.seek(SeekFrom::Start(0)).map_err(|_| Error::Storage)?;
    let mut bytes = Vec::new();
    file.take(capacity.checked_add(1).ok_or(Error::Storage)?)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Storage)?;
    if u64::try_from(bytes.len()).map_err(|_| Error::Storage)? > capacity {
        return Err(Error::Storage);
    }
    let mut cursor = 0_usize;
    let mut records = Vec::new();
    while bytes.len() - cursor >= HEADER {
        let header = &bytes[cursor..cursor + HEADER];
        let length = u64::from_be_bytes(header[..8].try_into().map_err(|_| Error::Storage)?);
        if length > capacity {
            return Err(Error::Storage);
        }
        let length = usize::try_from(length).map_err(|_| Error::Storage)?;
        let end = cursor
            .checked_add(HEADER)
            .and_then(|offset| offset.checked_add(length))
            .and_then(|offset| offset.checked_add(COMMIT.len()))
            .ok_or(Error::Storage)?;
        if end > bytes.len() {
            break;
        }
        let payload = &bytes[cursor + HEADER..end - COMMIT.len()];
        if &bytes[end - COMMIT.len()..end] != COMMIT
            || Sha256::digest(payload).as_slice() != &header[8..]
        {
            return Err(Error::Storage);
        }
        let batch: AuditSinkRequest2 =
            serde_json::from_slice(payload).map_err(|_| Error::Storage)?;
        batch.validate().map_err(|_| Error::Storage)?;
        records.push(batch);
        cursor = end;
    }
    if cursor < bytes.len() {
        file.set_len(u64::try_from(cursor).map_err(|_| Error::Storage)?)
            .map_err(|_| Error::Storage)?;
    }
    // Even a complete recovered retry is synced before it is acknowledged.
    file.sync_all().map_err(|_| Error::Storage)?;
    Ok(records)
}
pub(crate) fn append(file: &mut File, frame: &[u8]) -> Result<()> {
    file.seek(SeekFrom::End(0)).map_err(|_| Error::Storage)?;
    file.write_all(frame).map_err(|_| Error::Storage)?;
    file.sync_all().map_err(|_| Error::Storage)
}
#[cfg(test)]
#[path = "journal_tests.rs"]
mod tests;
