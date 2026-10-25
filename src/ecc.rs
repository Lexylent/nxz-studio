use crate::error::NxzError;
use reed_solomon_erasure::galois_8::ReedSolomon;

const ECC_MAGIC: [u8; 4] = *b"ECC1";
const DATA_SHARDS: usize = 16;
const PARITY_SHARDS: usize = 2;
const TOTAL_SHARDS: usize = DATA_SHARDS + PARITY_SHARDS;

pub fn ecc_protect(payload: &[u8]) -> Result<Vec<u8>, NxzError> {
    let orig_len = payload.len();
    let shard_len = ((orig_len + DATA_SHARDS - 1) / DATA_SHARDS).max(1);

    let rs = ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
        .map_err(|e| NxzError::EccError(format!("RS init error: {e}")))?;

    let mut shards: Vec<Vec<u8>> = vec![vec![0u8; shard_len]; TOTAL_SHARDS];
    for i in 0..DATA_SHARDS {
        let start = i * shard_len;
        if start < orig_len {
            let end = (start + shard_len).min(orig_len);
            let copy_len = end - start;
            shards[i][..copy_len].copy_from_slice(&payload[start..end]);
        }
    }

    rs.encode(&mut shards)
        .map_err(|e| NxzError::EccError(format!("RS encode error: {e}")))?;

    let mut out = Vec::with_capacity(16 + TOTAL_SHARDS * 8 + TOTAL_SHARDS * shard_len);
    out.extend_from_slice(&ECC_MAGIC);
    out.extend_from_slice(&(orig_len as u64).to_le_bytes());
    out.extend_from_slice(&(shard_len as u32).to_le_bytes());

    for shard in &shards {
        let h = blake3::hash(shard);
        out.extend_from_slice(&h.as_bytes()[0..8]);
    }
    for shard in &shards {
        out.extend_from_slice(shard);
    }

    Ok(out)
}

pub fn ecc_verify_and_heal(envelope: &[u8]) -> Result<(Vec<u8>, usize), NxzError> {
    if envelope.len() < 16 + TOTAL_SHARDS * 8 || &envelope[0..4] != &ECC_MAGIC {
        return Err(NxzError::EccError("Invalid ECC1 envelope header".to_string()));
    }

    let orig_len = u64::from_le_bytes(envelope[4..12].try_into().unwrap()) as usize;
    let shard_len = u32::from_le_bytes(envelope[12..16].try_into().unwrap()) as usize;
    let header_end = 16 + TOTAL_SHARDS * 8;

    if envelope.len() < header_end + TOTAL_SHARDS * shard_len {
        return Err(NxzError::EccError("Truncated ECC1 envelope".to_string()));
    }

    let mut expected_tags = [[0u8; 8]; TOTAL_SHARDS];
    for i in 0..TOTAL_SHARDS {
        let off = 16 + i * 8;
        expected_tags[i].copy_from_slice(&envelope[off..off + 8]);
    }

    let mut opt_shards: Vec<Option<Vec<u8>>> = Vec::with_capacity(TOTAL_SHARDS);
    let mut corrupted_shards = 0usize;

    for i in 0..TOTAL_SHARDS {
        let start = header_end + i * shard_len;
        let slice = &envelope[start..start + shard_len];
        let actual_hash = blake3::hash(slice);

        if actual_hash.as_bytes()[0..8] == expected_tags[i] {
            opt_shards.push(Some(slice.to_vec()));
        } else {
            corrupted_shards += 1;
            opt_shards.push(None);
        }
    }

    if corrupted_shards > 0 {
        let rs = ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
            .map_err(|e| NxzError::EccError(format!("RS init error: {e}")))?;
        rs.reconstruct(&mut opt_shards).map_err(|_| {
            NxzError::EccError(format!(
                "Damage exceeds Reed-Solomon capacity ({corrupted_shards} shards corrupted)"
            ))
        })?;
    }

    let mut recovered = Vec::with_capacity(DATA_SHARDS * shard_len);
    for i in 0..DATA_SHARDS {
        if let Some(ref shard) = opt_shards[i] {
            recovered.extend_from_slice(shard);
        }
    }
    recovered.truncate(orig_len);

    Ok((recovered, corrupted_shards))
}
