use crate::container::{
    ArchiveHeader, BlockDescriptor, FileEntry, SeekableIndexFooter, SeekableIndexFooterV1,
    DEFAULT_MICRO_BLOCK_SIZE, FLAG_ECC_SELF_HEALING, FLAG_ENCRYPTED_AEAD,
    FLAG_HAS_SEEKABLE_FOOTER, HEADER_SIZE_BYTES, NXZ_FORMAT_VERSION, NXZ_MAGIC,
};
use crate::crypto::{decrypt_block_aead, derive_master_key, encrypt_block_aead, FOOTER_AAD_BLOCK_ID, SALT_LEN};
use crate::ecc::{ecc_protect, ecc_verify_and_heal};
use crate::error::NxzError;
use crate::office::{office_refold, office_unfold};
use crate::prefilter::{bcj_x86_decode, bcj_x86_encode, fot_detokenize, fot_tokenize};
use crate::router::{analyze_sample, CodecRoute, CompressionProfile, ROUTER_SAMPLE_SIZE};
use crate::security::{check_decompression_quota, sanitize_extraction_path};
use liblzma::read::{XzDecoder, XzEncoder};
use rand::RngCore;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};
use walkdir::WalkDir;

#[derive(Debug, Default)]
pub struct ProgressTracker {
    pub processed_bytes: AtomicU64,
    pub total_bytes: AtomicU64,
    pub current_item: Mutex<String>,
    pub cancel_requested: AtomicBool,
}

impl ProgressTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn set_item(&self, item: impl Into<String>) {
        if let Ok(mut guard) = self.current_item.lock() {
            *guard = item.into();
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel_requested.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone)]
pub struct PackOptions {
    pub profile: CompressionProfile,
    pub password: Option<String>,
    pub enable_ecc: bool,
    pub progress: Option<Arc<ProgressTracker>>,
}

impl Default for PackOptions {
    fn default() -> Self {
        Self {
            profile: CompressionProfile::Balanced,
            password: None,
            enable_ecc: false,
            progress: None,
        }
    }
}

const MAX_BLOCKS_PER_BATCH: usize = 16;

struct PlannedFile {
    full_path: PathBuf,
    rel_path: String,
    file_size: u64,
    entropy: f32,
    modified_unix_secs: u64,
}

struct RawBlockJob {
    block_id: u32,
    codec_route: CodecRoute,
    raw_payload: Vec<u8>,
}

struct StoredBlockResult {
    block_id: u32,
    codec_route: CodecRoute,
    stored_payload: Vec<u8>,
    uncompressed_size: u64,
    uncompressed_blake3: [u8; 32],
    stored_blake3: [u8; 32],
}

pub fn pack_directory_or_file(
    input_path: &Path,
    output_archive: &Path,
    profile: CompressionProfile,
) -> Result<SeekableIndexFooter, NxzError> {
    pack_with_options(
        input_path,
        output_archive,
        &PackOptions {
            profile,
            password: None,
            enable_ecc: false,
            progress: None,
        },
    )
}

pub fn pack_with_options(
    input_path: &Path,
    output_archive: &Path,
    options: &PackOptions,
) -> Result<SeekableIndexFooter, NxzError> {
    let tmp_archive = PathBuf::from(format!("{}.tmp", output_archive.display()));
    let result = pack_into_temp_archive(input_path, output_archive, &tmp_archive, options);
    match result {
        Ok(footer) => {
            if output_archive.exists() {
                let _ = fs::remove_file(output_archive);
            }
            fs::rename(&tmp_archive, output_archive).map_err(|e| NxzError::IoPath {
                path: output_archive.to_path_buf(),
                source: e,
            })?;
            Ok(footer)
        }
        Err(err) => {
            let _ = fs::remove_file(&tmp_archive);
            Err(err)
        }
    }
}

fn pack_into_temp_archive(
    input_path: &Path,
    output_archive: &Path,
    tmp_archive: &Path,
    options: &PackOptions,
) -> Result<SeekableIndexFooter, NxzError> {
    let tracker = options.progress.as_ref();
    if let Some(t) = tracker {
        if t.is_cancelled() {
            return Err(NxzError::OperationCancelled);
        }
    }

    let mut file_paths: Vec<(PathBuf, String)> = Vec::new();
    if input_path.is_file() {
        let name = input_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file.bin")
            .to_string();
        file_paths.push((input_path.to_path_buf(), name));
    } else {
        for entry in WalkDir::new(input_path).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let full_path = entry.path().to_path_buf();
                if full_path == output_archive || full_path == tmp_archive {
                    continue;
                }
                let rel = full_path
                    .strip_prefix(input_path)
                    .unwrap_or(&full_path)
                    .to_string_lossy()
                    .replace('\\', "/");
                file_paths.push((full_path, rel));
            }
        }
    }
    file_paths.sort_by(|a, b| a.1.cmp(&b.1));

    let mut route_buckets: HashMap<CodecRoute, Vec<PlannedFile>> = HashMap::new();
    let mut planned_total_bytes = 0u64;

    for (full_path, rel_path) in file_paths {
        if let Some(t) = tracker {
            if t.is_cancelled() {
                return Err(NxzError::OperationCancelled);
            }
        }
        let meta = fs::metadata(&full_path).map_err(|e| NxzError::IoPath {
            path: full_path.clone(),
            source: e,
        })?;
        let file_size = meta.len();
        planned_total_bytes += file_size;
        let modified_unix_secs = meta
            .modified()
            .ok()
            .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let sample_len = (file_size as usize).min(ROUTER_SAMPLE_SIZE);
        let mut sample_buf = Vec::with_capacity(sample_len);
        if sample_len > 0 {
            let f = File::open(&full_path).map_err(|e| NxzError::IoPath {
                path: full_path.clone(),
                source: e,
            })?;
            f.take(sample_len as u64)
                .read_to_end(&mut sample_buf)
                .map_err(|e| NxzError::IoPath {
                    path: full_path.clone(),
                    source: e,
                })?;
        }

        let analysis = analyze_sample(&sample_buf, &full_path, options.profile);

        route_buckets
            .entry(analysis.recommended_route)
            .or_default()
            .push(PlannedFile {
                full_path,
                rel_path,
                file_size,
                entropy: analysis.shannon_entropy_bpb as f32,
                modified_unix_secs,
            });
    }

    if let Some(t) = tracker {
        t.total_bytes.store(planned_total_bytes, Ordering::Relaxed);
        t.processed_bytes.store(0, Ordering::Relaxed);
    }

    let mut crypto_salt = [0u8; SALT_LEN];
    let master_key: Option<[u8; 32]> = if let Some(ref pw) = options.password {
        if !pw.is_empty() {
            rand::thread_rng().fill_bytes(&mut crypto_salt);
            Some(derive_master_key(pw, &crypto_salt)?)
        } else {
            None
        }
    } else {
        None
    };

    let enable_ecc = options.enable_ecc;

    let mut out_file = File::create(tmp_archive).map_err(|e| NxzError::IoPath {
        path: tmp_archive.to_path_buf(),
        source: e,
    })?;

    let mut flags = FLAG_HAS_SEEKABLE_FOOTER;
    if master_key.is_some() {
        flags |= FLAG_ENCRYPTED_AEAD;
    }
    if enable_ecc {
        flags |= FLAG_ECC_SELF_HEALING;
    }

    let placeholder = ArchiveHeader {
        magic: NXZ_MAGIC,
        version: NXZ_FORMAT_VERSION,
        flags,
        index_offset: 0,
        index_stored_len: 0,
        index_tag_prefix: [0u8; 8],
        crypto_salt,
    };
    placeholder.write_to(&mut out_file)?;

    let mut current_offset = HEADER_SIZE_BYTES as u64;
    let mut block_descriptors: Vec<BlockDescriptor> = Vec::new();
    let mut total_uncompressed_bytes = 0u64;
    let mut total_stored_bytes = 0u64;

    let mut raw_jobs_batch: Vec<RawBlockJob> = Vec::with_capacity(MAX_BLOCKS_PER_BATCH);
    let mut file_entries: Vec<FileEntry> = Vec::new();
    let mut next_block_id: u32 = 0;
    let mut seen_files: HashMap<[u8; 32], (u32, u64, u64)> = HashMap::new();
    let mut seen_large_sizes: HashSet<u64> = HashSet::new();
    let mut seen_blocks: HashMap<[u8; 32], (CodecRoute, u64, u64, u64, [u8; 32])> = HashMap::new();

    let mut sorted_routes: Vec<CodecRoute> = route_buckets.keys().copied().collect();
    sorted_routes.sort_by_key(|r| *r as u8);

    for route in sorted_routes {
        let items = route_buckets.remove(&route).unwrap_or_default();
        let mut current_block_buf: Vec<u8> = Vec::new();
        let mut current_block_id = next_block_id;

        for item in items {
            if let Some(t) = tracker {
                if t.is_cancelled() {
                    return Err(NxzError::OperationCancelled);
                }
                t.set_item(item.rel_path.clone());
            }

            if item.file_size == 0 {
                let empty_hash = *blake3::hash(&[]).as_bytes();
                file_entries.push(FileEntry {
                    relative_path: item.rel_path,
                    original_size: 0,
                    file_blake3: empty_hash,
                    block_id: current_block_id,
                    offset_in_block: 0,
                    length_in_block: 0,
                    shannon_entropy_bpb: item.entropy,
                    modified_unix_secs: item.modified_unix_secs,
                });
                continue;
            }

            if item.file_size > DEFAULT_MICRO_BLOCK_SIZE as u64 {
                if seen_large_sizes.contains(&item.file_size) {
                    let mut pre_f = File::open(&item.full_path).map_err(|e| NxzError::IoPath {
                        path: item.full_path.clone(),
                        source: e,
                    })?;
                    let mut pre_hasher = blake3::Hasher::new();
                    let mut pre_buf = vec![0u8; 256 * 1024];
                    loop {
                        if let Some(t) = tracker {
                            if t.is_cancelled() {
                                return Err(NxzError::OperationCancelled);
                            }
                        }
                        let n = pre_f.read(&mut pre_buf).map_err(|e| NxzError::IoPath {
                            path: item.full_path.clone(),
                            source: e,
                        })?;
                        if n == 0 {
                            break;
                        }
                        pre_hasher.update(&pre_buf[..n]);
                    }
                    let pre_hash = *pre_hasher.finalize().as_bytes();
                    if let Some(&(existing_block_id, existing_offset, existing_first_chunk_len)) =
                        seen_files.get(&pre_hash)
                    {
                        if let Some(t) = tracker {
                            t.processed_bytes.fetch_add(item.file_size, Ordering::Relaxed);
                        }
                        file_entries.push(FileEntry {
                            relative_path: item.rel_path,
                            original_size: item.file_size,
                            file_blake3: pre_hash,
                            block_id: existing_block_id,
                            offset_in_block: existing_offset,
                            length_in_block: existing_first_chunk_len,
                            shannon_entropy_bpb: item.entropy,
                            modified_unix_secs: item.modified_unix_secs,
                        });
                        continue;
                    }
                }

                if !current_block_buf.is_empty() {
                    raw_jobs_batch.push(RawBlockJob {
                        block_id: current_block_id,
                        codec_route: route,
                        raw_payload: std::mem::take(&mut current_block_buf),
                    });
                    next_block_id += 1;
                    current_block_id = next_block_id;

                    if raw_jobs_batch.len() >= MAX_BLOCKS_PER_BATCH {
                        flush_block_batch(
                            &mut raw_jobs_batch,
                            &mut out_file,
                            &mut current_offset,
                            &mut block_descriptors,
                            &mut total_uncompressed_bytes,
                            &mut total_stored_bytes,
                            &mut seen_blocks,
                            master_key.as_ref(),
                            &crypto_salt,
                            enable_ecc,
                            tracker.map(|v| v.as_ref()),
                        )?;
                    }
                }

                let mut f = File::open(&item.full_path).map_err(|e| NxzError::IoPath {
                    path: item.full_path.clone(),
                    source: e,
                })?;
                let mut hasher = blake3::Hasher::new();
                let first_block_id = current_block_id;
                let mut first_chunk_len = 0u64;
                let mut total_read = 0u64;

                loop {
                    if let Some(t) = tracker {
                        if t.is_cancelled() {
                            return Err(NxzError::OperationCancelled);
                        }
                    }
                    let mut chunk = vec![0u8; DEFAULT_MICRO_BLOCK_SIZE];
                    let mut filled = 0usize;
                    while filled < DEFAULT_MICRO_BLOCK_SIZE {
                        let n = f.read(&mut chunk[filled..]).map_err(|e| NxzError::IoPath {
                            path: item.full_path.clone(),
                            source: e,
                        })?;
                        if n == 0 {
                            break;
                        }
                        filled += n;
                    }
                    if filled == 0 {
                        break;
                    }
                    chunk.truncate(filled);
                    hasher.update(&chunk);
                    if first_chunk_len == 0 {
                        first_chunk_len = filled as u64;
                    }
                    total_read += filled as u64;
                    if let Some(t) = tracker {
                        t.processed_bytes.fetch_add(filled as u64, Ordering::Relaxed);
                    }

                    raw_jobs_batch.push(RawBlockJob {
                        block_id: current_block_id,
                        codec_route: route,
                        raw_payload: chunk,
                    });
                    next_block_id += 1;
                    current_block_id = next_block_id;

                    if raw_jobs_batch.len() >= MAX_BLOCKS_PER_BATCH {
                        flush_block_batch(
                            &mut raw_jobs_batch,
                            &mut out_file,
                            &mut current_offset,
                            &mut block_descriptors,
                            &mut total_uncompressed_bytes,
                            &mut total_stored_bytes,
                            &mut seen_blocks,
                            master_key.as_ref(),
                            &crypto_salt,
                            enable_ecc,
                            tracker.map(|v| v.as_ref()),
                        )?;
                    }
                }

                let file_hash = *hasher.finalize().as_bytes();
                seen_large_sizes.insert(total_read);
                seen_files.insert(file_hash, (first_block_id, 0, first_chunk_len));

                file_entries.push(FileEntry {
                    relative_path: item.rel_path,
                    original_size: total_read,
                    file_blake3: file_hash,
                    block_id: first_block_id,
                    offset_in_block: 0,
                    length_in_block: first_chunk_len,
                    shannon_entropy_bpb: item.entropy,
                    modified_unix_secs: item.modified_unix_secs,
                });
                continue;
            }

            let data = fs::read(&item.full_path).map_err(|e| NxzError::IoPath {
                path: item.full_path.clone(),
                source: e,
            })?;
            let file_hash = *blake3::hash(&data).as_bytes();
            if let Some(t) = tracker {
                t.processed_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
            }

            if let Some(&(existing_block_id, existing_offset, existing_len)) =
                seen_files.get(&file_hash)
            {
                if existing_len == data.len() as u64 {
                    file_entries.push(FileEntry {
                        relative_path: item.rel_path,
                        original_size: existing_len,
                        file_blake3: file_hash,
                        block_id: existing_block_id,
                        offset_in_block: existing_offset,
                        length_in_block: existing_len,
                        shannon_entropy_bpb: item.entropy,
                        modified_unix_secs: item.modified_unix_secs,
                    });
                    continue;
                }
            }

            if !current_block_buf.is_empty()
                && current_block_buf.len() + data.len() > DEFAULT_MICRO_BLOCK_SIZE
            {
                raw_jobs_batch.push(RawBlockJob {
                    block_id: current_block_id,
                    codec_route: route,
                    raw_payload: std::mem::take(&mut current_block_buf),
                });
                next_block_id += 1;
                current_block_id = next_block_id;

                if raw_jobs_batch.len() >= MAX_BLOCKS_PER_BATCH {
                    flush_block_batch(
                        &mut raw_jobs_batch,
                        &mut out_file,
                        &mut current_offset,
                        &mut block_descriptors,
                        &mut total_uncompressed_bytes,
                        &mut total_stored_bytes,
                        &mut seen_blocks,
                        master_key.as_ref(),
                        &crypto_salt,
                        enable_ecc,
                        tracker.map(|v| v.as_ref()),
                    )?;
                }
            }

            if current_block_buf.capacity() == 0 {
                current_block_buf.reserve(DEFAULT_MICRO_BLOCK_SIZE);
            }

            let offset_in_block = current_block_buf.len() as u64;
            let length_in_block = data.len() as u64;
            current_block_buf.extend_from_slice(&data);

            seen_files.insert(file_hash, (current_block_id, offset_in_block, length_in_block));

            file_entries.push(FileEntry {
                relative_path: item.rel_path,
                original_size: length_in_block,
                file_blake3: file_hash,
                block_id: current_block_id,
                offset_in_block,
                length_in_block,
                shannon_entropy_bpb: item.entropy,
                modified_unix_secs: item.modified_unix_secs,
            });
        }

        if !current_block_buf.is_empty() {
            raw_jobs_batch.push(RawBlockJob {
                block_id: current_block_id,
                codec_route: route,
                raw_payload: current_block_buf,
            });
            next_block_id += 1;

            if raw_jobs_batch.len() >= MAX_BLOCKS_PER_BATCH {
                flush_block_batch(
                    &mut raw_jobs_batch,
                    &mut out_file,
                    &mut current_offset,
                    &mut block_descriptors,
                    &mut total_uncompressed_bytes,
                    &mut total_stored_bytes,
                    &mut seen_blocks,
                    master_key.as_ref(),
                    &crypto_salt,
                    enable_ecc,
                    tracker.map(|v| v.as_ref()),
                )?;
            }
        }
    }

    flush_block_batch(
        &mut raw_jobs_batch,
        &mut out_file,
        &mut current_offset,
        &mut block_descriptors,
        &mut total_uncompressed_bytes,
        &mut total_stored_bytes,
        &mut seen_blocks,
        master_key.as_ref(),
        &crypto_salt,
        enable_ecc,
        tracker.map(|v| v.as_ref()),
    )?;

    let total_files_original_bytes: u64 = file_entries.iter().map(|f| f.original_size).sum();

    let footer = SeekableIndexFooter {
        total_files: file_entries.len() as u64,
        total_uncompressed_bytes: total_files_original_bytes.max(total_uncompressed_bytes),
        total_stored_bytes,
        encrypted: master_key.is_some(),
        ecc_enabled: enable_ecc,
        blocks: block_descriptors,
        files: file_entries,
    };

    let serialized_footer = bincode::serialize(&footer)?;
    let mut footer_blob = zstd::encode_all(serialized_footer.as_slice(), 9)?;

    if let Some(ref key) = master_key {
        footer_blob = encrypt_block_aead(&footer_blob, key, &crypto_salt, FOOTER_AAD_BLOCK_ID)?;
    }
    if enable_ecc {
        footer_blob = ecc_protect(&footer_blob)?;
    }

    let footer_hash = blake3::hash(&footer_blob);
    let index_offset = current_offset;
    let index_stored_len = footer_blob.len() as u64;
    out_file.write_all(&footer_blob)?;

    let mut tag_prefix = [0u8; 8];
    tag_prefix.copy_from_slice(&footer_hash.as_bytes()[0..8]);

    let final_header = ArchiveHeader {
        magic: NXZ_MAGIC,
        version: NXZ_FORMAT_VERSION,
        flags,
        index_offset,
        index_stored_len,
        index_tag_prefix: tag_prefix,
        crypto_salt,
    };

    out_file.seek(SeekFrom::Start(0))?;
    final_header.write_to(&mut out_file)?;
    out_file.flush()?;

    Ok(footer)
}

pub fn read_archive_index_with_password(
    archive_path: &Path,
    password: Option<&str>,
) -> Result<(ArchiveHeader, SeekableIndexFooter, Option<[u8; 32]>), NxzError> {
    let mut file = File::open(archive_path).map_err(|e| NxzError::IoPath {
        path: archive_path.to_path_buf(),
        source: e,
    })?;

    let header = ArchiveHeader::read_from(&mut file)?;
    file.seek(SeekFrom::Start(header.index_offset))?;

    let mut footer_blob = vec![0u8; header.index_stored_len as usize];
    file.read_exact(&mut footer_blob)?;

    if (header.flags & FLAG_ECC_SELF_HEALING) != 0 {
        let (healed, _healed_shards) = ecc_verify_and_heal(&footer_blob)?;
        footer_blob = healed;
    } else {
        let actual_hash = blake3::hash(&footer_blob);
        if actual_hash.as_bytes()[0..8] != header.index_tag_prefix {
            return Err(NxzError::IntegrityMismatch {
                context: "Seekable Index Footer".to_string(),
                expected: format!("{:02x?}", header.index_tag_prefix),
                actual: format!("{:02x?}", &actual_hash.as_bytes()[0..8]),
            });
        }
    }

    let master_key = if (header.flags & FLAG_ENCRYPTED_AEAD) != 0 {
        let pw = password.filter(|s| !s.is_empty()).ok_or(NxzError::PasswordRequired)?;
        let key = derive_master_key(pw, &header.crypto_salt)?;
        footer_blob = decrypt_block_aead(&footer_blob, &key, &header.crypto_salt, FOOTER_AAD_BLOCK_ID)?;
        Some(key)
    } else {
        None
    };

    let raw_footer_bytes = zstd::decode_all(footer_blob.as_slice())?;
    let footer: SeekableIndexFooter = if header.version == 1 {
        let v1 = bincode::deserialize::<SeekableIndexFooterV1>(&raw_footer_bytes)?;
        SeekableIndexFooter {
            total_files: v1.total_files,
            total_uncompressed_bytes: v1.total_uncompressed_bytes,
            total_stored_bytes: v1.total_stored_bytes,
            encrypted: v1.encrypted,
            ecc_enabled: v1.ecc_enabled,
            blocks: v1.blocks,
            files: v1
                .files
                .into_iter()
                .map(|f| FileEntry {
                    relative_path: f.relative_path,
                    original_size: f.original_size,
                    file_blake3: f.file_blake3,
                    block_id: f.block_id,
                    offset_in_block: f.offset_in_block,
                    length_in_block: f.length_in_block,
                    shannon_entropy_bpb: f.shannon_entropy_bpb,
                    modified_unix_secs: 0,
                })
                .collect(),
        }
    } else if header.version == 2 {
        bincode::deserialize::<SeekableIndexFooter>(&raw_footer_bytes)?
    } else {
        return Err(NxzError::UnsupportedVersion(header.version));
    };
    Ok((header, footer, master_key))
}

pub fn read_archive_index(archive_path: &Path) -> Result<SeekableIndexFooter, NxzError> {
    let (_, footer, _) = read_archive_index_with_password(archive_path, None)?;
    Ok(footer)
}

pub fn unpack_all_with_password(
    archive_path: &Path,
    output_dir: &Path,
    password: Option<&str>,
) -> Result<(SeekableIndexFooter, usize), NxzError> {
    unpack_all_with_progress(archive_path, output_dir, password, None)
}

pub fn unpack_all_with_progress(
    archive_path: &Path,
    output_dir: &Path,
    password: Option<&str>,
    tracker: Option<&ProgressTracker>,
) -> Result<(SeekableIndexFooter, usize), NxzError> {
    if let Some(t) = tracker {
        if t.is_cancelled() {
            return Err(NxzError::OperationCancelled);
        }
    }
    let (header, footer, master_key) = read_archive_index_with_password(archive_path, password)?;
    if let Some(t) = tracker {
        t.total_bytes
            .store(footer.total_uncompressed_bytes, Ordering::Relaxed);
        t.processed_bytes.store(0, Ordering::Relaxed);
    }
    fs::create_dir_all(output_dir)?;

    let mut archive_file = File::open(archive_path)?;
    let mut raw_blocks: Vec<(BlockDescriptor, Vec<u8>)> = Vec::with_capacity(footer.blocks.len());

    for block in &footer.blocks {
        if let Some(t) = tracker {
            if t.is_cancelled() {
                return Err(NxzError::OperationCancelled);
            }
        }
        check_decompression_quota(block.stored_size, block.uncompressed_size)?;
        archive_file.seek(SeekFrom::Start(block.archive_byte_offset))?;
        let mut buf = vec![0u8; block.stored_size as usize];
        archive_file.read_exact(&mut buf)?;
        raw_blocks.push((block.clone(), buf));
    }

    let ecc_enabled = (header.flags & FLAG_ECC_SELF_HEALING) != 0;
    let salt = header.crypto_salt;

    let decoded_results: Vec<(u32, Vec<u8>, usize)> = raw_blocks
        .into_par_iter()
        .map(|(desc, stored_bytes)| {
            if let Some(t) = tracker {
                if t.is_cancelled() {
                    return Err(NxzError::OperationCancelled);
                }
            }
            let (plain, healed_count) = restore_and_decompress_block(
                &desc,
                &stored_bytes,
                master_key.as_ref(),
                &salt,
                ecc_enabled,
            )?;
            Ok((desc.block_id, plain, healed_count))
        })
        .collect::<Result<Vec<_>, NxzError>>()?;

    let mut total_healed_shards = 0usize;
    let mut decompressed_blocks: HashMap<u32, Vec<u8>> = HashMap::with_capacity(decoded_results.len());
    for (id, plain, healed) in decoded_results {
        total_healed_shards += healed;
        decompressed_blocks.insert(id, plain);
    }

    for entry in &footer.files {
        if let Some(t) = tracker {
            if t.is_cancelled() {
                return Err(NxzError::OperationCancelled);
            }
            t.set_item(entry.relative_path.clone());
        }

        let safe_target_path = sanitize_extraction_path(output_dir, &entry.relative_path)?;
        if let Some(parent) = safe_target_path.parent() {
            fs::create_dir_all(parent)?;
        }

        if entry.length_in_block == 0 || entry.original_size == 0 {
            fs::write(&safe_target_path, &[]).map_err(|e| NxzError::IoPath {
                path: safe_target_path.clone(),
                source: e,
            })?;
            restore_file_mtime(&safe_target_path, entry.modified_unix_secs);
            continue;
        }

        if entry.original_size > entry.length_in_block {
            let mut out_f = File::create(&safe_target_path).map_err(|e| NxzError::IoPath {
                path: safe_target_path.clone(),
                source: e,
            })?;
            let mut hasher = blake3::Hasher::new();
            let mut remaining = entry.original_size;
            let mut cur_block_id = entry.block_id;

            while remaining > 0 {
                if let Some(t) = tracker {
                    if t.is_cancelled() {
                        return Err(NxzError::OperationCancelled);
                    }
                }
                let block_buf = decompressed_blocks
                    .get(&cur_block_id)
                    .ok_or_else(|| NxzError::FileNotFoundInArchive(entry.relative_path.clone()))?;
                let take_len = (remaining as usize).min(block_buf.len());
                let slice = &block_buf[..take_len];
                hasher.update(slice);
                out_f.write_all(slice).map_err(|e| NxzError::IoPath {
                    path: safe_target_path.clone(),
                    source: e,
                })?;
                remaining -= take_len as u64;
                cur_block_id += 1;
                if let Some(t) = tracker {
                    t.processed_bytes.fetch_add(take_len as u64, Ordering::Relaxed);
                }
            }
            out_f.flush().map_err(|e| NxzError::IoPath {
                path: safe_target_path.clone(),
                source: e,
            })?;
            drop(out_f);

            let actual_file_hash = *hasher.finalize().as_bytes();
            if actual_file_hash != entry.file_blake3 {
                return Err(NxzError::IntegrityMismatch {
                    context: entry.relative_path.clone(),
                    expected: hex_preview(&entry.file_blake3),
                    actual: hex_preview(&actual_file_hash),
                });
            }
            restore_file_mtime(&safe_target_path, entry.modified_unix_secs);
            continue;
        }

        let block_buf = decompressed_blocks
            .get(&entry.block_id)
            .ok_or_else(|| NxzError::FileNotFoundInArchive(entry.relative_path.clone()))?;

        let start = entry.offset_in_block as usize;
        let end = start + (entry.length_in_block as usize);
        let file_slice = &block_buf[start..end];

        let actual_file_hash = *blake3::hash(file_slice).as_bytes();
        if actual_file_hash != entry.file_blake3 {
            return Err(NxzError::IntegrityMismatch {
                context: entry.relative_path.clone(),
                expected: hex_preview(&entry.file_blake3),
                actual: hex_preview(&actual_file_hash),
            });
        }

        fs::write(&safe_target_path, file_slice).map_err(|e| NxzError::IoPath {
            path: safe_target_path.clone(),
            source: e,
        })?;
        restore_file_mtime(&safe_target_path, entry.modified_unix_secs);
        if let Some(t) = tracker {
            t.processed_bytes
                .fetch_add(entry.original_size, Ordering::Relaxed);
        }
    }

    Ok((footer, total_healed_shards))
}

pub fn unpack_all(archive_path: &Path, output_dir: &Path) -> Result<SeekableIndexFooter, NxzError> {
    let (footer, _) = unpack_all_with_password(archive_path, output_dir, None)?;
    Ok(footer)
}

pub fn extract_single_file_with_password(
    archive_path: &Path,
    target_rel_path: &str,
    output_dir: &Path,
    password: Option<&str>,
) -> Result<PathBuf, NxzError> {
    let (header, footer, master_key) = read_archive_index_with_password(archive_path, password)?;
    let entry = footer
        .files
        .iter()
        .find(|f| f.relative_path == target_rel_path)
        .ok_or_else(|| NxzError::FileNotFoundInArchive(target_rel_path.to_string()))?;

    if entry.length_in_block == 0 || entry.original_size == 0 {
        let safe_target = sanitize_extraction_path(output_dir, &entry.relative_path)?;
        if let Some(parent) = safe_target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&safe_target, &[])?;
        restore_file_mtime(&safe_target, entry.modified_unix_secs);
        return Ok(safe_target);
    }

    if entry.original_size > entry.length_in_block {
        let safe_target = sanitize_extraction_path(output_dir, &entry.relative_path)?;
        if let Some(parent) = safe_target.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out_f = File::create(&safe_target)?;
        let mut hasher = blake3::Hasher::new();
        let mut remaining = entry.original_size;
        let mut cur_block_id = entry.block_id;
        let mut archive_file = File::open(archive_path)?;
        let ecc_enabled = (header.flags & FLAG_ECC_SELF_HEALING) != 0;

        while remaining > 0 {
            let block_desc = footer
                .blocks
                .iter()
                .find(|b| b.block_id == cur_block_id)
                .ok_or_else(|| NxzError::FileNotFoundInArchive(target_rel_path.to_string()))?;

            check_decompression_quota(block_desc.stored_size, block_desc.uncompressed_size)?;
            archive_file.seek(SeekFrom::Start(block_desc.archive_byte_offset))?;
            let mut stored_bytes = vec![0u8; block_desc.stored_size as usize];
            archive_file.read_exact(&mut stored_bytes)?;

            let (plain_block, _) = restore_and_decompress_block(
                block_desc,
                &stored_bytes,
                master_key.as_ref(),
                &header.crypto_salt,
                ecc_enabled,
            )?;

            let take_len = (remaining as usize).min(plain_block.len());
            let slice = &plain_block[..take_len];
            hasher.update(slice);
            out_f.write_all(slice)?;
            remaining -= take_len as u64;
            cur_block_id += 1;
        }
        out_f.flush()?;
        drop(out_f);

        let actual_hash = *hasher.finalize().as_bytes();
        if actual_hash != entry.file_blake3 {
            return Err(NxzError::IntegrityMismatch {
                context: entry.relative_path.clone(),
                expected: hex_preview(&entry.file_blake3),
                actual: hex_preview(&actual_hash),
            });
        }
        restore_file_mtime(&safe_target, entry.modified_unix_secs);
        return Ok(safe_target);
    }

    let block_desc = footer
        .blocks
        .iter()
        .find(|b| b.block_id == entry.block_id)
        .ok_or_else(|| NxzError::FileNotFoundInArchive(target_rel_path.to_string()))?;

    check_decompression_quota(block_desc.stored_size, block_desc.uncompressed_size)?;

    let mut archive_file = File::open(archive_path)?;
    archive_file.seek(SeekFrom::Start(block_desc.archive_byte_offset))?;
    let mut stored_bytes = vec![0u8; block_desc.stored_size as usize];
    archive_file.read_exact(&mut stored_bytes)?;

    let ecc_enabled = (header.flags & FLAG_ECC_SELF_HEALING) != 0;
    let (plain_block, _) = restore_and_decompress_block(
        block_desc,
        &stored_bytes,
        master_key.as_ref(),
        &header.crypto_salt,
        ecc_enabled,
    )?;

    let start = entry.offset_in_block as usize;
    let end = start + (entry.length_in_block as usize);
    let file_slice = &plain_block[start..end];

    let actual_hash = *blake3::hash(file_slice).as_bytes();
    if actual_hash != entry.file_blake3 {
        return Err(NxzError::IntegrityMismatch {
            context: entry.relative_path.clone(),
            expected: hex_preview(&entry.file_blake3),
            actual: hex_preview(&actual_hash),
        });
    }

    let safe_target = sanitize_extraction_path(output_dir, &entry.relative_path)?;
    if let Some(parent) = safe_target.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&safe_target, file_slice)?;
    restore_file_mtime(&safe_target, entry.modified_unix_secs);

    Ok(safe_target)
}

pub fn extract_single_file(
    archive_path: &Path,
    target_rel_path: &str,
    output_dir: &Path,
) -> Result<PathBuf, NxzError> {
    extract_single_file_with_password(archive_path, target_rel_path, output_dir, None)
}

pub fn verify_archive_integrity(
    archive_path: &Path,
    password: Option<&str>,
) -> Result<(u64, u64, usize), NxzError> {
    verify_archive_integrity_with_progress(archive_path, password, None)
}

pub fn verify_archive_integrity_with_progress(
    archive_path: &Path,
    password: Option<&str>,
    tracker: Option<&ProgressTracker>,
) -> Result<(u64, u64, usize), NxzError> {
    if let Some(t) = tracker {
        if t.is_cancelled() {
            return Err(NxzError::OperationCancelled);
        }
    }
    let (header, footer, master_key) = read_archive_index_with_password(archive_path, password)?;
    if let Some(t) = tracker {
        t.total_bytes
            .store(footer.total_uncompressed_bytes, Ordering::Relaxed);
        t.processed_bytes.store(0, Ordering::Relaxed);
    }
    let mut archive_file = File::open(archive_path).map_err(|e| NxzError::IoPath {
        path: archive_path.to_path_buf(),
        source: e,
    })?;

    let mut raw_blocks: Vec<(BlockDescriptor, Vec<u8>)> = Vec::with_capacity(footer.blocks.len());
    for block in &footer.blocks {
        if let Some(t) = tracker {
            if t.is_cancelled() {
                return Err(NxzError::OperationCancelled);
            }
        }
        check_decompression_quota(block.stored_size, block.uncompressed_size)?;
        archive_file.seek(SeekFrom::Start(block.archive_byte_offset))?;
        let mut buf = vec![0u8; block.stored_size as usize];
        archive_file.read_exact(&mut buf)?;
        raw_blocks.push((block.clone(), buf));
    }

    let ecc_enabled = (header.flags & FLAG_ECC_SELF_HEALING) != 0;
    let salt = header.crypto_salt;

    let decoded_results: Vec<(u32, Vec<u8>, usize)> = raw_blocks
        .into_par_iter()
        .map(|(desc, stored_bytes)| {
            if let Some(t) = tracker {
                if t.is_cancelled() {
                    return Err(NxzError::OperationCancelled);
                }
            }
            let (plain, healed_count) = restore_and_decompress_block(
                &desc,
                &stored_bytes,
                master_key.as_ref(),
                &salt,
                ecc_enabled,
            )?;
            Ok((desc.block_id, plain, healed_count))
        })
        .collect::<Result<Vec<_>, NxzError>>()?;

    let mut total_healed_shards = 0usize;
    let mut decompressed_blocks: HashMap<u32, Vec<u8>> = HashMap::with_capacity(decoded_results.len());
    for (id, plain, healed) in decoded_results {
        total_healed_shards += healed;
        decompressed_blocks.insert(id, plain);
    }

    let mut verified_bytes = 0u64;
    for entry in &footer.files {
        if let Some(t) = tracker {
            if t.is_cancelled() {
                return Err(NxzError::OperationCancelled);
            }
            t.set_item(entry.relative_path.clone());
        }
        if entry.length_in_block == 0 || entry.original_size == 0 {
            let empty_hash = *blake3::hash(&[]).as_bytes();
            if empty_hash != entry.file_blake3 {
                return Err(NxzError::IntegrityMismatch {
                    context: entry.relative_path.clone(),
                    expected: hex_preview(&entry.file_blake3),
                    actual: hex_preview(&empty_hash),
                });
            }
            continue;
        }

        if entry.original_size > entry.length_in_block {
            let mut hasher = blake3::Hasher::new();
            let mut remaining = entry.original_size;
            let mut cur_block_id = entry.block_id;
            while remaining > 0 {
                if let Some(t) = tracker {
                    if t.is_cancelled() {
                        return Err(NxzError::OperationCancelled);
                    }
                }
                let block_buf = decompressed_blocks
                    .get(&cur_block_id)
                    .ok_or_else(|| NxzError::FileNotFoundInArchive(entry.relative_path.clone()))?;
                let take_len = (remaining as usize).min(block_buf.len());
                hasher.update(&block_buf[..take_len]);
                remaining -= take_len as u64;
                cur_block_id += 1;
            }
            let actual_hash = *hasher.finalize().as_bytes();
            if actual_hash != entry.file_blake3 {
                return Err(NxzError::IntegrityMismatch {
                    context: entry.relative_path.clone(),
                    expected: hex_preview(&entry.file_blake3),
                    actual: hex_preview(&actual_hash),
                });
            }
            verified_bytes += entry.original_size;
            if let Some(t) = tracker {
                t.processed_bytes
                    .fetch_add(entry.original_size, Ordering::Relaxed);
            }
            continue;
        }

        let block_buf = decompressed_blocks
            .get(&entry.block_id)
            .ok_or_else(|| NxzError::FileNotFoundInArchive(entry.relative_path.clone()))?;
        let start = entry.offset_in_block as usize;
        let end = start + (entry.length_in_block as usize);
        let file_slice = &block_buf[start..end];
        let actual_hash = *blake3::hash(file_slice).as_bytes();
        if actual_hash != entry.file_blake3 {
            return Err(NxzError::IntegrityMismatch {
                context: entry.relative_path.clone(),
                expected: hex_preview(&entry.file_blake3),
                actual: hex_preview(&actual_hash),
            });
        }
        verified_bytes += entry.original_size;
        if let Some(t) = tracker {
            t.processed_bytes
                .fetch_add(entry.original_size, Ordering::Relaxed);
        }
    }

    Ok((footer.total_files, verified_bytes, total_healed_shards))
}

fn restore_file_mtime(path: &Path, modified_unix_secs: u64) {
    if modified_unix_secs == 0 {
        return;
    }
    if let Ok(file) = fs::OpenOptions::new().write(true).open(path) {
        let mtime = UNIX_EPOCH + Duration::from_secs(modified_unix_secs);
        let _ = file.set_modified(mtime);
    }
}

fn flush_block_batch(
    batch: &mut Vec<RawBlockJob>,
    out_file: &mut File,
    current_offset: &mut u64,
    block_descriptors: &mut Vec<BlockDescriptor>,
    total_uncompressed_bytes: &mut u64,
    total_stored_bytes: &mut u64,
    seen_blocks: &mut HashMap<[u8; 32], (CodecRoute, u64, u64, u64, [u8; 32])>,
    master_key: Option<&[u8; 32]>,
    crypto_salt: &[u8; SALT_LEN],
    enable_ecc: bool,
    tracker: Option<&ProgressTracker>,
) -> Result<(), NxzError> {
    if batch.is_empty() {
        return Ok(());
    }
    if let Some(t) = tracker {
        if t.is_cancelled() {
            return Err(NxzError::OperationCancelled);
        }
    }
    let jobs = std::mem::take(batch);
    let mut stored_results: Vec<StoredBlockResult> = jobs
        .into_par_iter()
        .map(|job| {
            if let Some(t) = tracker {
                if t.is_cancelled() {
                    return Err(NxzError::OperationCancelled);
                }
            }
            process_and_store_block(job, master_key, crypto_salt, enable_ecc)
        })
        .collect::<Result<Vec<_>, NxzError>>()?;

    stored_results.sort_by_key(|r| r.block_id);

    for res in stored_results {
        if master_key.is_none() {
            if let Some(&(existing_route, existing_offset, existing_stored_len, existing_uncomp_size, existing_stored_hash)) =
                seen_blocks.get(&res.uncompressed_blake3)
            {
                if existing_uncomp_size == res.uncompressed_size {
                    block_descriptors.push(BlockDescriptor {
                        block_id: res.block_id,
                        codec_route: existing_route,
                        archive_byte_offset: existing_offset,
                        stored_size: existing_stored_len,
                        uncompressed_size: res.uncompressed_size,
                        uncompressed_blake3: res.uncompressed_blake3,
                        stored_blake3: existing_stored_hash,
                    });
                    *total_uncompressed_bytes += res.uncompressed_size;
                    continue;
                }
            }
        }

        out_file.write_all(&res.stored_payload)?;
        let stored_len = res.stored_payload.len() as u64;

        if master_key.is_none() {
            seen_blocks.insert(
                res.uncompressed_blake3,
                (
                    res.codec_route,
                    *current_offset,
                    stored_len,
                    res.uncompressed_size,
                    res.stored_blake3,
                ),
            );
        }

        block_descriptors.push(BlockDescriptor {
            block_id: res.block_id,
            codec_route: res.codec_route,
            archive_byte_offset: *current_offset,
            stored_size: stored_len,
            uncompressed_size: res.uncompressed_size,
            uncompressed_blake3: res.uncompressed_blake3,
            stored_blake3: res.stored_blake3,
        });

        *current_offset += stored_len;
        *total_uncompressed_bytes += res.uncompressed_size;
        *total_stored_bytes += stored_len;
    }
    Ok(())
}

fn process_and_store_block(
    job: RawBlockJob,
    master_key: Option<&[u8; 32]>,
    salt: &[u8; SALT_LEN],
    enable_ecc: bool,
) -> Result<StoredBlockResult, NxzError> {
    let uncompressed_size = job.raw_payload.len() as u64;
    let uncompressed_blake3 = *blake3::hash(&job.raw_payload).as_bytes();

    if job.codec_route == CodecRoute::BypassPassthrough {
        let mut payload = job.raw_payload;
        if let Some(key) = master_key {
            payload = encrypt_block_aead(&payload, key, salt, job.block_id)?;
        }
        if enable_ecc {
            payload = ecc_protect(&payload)?;
        }
        let stored_blake3 = *blake3::hash(&payload).as_bytes();
        return Ok(StoredBlockResult {
            block_id: job.block_id,
            codec_route: CodecRoute::BypassPassthrough,
            stored_payload: payload,
            uncompressed_size,
            uncompressed_blake3,
            stored_blake3,
        });
    }

    let (mut effective_route, mut payload) = match job.codec_route {
        CodecRoute::BypassPassthrough => unreachable!(),
        CodecRoute::HighSpeedZstd => {
            let comp = zstd::encode_all(job.raw_payload.as_slice(), 3)?;
            (CodecRoute::HighSpeedZstd, comp)
        }
        CodecRoute::TextFotZstd => {
            let tokenized = fot_tokenize(&job.raw_payload);
            let comp = zstd::encode_all(tokenized.as_slice(), 9)?;
            (CodecRoute::TextFotZstd, comp)
        }
        CodecRoute::TextFotLzma2 => {
            let tokenized = fot_tokenize(&job.raw_payload);
            let comp = lzma2_compress(&tokenized, 6)?;
            (CodecRoute::TextFotLzma2, comp)
        }
        CodecRoute::ExecutableBcjZstd => {
            let filtered = bcj_x86_encode(&job.raw_payload);
            let comp = zstd::encode_all(filtered.as_slice(), 9)?;
            (CodecRoute::ExecutableBcjZstd, comp)
        }
        CodecRoute::ExecutableBcjLzma2 => {
            let filtered = bcj_x86_encode(&job.raw_payload);
            let comp = lzma2_compress(&filtered, 6)?;
            (CodecRoute::ExecutableBcjLzma2, comp)
        }
        CodecRoute::GeneralZstd => {
            let comp = zstd::encode_all(job.raw_payload.as_slice(), 6)?;
            (CodecRoute::GeneralZstd, comp)
        }
        CodecRoute::GeneralLzma2 => {
            let comp = lzma2_compress(&job.raw_payload, 6)?;
            (CodecRoute::GeneralLzma2, comp)
        }
        CodecRoute::OfficeFotZstd => {
            let unfolded = office_unfold(&job.raw_payload);
            let tokenized = fot_tokenize(&unfolded);
            let comp = zstd::encode_all(tokenized.as_slice(), 9)?;
            (CodecRoute::OfficeFotZstd, comp)
        }
        CodecRoute::OfficeFotLzma2 => {
            let unfolded = office_unfold(&job.raw_payload);
            let tokenized = fot_tokenize(&unfolded);
            let comp = lzma2_compress(&tokenized, 6)?;
            (CodecRoute::OfficeFotLzma2, comp)
        }
        CodecRoute::ReservedNeuralPmatic => return Err(NxzError::NeuralCodecNotLoaded),
    };

    if payload.len() >= job.raw_payload.len() {
        effective_route = CodecRoute::BypassPassthrough;
        payload = job.raw_payload;
    }

    if let Some(key) = master_key {
        payload = encrypt_block_aead(&payload, key, salt, job.block_id)?;
    }

    if enable_ecc {
        payload = ecc_protect(&payload)?;
    }

    let stored_blake3 = *blake3::hash(&payload).as_bytes();

    Ok(StoredBlockResult {
        block_id: job.block_id,
        codec_route: effective_route,
        stored_payload: payload,
        uncompressed_size,
        uncompressed_blake3,
        stored_blake3,
    })
}

fn restore_and_decompress_block(
    desc: &BlockDescriptor,
    stored_bytes: &[u8],
    master_key: Option<&[u8; 32]>,
    salt: &[u8; SALT_LEN],
    ecc_enabled: bool,
) -> Result<(Vec<u8>, usize), NxzError> {
    let mut working_bytes: Vec<u8>;
    let mut healed_shards = 0usize;

    if ecc_enabled {
        let (healed, count) = ecc_verify_and_heal(stored_bytes)?;
        working_bytes = healed;
        healed_shards = count;
    } else {
        let actual_stored_hash = *blake3::hash(stored_bytes).as_bytes();
        if actual_stored_hash != desc.stored_blake3 {
            return Err(NxzError::IntegrityMismatch {
                context: format!("Stored Block #{}", desc.block_id),
                expected: hex_preview(&desc.stored_blake3),
                actual: hex_preview(&actual_stored_hash),
            });
        }
        working_bytes = stored_bytes.to_vec();
    }

    if let Some(key) = master_key {
        working_bytes = decrypt_block_aead(&working_bytes, key, salt, desc.block_id)?;
    }

    let plain = match desc.codec_route {
        CodecRoute::BypassPassthrough => working_bytes,
        CodecRoute::HighSpeedZstd | CodecRoute::GeneralZstd => zstd::decode_all(working_bytes.as_slice())?,
        CodecRoute::TextFotZstd => {
            let tokenized = zstd::decode_all(working_bytes.as_slice())?;
            fot_detokenize(&tokenized)
        }
        CodecRoute::TextFotLzma2 => {
            let tokenized = lzma2_decompress(&working_bytes)?;
            fot_detokenize(&tokenized)
        }
        CodecRoute::ExecutableBcjZstd => {
            let filtered = zstd::decode_all(working_bytes.as_slice())?;
            bcj_x86_decode(&filtered)
        }
        CodecRoute::ExecutableBcjLzma2 => {
            let filtered = lzma2_decompress(&working_bytes)?;
            bcj_x86_decode(&filtered)
        }
        CodecRoute::GeneralLzma2 => lzma2_decompress(&working_bytes)?,
        CodecRoute::OfficeFotZstd => {
            let tokenized = zstd::decode_all(working_bytes.as_slice())?;
            let unfolded = fot_detokenize(&tokenized);
            office_refold(&unfolded)?
        }
        CodecRoute::OfficeFotLzma2 => {
            let tokenized = lzma2_decompress(&working_bytes)?;
            let unfolded = fot_detokenize(&tokenized);
            office_refold(&unfolded)?
        }
        CodecRoute::ReservedNeuralPmatic => return Err(NxzError::NeuralCodecNotLoaded),
    };

    let actual_plain_hash = *blake3::hash(&plain).as_bytes();
    if actual_plain_hash != desc.uncompressed_blake3 {
        return Err(NxzError::IntegrityMismatch {
            context: format!("Decompressed Block #{}", desc.block_id),
            expected: hex_preview(&desc.uncompressed_blake3),
            actual: hex_preview(&actual_plain_hash),
        });
    }

    Ok((plain, healed_shards))
}

fn lzma2_compress(input: &[u8], level: u32) -> std::io::Result<Vec<u8>> {
    let mut encoder = XzEncoder::new(input, level);
    let mut out = Vec::new();
    encoder.read_to_end(&mut out)?;
    Ok(out)
}

fn lzma2_decompress(input: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut decoder = XzDecoder::new(input);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

fn hex_preview(hash: &[u8; 32]) -> String {
    hash.iter().take(8).map(|b| format!("{:02x}", b)).collect()
}
