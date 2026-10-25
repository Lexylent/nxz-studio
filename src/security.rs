use crate::error::NxzError;
use std::path::{Component, Path, PathBuf};

pub const MAX_SAFE_EXPANSION_RATIO: f64 = 1200.0;

pub fn sanitize_extraction_path(base_dir: &Path, archive_rel_path: &str) -> Result<PathBuf, NxzError> {
    if archive_rel_path.contains('\0') {
        return Err(NxzError::PathTraversalBlocked(archive_rel_path.to_string()));
    }
    let candidate = Path::new(archive_rel_path);
    let mut clean_relative = PathBuf::new();

    for component in candidate.components() {
        match component {
            Component::Normal(part) => {
                let s = part.to_string_lossy();
                if s.is_empty() || s == "." || s == ".." {
                    return Err(NxzError::PathTraversalBlocked(archive_rel_path.to_string()));
                }
                clean_relative.push(part);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(NxzError::PathTraversalBlocked(archive_rel_path.to_string()));
            }
        }
    }

    if clean_relative.as_os_str().is_empty() {
        return Err(NxzError::PathTraversalBlocked(archive_rel_path.to_string()));
    }
    Ok(base_dir.join(clean_relative))
}

pub fn check_decompression_quota(compressed_size: u64, uncompressed_size: u64) -> Result<(), NxzError> {
    if compressed_size == 0 && uncompressed_size > 0 {
        return Err(NxzError::DecompressionBombDetected {
            compressed: compressed_size,
            uncompressed: uncompressed_size,
            ratio: f64::INFINITY,
        });
    }
    if uncompressed_size > 32 * 1024 * 1024 {
        let ratio = (uncompressed_size as f64) / (compressed_size.max(1) as f64);
        if ratio > MAX_SAFE_EXPANSION_RATIO {
            return Err(NxzError::DecompressionBombDetected {
                compressed: compressed_size,
                uncompressed: uncompressed_size,
                ratio,
            });
        }
    }
    Ok(())
}
