use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NxzError {
    #[error("I/O error while accessing '{path}': {source}")]
    IoPath {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("I/O operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid NXZ archive magic bytes or unsupported format version")]
    InvalidMagicOrVersion,
    #[error("Unsupported NXZ archive format version: {0}")]
    UnsupportedVersion(u16),
    #[error("Integrity check failed for {context}: expected BLAKE3 {expected}, got {actual}")]
    IntegrityMismatch {
        context: String,
        expected: String,
        actual: String,
    },
    #[error("Security sandbox violation (Path Traversal blocked): '{0}'")]
    PathTraversalBlocked(String),
    #[error("Security sandbox violation (Decompression Bomb Guard triggered): block expands from {compressed} B to {uncompressed} B (ratio {ratio:.1}x exceeds limit)")]
    DecompressionBombDetected {
        compressed: u64,
        uncompressed: u64,
        ratio: f64,
    },
    #[error("Serialization/Deserialization error in archive metadata: {0}")]
    Serialization(#[from] Box<bincode::ErrorKind>),
    #[error("Cryptography / Authentication error: {0}")]
    CryptoError(String),
    #[error("Archive is encrypted — a password is required to unlock it")]
    PasswordRequired,
    #[error("Reed-Solomon Self-Healing (ECC) error: {0}")]
    EccError(String),
    #[error("Phase-2 Neural Codec (0x10 PMATIC-LLM) encountered, but Phase-2 module is not loaded")]
    NeuralCodecNotLoaded,
    #[error("Requested file '{0}' not found in archive index")]
    FileNotFoundInArchive(String),
    #[error("Vorgang vom Benutzer abgebrochen")]
    OperationCancelled,
}
