use crate::error::NxzError;
use crate::router::CodecRoute;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

pub const NXZ_MAGIC: [u8; 4] = *b"NXZ\x01";
pub const NXZ_FORMAT_VERSION: u16 = 2;
pub const HEADER_SIZE_BYTES: usize = 64;
pub const DEFAULT_MICRO_BLOCK_SIZE: usize = 16 * 1024 * 1024;

pub const FLAG_HAS_SEEKABLE_FOOTER: u16 = 0x0001;
pub const FLAG_ENCRYPTED_AEAD: u16 = 0x0002;
pub const FLAG_ECC_SELF_HEALING: u16 = 0x0004;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ArchiveHeader {
    pub magic: [u8; 4],
    pub version: u16,
    pub flags: u16,
    pub index_offset: u64,
    pub index_stored_len: u64,
    pub index_tag_prefix: [u8; 8],
    pub crypto_salt: [u8; 32],
}

impl ArchiveHeader {
    pub fn write_to<W: Write>(&self, mut writer: W) -> Result<(), NxzError> {
        let mut buf = [0u8; HEADER_SIZE_BYTES];
        buf[0..4].copy_from_slice(&self.magic);
        buf[4..6].copy_from_slice(&self.version.to_le_bytes());
        buf[6..8].copy_from_slice(&self.flags.to_le_bytes());
        buf[8..16].copy_from_slice(&self.index_offset.to_le_bytes());
        buf[16..24].copy_from_slice(&self.index_stored_len.to_le_bytes());
        buf[24..32].copy_from_slice(&self.index_tag_prefix);
        buf[32..64].copy_from_slice(&self.crypto_salt);
        writer.write_all(&buf)?;
        Ok(())
    }

    pub fn read_from<R: Read>(mut reader: R) -> Result<Self, NxzError> {
        let mut buf = [0u8; HEADER_SIZE_BYTES];
        reader.read_exact(&mut buf)?;
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&buf[0..4]);
        if magic != NXZ_MAGIC {
            return Err(NxzError::InvalidMagicOrVersion);
        }
        let version = u16::from_le_bytes([buf[4], buf[5]]);
        if version != 1 && version != 2 {
            return Err(NxzError::UnsupportedVersion(version));
        }
        let flags = u16::from_le_bytes([buf[6], buf[7]]);
        let index_offset = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let index_stored_len = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let mut index_tag_prefix = [0u8; 8];
        index_tag_prefix.copy_from_slice(&buf[24..32]);
        let mut crypto_salt = [0u8; 32];
        crypto_salt.copy_from_slice(&buf[32..64]);

        Ok(Self {
            magic,
            version,
            flags,
            index_offset,
            index_stored_len,
            index_tag_prefix,
            crypto_salt,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockDescriptor {
    pub block_id: u32,
    pub codec_route: CodecRoute,
    pub archive_byte_offset: u64,
    pub stored_size: u64,
    pub uncompressed_size: u64,
    pub uncompressed_blake3: [u8; 32],
    pub stored_blake3: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntryV1 {
    pub relative_path: String,
    pub original_size: u64,
    pub file_blake3: [u8; 32],
    pub block_id: u32,
    pub offset_in_block: u64,
    pub length_in_block: u64,
    pub shannon_entropy_bpb: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeekableIndexFooterV1 {
    pub total_files: u64,
    pub total_uncompressed_bytes: u64,
    pub total_stored_bytes: u64,
    pub encrypted: bool,
    pub ecc_enabled: bool,
    pub blocks: Vec<BlockDescriptor>,
    pub files: Vec<FileEntryV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub relative_path: String,
    pub original_size: u64,
    pub file_blake3: [u8; 32],
    pub block_id: u32,
    pub offset_in_block: u64,
    pub length_in_block: u64,
    pub shannon_entropy_bpb: f32,
    #[serde(default)]
    pub modified_unix_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeekableIndexFooter {
    pub total_files: u64,
    pub total_uncompressed_bytes: u64,
    pub total_stored_bytes: u64,
    pub encrypted: bool,
    pub ecc_enabled: bool,
    pub blocks: Vec<BlockDescriptor>,
    pub files: Vec<FileEntry>,
}
