use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub const ROUTER_SAMPLE_SIZE: usize = 65_536;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CodecRoute {
    BypassPassthrough = 0x00,
    HighSpeedZstd = 0x01,
    TextFotZstd = 0x02,
    TextFotLzma2 = 0x03,
    ExecutableBcjZstd = 0x04,
    ExecutableBcjLzma2 = 0x05,
    GeneralZstd = 0x06,
    GeneralLzma2 = 0x07,
    OfficeFotZstd = 0x08,
    OfficeFotLzma2 = 0x09,
    ReservedNeuralPmatic = 0x10,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionProfile {
    Turbo,
    Balanced,
    Ultra,
}

#[derive(Debug, Clone)]
pub struct StreamAnalysis {
    pub shannon_entropy_bpb: f64,
    pub ascii_printable_ratio: f64,
    pub null_byte_ratio: f64,
    pub is_valid_utf8_prefix: bool,
    pub detected_class: StreamClass,
    pub recommended_route: CodecRoute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamClass {
    IncompressibleMediaOrCrypto,
    StructuredTextOrCode,
    ExecutableBinary,
    OfficeOrZipContainer,
    GeneralBinary,
}

pub fn analyze_file_route(path: &Path, profile: CompressionProfile) -> std::io::Result<StreamAnalysis> {
    let mut file = File::open(path)?;
    let mut buffer = vec![0u8; ROUTER_SAMPLE_SIZE];
    let bytes_read = file.read(&mut buffer)?;
    buffer.truncate(bytes_read);
    Ok(analyze_sample(&buffer, path, profile))
}

pub fn analyze_sample(sample: &[u8], path: &Path, profile: CompressionProfile) -> StreamAnalysis {
    if sample.is_empty() {
        return StreamAnalysis {
            shannon_entropy_bpb: 0.0,
            ascii_printable_ratio: 1.0,
            null_byte_ratio: 0.0,
            is_valid_utf8_prefix: true,
            detected_class: StreamClass::StructuredTextOrCode,
            recommended_route: CodecRoute::BypassPassthrough,
        };
    }

    let mut counts = [0u32; 256];
    let mut printable_count = 0u32;

    for &b in sample {
        counts[b as usize] += 1;
        if (0x20..=0x7E).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t' {
            printable_count += 1;
        }
    }

    let len_f64 = sample.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len_f64;
            entropy -= p * p.log2();
        }
    }

    let ascii_printable_ratio = (printable_count as f64) / len_f64;
    let null_byte_ratio = (counts[0] as f64) / len_f64;
    let is_valid_utf8_prefix = check_utf8_prefix(sample);

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    let detected_class = classify_stream(sample, &ext, entropy, ascii_printable_ratio, null_byte_ratio, is_valid_utf8_prefix);

    let recommended_route = match (detected_class, profile) {
        (StreamClass::IncompressibleMediaOrCrypto, _) => CodecRoute::BypassPassthrough,
        (StreamClass::StructuredTextOrCode, CompressionProfile::Turbo) => CodecRoute::HighSpeedZstd,
        (StreamClass::StructuredTextOrCode, CompressionProfile::Balanced) => CodecRoute::TextFotZstd,
        (StreamClass::StructuredTextOrCode, CompressionProfile::Ultra) => CodecRoute::TextFotLzma2,
        (StreamClass::ExecutableBinary, CompressionProfile::Turbo) => CodecRoute::ExecutableBcjZstd,
        (StreamClass::ExecutableBinary, CompressionProfile::Balanced) => CodecRoute::ExecutableBcjZstd,
        (StreamClass::ExecutableBinary, CompressionProfile::Ultra) => CodecRoute::ExecutableBcjLzma2,
        (StreamClass::OfficeOrZipContainer, CompressionProfile::Turbo) => CodecRoute::OfficeFotZstd,
        (StreamClass::OfficeOrZipContainer, CompressionProfile::Balanced) => CodecRoute::OfficeFotZstd,
        (StreamClass::OfficeOrZipContainer, CompressionProfile::Ultra) => CodecRoute::OfficeFotLzma2,
        (StreamClass::GeneralBinary, CompressionProfile::Turbo) => CodecRoute::HighSpeedZstd,
        (StreamClass::GeneralBinary, CompressionProfile::Balanced) => CodecRoute::GeneralZstd,
        (StreamClass::GeneralBinary, CompressionProfile::Ultra) => CodecRoute::GeneralLzma2,
    };

    StreamAnalysis {
        shannon_entropy_bpb: entropy,
        ascii_printable_ratio,
        null_byte_ratio,
        is_valid_utf8_prefix,
        detected_class,
        recommended_route,
    }
}

fn classify_stream(sample: &[u8], ext: &str, entropy: f64, printable_ratio: f64, null_ratio: f64, utf8_ok: bool) -> StreamClass {
    if sample.starts_with(b"MZ")
        || sample.starts_with(b"\x7FELF")
        || sample.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
        || matches!(ext, "exe" | "dll" | "sys" | "so" | "dylib" | "bin" | "o" | "obj")
    {
        if entropy < 7.85 {
            return StreamClass::ExecutableBinary;
        }
    }

    if matches!(ext, "docx" | "xlsx" | "pptx" | "odt" | "epub" | "jar")
        || (sample.starts_with(b"PK\x03\x04") && ext != "zip")
    {
        return StreamClass::OfficeOrZipContainer;
    }

    if sample.starts_with(b"\x89PNG\r\n\x1a\n")
        || sample.starts_with(&[0xFF, 0xD8, 0xFF])
        || sample.starts_with(b"7z\xBC\xAF\x27\x1C")
        || sample.starts_with(&[0x28, 0xB5, 0x2F, 0xFD])
        || sample.starts_with(&[0x1F, 0x8B, 0x08])
        || sample.starts_with(b"\xFD7zXZ\x00")
        || (sample.len() >= 8 && &sample[4..8] == b"ftyp")
        || matches!(
            ext,
            "mp4" | "mkv" | "webm" | "avi" | "mov" | "mp3" | "aac" | "ogg" | "flac"
                | "jpg" | "jpeg" | "png" | "webp" | "avif"
                | "7z" | "zst" | "gz" | "xz" | "rar" | "zip"
        )
    {
        return StreamClass::IncompressibleMediaOrCrypto;
    }

    if entropy > 7.92 && sample.len() >= 4096 {
        return StreamClass::IncompressibleMediaOrCrypto;
    }

    if (utf8_ok && null_ratio == 0.0 && printable_ratio > 0.85)
        || matches!(ext, "txt" | "md" | "json" | "jsonl" | "csv" | "tsv" | "xml" | "html" | "css" | "js" | "ts" | "jsx" | "tsx" | "rs" | "py" | "c" | "cpp" | "h" | "hpp" | "cs" | "go" | "java" | "sql" | "yaml" | "yml" | "toml" | "ini" | "log")
    {
        if entropy < 6.80 && null_ratio < 0.01 {
            return StreamClass::StructuredTextOrCode;
        }
    }

    StreamClass::GeneralBinary
}

fn check_utf8_prefix(sample: &[u8]) -> bool {
    match std::str::from_utf8(sample) {
        Ok(_) => true,
        Err(err) => err.valid_up_to() + 4 >= sample.len() && err.error_len().is_none(),
    }
}
