use flate2::read::{DeflateDecoder, DeflateEncoder};
use flate2::Compression;
use std::io::Read;

const OFC_MAGIC: [u8; 4] = *b"OFC2";
const SEGMENT_RAW: u8 = 0x00;
const SEGMENT_UNFOLDED_DEFLATE: u8 = 0x01;
const ZIP_LOCAL_HEADER_SIG: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];
const ZIP_CD_HEADER_SIG: [u8; 4] = [0x50, 0x4B, 0x01, 0x02];
const ZIP_EOCD_SIG: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
const MAX_ENTRY_UNCOMP_SIZE: usize = 32 * 1024 * 1024;

pub fn office_unfold(input: &[u8]) -> Vec<u8> {
    if input.len() < 30 || !input.starts_with(&ZIP_LOCAL_HEADER_SIG) {
        return encode_passthrough(input);
    }

    let mut out = Vec::with_capacity(input.len() + (input.len() / 2));
    out.extend_from_slice(&OFC_MAGIC);

    let mut cursor = 0usize;
    let mut raw_start = 0usize;
    let mut unfolded_any = false;
    let total_len = input.len();

    while cursor + 30 <= total_len {
        if input[cursor..cursor + 4] == ZIP_LOCAL_HEADER_SIG {
            let flags = u16::from_le_bytes([input[cursor + 6], input[cursor + 7]]);
            let method = u16::from_le_bytes([input[cursor + 8], input[cursor + 9]]);
            let comp_size = u32::from_le_bytes([input[cursor + 18], input[cursor + 19], input[cursor + 20], input[cursor + 21]]) as usize;
            let uncomp_size = u32::from_le_bytes([input[cursor + 22], input[cursor + 23], input[cursor + 24], input[cursor + 25]]) as usize;
            let name_len = u16::from_le_bytes([input[cursor + 26], input[cursor + 27]]) as usize;
            let extra_len = u16::from_le_bytes([input[cursor + 28], input[cursor + 29]]) as usize;

            let header_end = cursor + 30 + name_len + extra_len;
            let payload_end = header_end.saturating_add(comp_size);

            if (flags & 0x0008) == 0
                && method == 8
                && comp_size > 16
                && uncomp_size > comp_size
                && uncomp_size <= MAX_ENTRY_UNCOMP_SIZE
                && payload_end <= total_len
            {
                let entry_name = &input[cursor + 30..cursor + 30 + name_len];
                let comp_payload = &input[header_end..payload_end];

                if is_compressible_office_entry(entry_name) {
                    if let Some((raw_xml, matched_level)) = try_lossless_inflate_and_verify(comp_payload, uncomp_size) {
                        write_raw_segment(&mut out, &input[raw_start..header_end]);
                        out.push(SEGMENT_UNFOLDED_DEFLATE);
                        out.push(matched_level);
                        out.extend_from_slice(&(raw_xml.len() as u32).to_le_bytes());
                        out.extend_from_slice(&raw_xml);

                        unfolded_any = true;
                        cursor = payload_end;
                        raw_start = cursor;
                        continue;
                    }
                }
                cursor = payload_end;
                continue;
            }
        }
        cursor += 1;
    }

    if !unfolded_any {
        return encode_passthrough(input);
    }
    if raw_start < total_len {
        write_raw_segment(&mut out, &input[raw_start..total_len]);
    }
    out
}

pub fn office_refold(input: &[u8]) -> std::io::Result<Vec<u8>> {
    if input.len() < 4 || &input[0..4] != &OFC_MAGIC {
        return Ok(input.to_vec());
    }

    let mut out = Vec::with_capacity(input.len());
    let mut cursor = 4usize;
    let total_len = input.len();

    while cursor < total_len {
        let seg_type = input[cursor];
        cursor += 1;
        match seg_type {
            SEGMENT_RAW => {
                if cursor + 4 > total_len {
                    break;
                }
                let len = u32::from_le_bytes([input[cursor], input[cursor + 1], input[cursor + 2], input[cursor + 3]]) as usize;
                cursor += 4;
                if cursor + len > total_len {
                    break;
                }
                out.extend_from_slice(&input[cursor..cursor + len]);
                cursor += len;
            }
            SEGMENT_UNFOLDED_DEFLATE => {
                if cursor + 5 > total_len {
                    break;
                }
                let level = input[cursor];
                let len = u32::from_le_bytes([input[cursor + 1], input[cursor + 2], input[cursor + 3], input[cursor + 4]]) as usize;
                cursor += 5;
                if cursor + len > total_len {
                    break;
                }
                let raw_xml = &input[cursor..cursor + len];
                cursor += len;
                let re_deflated = deflate_raw_bytes(raw_xml, u32::from(level))?;
                out.extend_from_slice(&re_deflated);
            }
            _ => break,
        }
    }
    Ok(out)
}

fn is_compressible_office_entry(name_bytes: &[u8]) -> bool {
    let name = String::from_utf8_lossy(name_bytes).to_ascii_lowercase();
    name.ends_with(".xml") || name.ends_with(".rels") || name.ends_with(".html") || name.ends_with(".xhtml") || name.ends_with(".css") || name.ends_with(".json") || name.ends_with(".txt") || name.ends_with(".csv")
}

fn try_lossless_inflate_and_verify(comp_payload: &[u8], expected_uncomp_size: usize) -> Option<(Vec<u8>, u8)> {
    let mut decoder = DeflateDecoder::new(comp_payload);
    let mut raw = Vec::with_capacity(expected_uncomp_size);
    if decoder.read_to_end(&mut raw).is_err() || raw.len() != expected_uncomp_size {
        return None;
    }
    for &lvl in &[6u8, 1, 9, 5, 4, 3, 2, 7, 8] {
        if let Ok(recomp) = deflate_raw_bytes(&raw, u32::from(lvl)) {
            if recomp.as_slice() == comp_payload {
                return Some((raw, lvl));
            }
        }
    }
    None
}

fn deflate_raw_bytes(raw: &[u8], level: u32) -> std::io::Result<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(raw, Compression::new(level));
    let mut out = Vec::new();
    encoder.read_to_end(&mut out)?;
    Ok(out)
}

fn write_raw_segment(out: &mut Vec<u8>, slice: &[u8]) {
    if slice.is_empty() {
        return;
    }
    out.push(SEGMENT_RAW);
    out.extend_from_slice(&(slice.len() as u32).to_le_bytes());
    out.extend_from_slice(slice);
}

fn encode_passthrough(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + 9);
    out.extend_from_slice(&OFC_MAGIC);
    write_raw_segment(&mut out, input);
    out
}

fn find_eocd_offset(data: &[u8]) -> Option<usize> {
    if data.len() < 22 {
        return None;
    }
    let min_pos = data.len().saturating_sub(22 + 65535);
    let mut pos = data.len() - 22;
    loop {
        if data[pos..pos + 4] == ZIP_EOCD_SIG {
            let comment_len = u16::from_le_bytes([data[pos + 20], data[pos + 21]]) as usize;
            if pos + 22 + comment_len <= data.len() {
                return Some(pos);
            }
        }
        if pos <= min_pos {
            break;
        }
        pos -= 1;
    }
    None
}

pub fn extract_standard_zip(
    zip_path: &std::path::Path,
    output_dir: &std::path::Path,
) -> Result<(u64, u64), crate::error::NxzError> {
    use crate::error::NxzError;
    use crate::security::{check_decompression_quota, sanitize_extraction_path};
    use std::fs;

    let data = fs::read(zip_path).map_err(|e| NxzError::IoPath {
        path: zip_path.to_path_buf(),
        source: e,
    })?;
    fs::create_dir_all(output_dir)?;

    let total_len = data.len();
    let mut files_extracted = 0u64;
    let mut total_uncomp_bytes = 0u64;

    // 1. Primary path: Parse Central Directory via EOCD (supports Flag 0x08 Data Descriptors 100%)
    if let Some(eocd_pos) = find_eocd_offset(&data) {
        let cd_size = u32::from_le_bytes([
            data[eocd_pos + 12],
            data[eocd_pos + 13],
            data[eocd_pos + 14],
            data[eocd_pos + 15],
        ]) as usize;
        let cd_offset = u32::from_le_bytes([
            data[eocd_pos + 16],
            data[eocd_pos + 17],
            data[eocd_pos + 18],
            data[eocd_pos + 19],
        ]) as usize;

        if cd_offset.saturating_add(cd_size) <= total_len {
            let mut cd_cursor = cd_offset;
            let cd_end = cd_offset + cd_size;

            while cd_cursor + 46 <= cd_end {
                if data[cd_cursor..cd_cursor + 4] != ZIP_CD_HEADER_SIG {
                    break;
                }
                let method = u16::from_le_bytes([data[cd_cursor + 10], data[cd_cursor + 11]]);
                let comp_size = u32::from_le_bytes([
                    data[cd_cursor + 20],
                    data[cd_cursor + 21],
                    data[cd_cursor + 22],
                    data[cd_cursor + 23],
                ]) as usize;
                let uncomp_size = u32::from_le_bytes([
                    data[cd_cursor + 24],
                    data[cd_cursor + 25],
                    data[cd_cursor + 26],
                    data[cd_cursor + 27],
                ]) as usize;
                let name_len = u16::from_le_bytes([data[cd_cursor + 28], data[cd_cursor + 29]]) as usize;
                let extra_len = u16::from_le_bytes([data[cd_cursor + 30], data[cd_cursor + 31]]) as usize;
                let comment_len = u16::from_le_bytes([data[cd_cursor + 32], data[cd_cursor + 33]]) as usize;
                let local_header_offset = u32::from_le_bytes([
                    data[cd_cursor + 42],
                    data[cd_cursor + 43],
                    data[cd_cursor + 44],
                    data[cd_cursor + 45],
                ]) as usize;

                let cd_entry_end = cd_cursor + 46 + name_len + extra_len + comment_len;
                if cd_entry_end > cd_end {
                    break;
                }

                let raw_name = String::from_utf8_lossy(&data[cd_cursor + 46..cd_cursor + 46 + name_len])
                    .replace('\\', "/");
                cd_cursor = cd_entry_end;

                let trimmed_name = raw_name.trim_end_matches('/');
                if raw_name.ends_with('/') {
                    if !trimmed_name.is_empty() {
                        let safe_dir = sanitize_extraction_path(output_dir, trimmed_name)?;
                        fs::create_dir_all(&safe_dir)?;
                    }
                    continue;
                }

                if local_header_offset + 30 > total_len
                    || data[local_header_offset..local_header_offset + 4] != ZIP_LOCAL_HEADER_SIG
                {
                    continue;
                }

                let local_name_len = u16::from_le_bytes([
                    data[local_header_offset + 26],
                    data[local_header_offset + 27],
                ]) as usize;
                let local_extra_len = u16::from_le_bytes([
                    data[local_header_offset + 28],
                    data[local_header_offset + 29],
                ]) as usize;

                let payload_start = local_header_offset + 30 + local_name_len + local_extra_len;
                let payload_end = payload_start.saturating_add(comp_size);
                if payload_end > total_len {
                    continue;
                }

                check_decompression_quota(comp_size as u64, uncomp_size as u64)?;
                let safe_target = sanitize_extraction_path(output_dir, &raw_name)?;
                if let Some(parent) = safe_target.parent() {
                    fs::create_dir_all(parent)?;
                }

                let payload = &data[payload_start..payload_end];
                let plain_bytes: Vec<u8> = match method {
                    0 => payload.to_vec(),
                    8 => {
                        let mut decoder = DeflateDecoder::new(payload);
                        let mut out = Vec::with_capacity(uncomp_size);
                        decoder.read_to_end(&mut out)?;
                        out
                    }
                    _ => continue,
                };

                fs::write(&safe_target, &plain_bytes).map_err(|e| NxzError::IoPath {
                    path: safe_target,
                    source: e,
                })?;

                files_extracted += 1;
                total_uncomp_bytes += plain_bytes.len() as u64;
            }

            if files_extracted > 0 {
                return Ok((files_extracted, total_uncomp_bytes));
            }
        }
    }

    // 2. Fallback path: Sequential Local File Header scan (including streaming Flag 0x08 inflate)
    let mut cursor = 0usize;
    while cursor + 30 <= total_len {
        if data[cursor..cursor + 4] == ZIP_LOCAL_HEADER_SIG {
            let flags = u16::from_le_bytes([data[cursor + 6], data[cursor + 7]]);
            let method = u16::from_le_bytes([data[cursor + 8], data[cursor + 9]]);
            let comp_size = u32::from_le_bytes([
                data[cursor + 18],
                data[cursor + 19],
                data[cursor + 20],
                data[cursor + 21],
            ]) as usize;
            let uncomp_size = u32::from_le_bytes([
                data[cursor + 22],
                data[cursor + 23],
                data[cursor + 24],
                data[cursor + 25],
            ]) as usize;
            let name_len = u16::from_le_bytes([data[cursor + 26], data[cursor + 27]]) as usize;
            let extra_len = u16::from_le_bytes([data[cursor + 28], data[cursor + 29]]) as usize;

            let name_end = cursor + 30 + name_len;
            let header_end = name_end + extra_len;
            if name_end > total_len || header_end > total_len {
                break;
            }

            let raw_name = String::from_utf8_lossy(&data[cursor + 30..name_end]).replace('\\', "/");
            let trimmed_name = raw_name.trim_end_matches('/');

            if raw_name.ends_with('/') {
                if !trimmed_name.is_empty() {
                    let safe_dir = sanitize_extraction_path(output_dir, trimmed_name)?;
                    fs::create_dir_all(&safe_dir)?;
                }
                cursor = header_end.saturating_add(comp_size);
                continue;
            }

            let safe_target = sanitize_extraction_path(output_dir, &raw_name)?;
            if let Some(parent) = safe_target.parent() {
                fs::create_dir_all(parent)?;
            }

            let (plain_bytes, next_cursor) = if (flags & 0x0008) != 0 && comp_size == 0 && method == 8 {
                let mut decoder = DeflateDecoder::new(&data[header_end..]);
                let mut out = Vec::new();
                decoder.read_to_end(&mut out)?;
                let consumed = decoder.total_in() as usize;
                check_decompression_quota(consumed as u64, out.len() as u64)?;
                let mut after = header_end + consumed;
                // Skip optional 12-byte or 16-byte Data Descriptor
                if after + 16 <= total_len && data[after..after + 4] == [0x50, 0x4B, 0x07, 0x08] {
                    after += 16;
                } else if after + 12 <= total_len {
                    after += 12;
                }
                (out, after)
            } else {
                let payload_end = header_end.saturating_add(comp_size);
                if payload_end > total_len {
                    break;
                }
                check_decompression_quota(comp_size as u64, uncomp_size as u64)?;
                let payload = &data[header_end..payload_end];
                let out: Vec<u8> = match method {
                    0 => payload.to_vec(),
                    8 => {
                        let mut decoder = DeflateDecoder::new(payload);
                        let mut out = Vec::with_capacity(uncomp_size);
                        decoder.read_to_end(&mut out)?;
                        out
                    }
                    _ => {
                        cursor = payload_end;
                        continue;
                    }
                };
                (out, payload_end)
            };

            fs::write(&safe_target, &plain_bytes).map_err(|e| NxzError::IoPath {
                path: safe_target,
                source: e,
            })?;

            files_extracted += 1;
            total_uncomp_bytes += plain_bytes.len() as u64;
            cursor = next_cursor;
        } else {
            cursor += 1;
        }
    }

    Ok((files_extracted, total_uncomp_bytes))
}
