use std::collections::HashMap;

const FOT2_MAGIC: [u8; 4] = *b"FOT2";
const FOT_ESCAPE_BYTE: u8 = 0xFE;
const FOT_LITERAL_MARKER: u8 = 0xFF;
const MAX_DYNAMIC_TOKENS: usize = 200;
const DYNAMIC_SAMPLE_LIMIT: usize = 262_144;

const STATIC_FOT_DICTIONARY: &[&[u8]] = &[
    b"    ",
    b"        ",
    br#"": ""#,
    br#"", ""#,
    b"{\n",
    b"}\n",
    b"\r\n",
    b"https://",
    b"http://",
    b"function ",
    b"return ",
    b"const ",
    b"pub fn ",
    b"struct ",
    b"import ",
    b"class ",
    b"null",
    b"true",
    b"false",
    b"application/",
    b"content-",
    b"<div ",
    b"</div>",
    b"span>",
    br#"=""#,
    br#"">"#,
    b"2026-",
    b"2025-",
    b"[INFO]",
    b"[WARN]",
    b"[ERROR]",
    b" der ",
    b" die ",
    b" und ",
    b"ung ",
    b"chen ",
    b" the ",
    b" and ",
    b"tion ",
    b"ing ",
    b"<w:t>",
    b"</w:t>",
    b"<w:r>",
    b"</w:r>",
    b"<w:p>",
    b"</w:p>",
    b"<c r=\"",
    b"</row>",
];

pub fn fot_tokenize(input: &[u8]) -> Vec<u8> {
    if input.len() < 64 {
        return input.to_vec();
    }

    let dynamic_tokens = discover_dynamic_tokens(input);
    let mut combined_dict: Vec<&[u8]> = Vec::with_capacity(STATIC_FOT_DICTIONARY.len() + dynamic_tokens.len());
    combined_dict.extend_from_slice(STATIC_FOT_DICTIONARY);
    for tok in &dynamic_tokens {
        combined_dict.push(tok.as_slice());
    }

    let mut buckets: Vec<Vec<(u8, &[u8])>> = vec![Vec::new(); 256];
    for (idx, &pattern) in combined_dict.iter().enumerate() {
        if !pattern.is_empty() {
            buckets[pattern[0] as usize].push((idx as u8, pattern));
        }
    }
    for bucket in &mut buckets {
        bucket.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
    }

    let mut out = Vec::with_capacity(input.len());
    out.extend_from_slice(&FOT2_MAGIC);
    out.push(dynamic_tokens.len() as u8);
    for tok in &dynamic_tokens {
        out.push(tok.len() as u8);
        out.extend_from_slice(tok);
    }

    let mut i = 0;
    let n = input.len();

    while i < n {
        let b = input[i];
        if b == FOT_ESCAPE_BYTE {
            out.push(FOT_ESCAPE_BYTE);
            out.push(FOT_LITERAL_MARKER);
            i += 1;
            continue;
        }

        let bucket = &buckets[b as usize];
        if !bucket.is_empty() && i + 2 <= n {
            let remaining = &input[i..];
            let mut matched = false;
            for &(idx, pattern) in bucket {
                if remaining.starts_with(pattern) {
                    out.push(FOT_ESCAPE_BYTE);
                    out.push(idx);
                    i += pattern.len();
                    matched = true;
                    break;
                }
            }
            if matched {
                continue;
            }
        }

        out.push(b);
        i += 1;
    }

    out
}

pub fn fot_detokenize(input: &[u8]) -> Vec<u8> {
    if input.len() < 5 || &input[0..4] != &FOT2_MAGIC {
        return input.to_vec();
    }

    let dyn_count = input[4] as usize;
    let mut cursor = 5usize;
    let total_len = input.len();

    let mut dynamic_tokens: Vec<&[u8]> = Vec::with_capacity(dyn_count);
    for _ in 0..dyn_count {
        if cursor >= total_len {
            return input.to_vec();
        }
        let tok_len = input[cursor] as usize;
        cursor += 1;
        if cursor + tok_len > total_len {
            return input.to_vec();
        }
        dynamic_tokens.push(&input[cursor..cursor + tok_len]);
        cursor += tok_len;
    }

    let static_len = STATIC_FOT_DICTIONARY.len();
    let mut out = Vec::with_capacity(input.len() + (input.len() / 3));

    while cursor < total_len {
        let b = input[cursor];
        if b == FOT_ESCAPE_BYTE && cursor + 1 < total_len {
            let code = input[cursor + 1];
            if code == FOT_LITERAL_MARKER {
                out.push(FOT_ESCAPE_BYTE);
            } else if (code as usize) < static_len {
                out.extend_from_slice(STATIC_FOT_DICTIONARY[code as usize]);
            } else if (code as usize) < static_len + dynamic_tokens.len() {
                out.extend_from_slice(dynamic_tokens[(code as usize) - static_len]);
            } else {
                out.push(b);
                out.push(code);
            }
            cursor += 2;
        } else {
            out.push(b);
            cursor += 1;
        }
    }

    out
}

fn discover_dynamic_tokens(input: &[u8]) -> Vec<Vec<u8>> {
    let sample = &input[..input.len().min(DYNAMIC_SAMPLE_LIMIT)];
    let mut freq_map: HashMap<&[u8], u32> = HashMap::new();

    let mut i = 0;
    let n = sample.len();

    while i < n {
        let b = sample[i];
        if b == b'<' && i + 4 <= n {
            let max_end = (i + 24).min(n);
            if let Some(rel_close) = sample[i + 1..max_end].iter().position(|&c| c == b'>') {
                let end = i + 1 + rel_close + 1;
                let slice = &sample[i..end];
                if slice.len() >= 4 && !slice.contains(&FOT_ESCAPE_BYTE) {
                    *freq_map.entry(slice).or_insert(0) += 1;
                    i = end;
                    continue;
                }
            }
        }

        if is_token_char(b) {
            let start = i;
            let max_end = (i + 24).min(n);
            while i < max_end && is_token_char(sample[i]) {
                i += 1;
            }
            if i < max_end && (sample[i] == b' ' || sample[i] == b':' || sample[i] == b'"') {
                i += 1;
            }
            let slice = &sample[start..i];
            if slice.len() >= 5 && !slice.contains(&FOT_ESCAPE_BYTE) {
                *freq_map.entry(slice).or_insert(0) += 1;
            }
            continue;
        }
        i += 1;
    }

    let mut scored: Vec<(&[u8], i64)> = freq_map
        .into_iter()
        .filter_map(|(slice, count)| {
            if count < 4 || STATIC_FOT_DICTIONARY.contains(&slice) {
                return None;
            }
            let len = slice.len() as i64;
            let net_savings = (count as i64) * (len - 2) - (len + 2);
            if net_savings > 24 {
                Some((slice, net_savings))
            } else {
                None
            }
        })
        .collect();

    scored.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    scored.into_iter().take(MAX_DYNAMIC_TOKENS).map(|(s, _)| s.to_vec()).collect()
}

#[inline]
fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.'
}

pub fn bcj_x86_encode(data: &[u8]) -> Vec<u8> {
    let mut buf = data.to_vec();
    if buf.len() < 5 {
        return buf;
    }
    let limit = buf.len() - 4;
    let mut i = 0;
    while i < limit {
        if buf[i] == 0xE8 || buf[i] == 0xE9 {
            let b3 = buf[i + 4];
            if b3 == 0x00 || b3 == 0xFF {
                let rel = u32::from_le_bytes([buf[i + 1], buf[i + 2], buf[i + 3], buf[i + 4]]);
                let abs = rel.wrapping_add((i as u32).wrapping_add(5));
                let mut bytes = abs.to_le_bytes();
                bytes[3] = if (bytes[3] & 1) != 0 { 0xFF } else { 0x00 };
                buf[i + 1..i + 5].copy_from_slice(&bytes);
            }
            i += 5;
            continue;
        }
        i += 1;
    }
    buf
}

pub fn bcj_x86_decode(data: &[u8]) -> Vec<u8> {
    let mut buf = data.to_vec();
    if buf.len() < 5 {
        return buf;
    }
    let limit = buf.len() - 4;
    let mut i = 0;
    while i < limit {
        if buf[i] == 0xE8 || buf[i] == 0xE9 {
            let b3 = buf[i + 4];
            if b3 == 0x00 || b3 == 0xFF {
                let abs = u32::from_le_bytes([buf[i + 1], buf[i + 2], buf[i + 3], buf[i + 4]]);
                let rel = abs.wrapping_sub((i as u32).wrapping_add(5));
                let mut bytes = rel.to_le_bytes();
                bytes[3] = if (bytes[3] & 1) != 0 { 0xFF } else { 0x00 };
                buf[i + 1..i + 5].copy_from_slice(&bytes);
            }
            i += 5;
            continue;
        }
        i += 1;
    }
    buf
}
