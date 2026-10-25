pub mod container;
pub mod crypto;
pub mod ecc;
pub mod error;
pub mod gui;
pub mod installer;
pub mod office;
pub mod pipeline;
pub mod prefilter;
pub mod router;
pub mod security;
pub mod shell;

#[cfg(test)]
mod tests {
    use super::ecc::{ecc_protect, ecc_verify_and_heal};
    use super::pipeline::{
        extract_single_file_with_password, pack_with_options, unpack_all_with_password,
        verify_archive_integrity, PackOptions, ProgressTracker,
    };
    use super::prefilter::{bcj_x86_decode, bcj_x86_encode, fot_detokenize, fot_tokenize};
    use super::router::CompressionProfile;
    use rand::RngCore;
    use std::fs;

    #[test]
    fn test_dynamic_fot2_bijective() {
        let text = b"<w:p><w:r><w:t>NextGen Archiver Dynamic Tokenization Test 2026</w:t></w:r></w:p>\n".repeat(250);
        let tok = fot_tokenize(&text);
        assert!(tok.len() < text.len() / 2);
        let restored = fot_detokenize(&tok);
        assert_eq!(text, restored);
    }

    #[test]
    fn test_bcj_bijective() {
        let fake_exe = vec![0x4D, 0x5A, 0x90, 0x00, 0xE8, 0x10, 0x00, 0x00, 0x00, 0xE9, 0xF0, 0xFF, 0xFF, 0xFF];
        let enc = bcj_x86_encode(&fake_exe);
        assert_eq!(fake_exe, bcj_x86_decode(&enc));
    }

    #[test]
    fn test_reed_solomon_self_healing_bit_rot() {
        let original = b"Kritische Backup-Daten, die selbst bei defekten Sektoren auf dem USB-Stick heil bleiben muessen!".repeat(100);
        let mut protected = ecc_protect(&original).unwrap();

        let corrupt_start = 220;
        for b in &mut protected[corrupt_start..corrupt_start + 400] {
            *b ^= 0xFF;
        }

        let (healed, repaired_shards) = ecc_verify_and_heal(&protected).unwrap();
        assert!(repaired_shards >= 1);
        assert_eq!(original.as_slice(), healed.as_slice());
    }

    #[test]
    fn test_encrypted_aead_and_ecc_end_to_end() {
        let tmp_root = std::env::temp_dir().join("nxz_master_test");
        let _ = fs::remove_dir_all(&tmp_root);
        let src_dir = tmp_root.join("src");
        let out_dir = tmp_root.join("out");
        let archive = tmp_root.join("vault.nxz");

        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("secret.json"), br#"{"project": "NXZ", "status": "top_secret"}"#.repeat(120)).unwrap();

        let opts = PackOptions {
            profile: CompressionProfile::Balanced,
            password: Some("TresorPasswort2026!".to_string()),
            enable_ecc: true,
            progress: None,
        };
        pack_with_options(&src_dir, &archive, &opts).unwrap();

        assert!(unpack_all_with_password(&archive, &out_dir, Some("FalschesPasswort")).is_err());

        let single = extract_single_file_with_password(&archive, "secret.json", &out_dir, Some("TresorPasswort2026!")).unwrap();
        assert!(single.exists());

        let _ = fs::remove_dir_all(&tmp_root);
    }

    #[test]
    fn test_bcj_overlapping_opcodes_5mb_stress() {
        let target_len = 2 * 1024 * 1024;
        let mut data = Vec::with_capacity(target_len + 16);
        let mut state: u32 = 0x9E37_79B9;
        while data.len() < target_len {
            data.extend_from_slice(&[0xE8, 0xE8, 0x00, 0x00, 0x05, 0x00]);
            data.extend_from_slice(&[0xE9, 0xE8, 0xFF, 0xFF, 0x03, 0xFF]);
            for _ in 0..8 {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                data.push((state >> 24) as u8);
            }
        }
        data.truncate(target_len);

        let encoded = bcj_x86_encode(&data);
        let decoded = bcj_x86_decode(&encoded);
        assert_eq!(data, decoded);
    }

    #[test]
    fn test_zero_byte_file_instant_seek() {
        let tmp_root = std::env::temp_dir().join("nxz_zero_byte_seek_test");
        let _ = fs::remove_dir_all(&tmp_root);
        let src_dir = tmp_root.join("src");
        let out_dir = tmp_root.join("out");
        let single_dir = tmp_root.join("single");
        let archive = tmp_root.join("zero_test.nxz");

        fs::create_dir_all(src_dir.join("nested")).unwrap();
        fs::write(src_dir.join("empty.bin"), b"").unwrap();
        fs::write(src_dir.join("nested/empty_marker.lock"), b"").unwrap();
        fs::write(src_dir.join("normal.txt"), b"Normale Testdatei neben 0-Byte-Dateien".repeat(32)).unwrap();

        let opts = PackOptions {
            profile: CompressionProfile::Balanced,
            password: Some("ZeroByteTestPw!".to_string()),
            enable_ecc: true,
            progress: None,
        };
        pack_with_options(&src_dir, &archive, &opts).unwrap();

        let extracted_zero = extract_single_file_with_password(
            &archive,
            "empty.bin",
            &single_dir,
            Some("ZeroByteTestPw!"),
        )
        .unwrap();
        assert!(extracted_zero.exists());
        assert_eq!(fs::metadata(&extracted_zero).unwrap().len(), 0);

        let extracted_nested_zero = extract_single_file_with_password(
            &archive,
            "nested/empty_marker.lock",
            &single_dir,
            Some("ZeroByteTestPw!"),
        )
        .unwrap();
        assert!(extracted_nested_zero.exists());
        assert_eq!(fs::metadata(&extracted_nested_zero).unwrap().len(), 0);

        let (footer, _) = unpack_all_with_password(&archive, &out_dir, Some("ZeroByteTestPw!")).unwrap();
        assert_eq!(footer.total_files, 3);
        assert_eq!(fs::metadata(out_dir.join("empty.bin")).unwrap().len(), 0);

        let _ = fs::remove_dir_all(&tmp_root);
    }

    #[test]
    fn test_blake3_file_deduplication() {
        let tmp_root = std::env::temp_dir().join("nxz_blake3_dedup_test");
        let _ = fs::remove_dir_all(&tmp_root);
        let src_dir = tmp_root.join("src");
        let out_dir = tmp_root.join("out");
        let archive = tmp_root.join("dedup_test.nxz");

        fs::create_dir_all(src_dir.join("renders")).unwrap();
        fs::create_dir_all(src_dir.join("upload_package")).unwrap();
        fs::create_dir_all(src_dir.join("backup")).unwrap();

        let mut random_2mb = vec![0u8; 2 * 1024 * 1024];
        rand::thread_rng().fill_bytes(&mut random_2mb);
        let expected_hash = blake3::hash(&random_2mb);

        fs::write(src_dir.join("renders/video_a.mp4"), &random_2mb).unwrap();
        fs::write(src_dir.join("upload_package/video_b.mp4"), &random_2mb).unwrap();
        fs::write(src_dir.join("backup/video_c.mp4"), &random_2mb).unwrap();

        let opts = PackOptions {
            profile: CompressionProfile::Balanced,
            password: None,
            enable_ecc: false,
            progress: None,
        };
        let footer = pack_with_options(&src_dir, &archive, &opts).unwrap();

        assert_eq!(footer.total_files, 3);
        assert_eq!(footer.total_uncompressed_bytes, 6 * 1024 * 1024);
        assert!(
            footer.total_stored_bytes < 2_500_000,
            "Expected stored bytes < 2.5 MB due to deduplication, got {}",
            footer.total_stored_bytes
        );

        let (verified_files, verified_bytes, _) = verify_archive_integrity(&archive, None).unwrap();
        assert_eq!(verified_files, 3);
        assert_eq!(verified_bytes, 6 * 1024 * 1024);

        let (unpacked_footer, _) = unpack_all_with_password(&archive, &out_dir, None).unwrap();
        assert_eq!(unpacked_footer.total_files, 3);

        for rel in [
            "renders/video_a.mp4",
            "upload_package/video_b.mp4",
            "backup/video_c.mp4",
        ] {
            let restored = fs::read(out_dir.join(rel)).unwrap();
            assert_eq!(blake3::hash(&restored), expected_hash);
        }

        let _ = fs::remove_dir_all(&tmp_root);
    }


    #[test]
    fn test_mtime_preserved_on_unpack_and_single_seek() {
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        let tmp_root = std::env::temp_dir().join("nxz_mtime_test");
        let _ = fs::remove_dir_all(&tmp_root);
        let src_dir = tmp_root.join("src");
        let out_dir = tmp_root.join("out");
        let single_dir = tmp_root.join("single");
        let archive = tmp_root.join("mtime.nxz");
        fs::create_dir_all(src_dir.join("docs")).unwrap();

        let original_secs: u64 = 1_600_000_000;
        let original_mtime = UNIX_EPOCH + Duration::from_secs(original_secs);
        let file_path = src_dir.join("docs/report.txt");
        fs::write(&file_path, b"Zeitstempel-Test fuer NXZ Studio v2.0\n".repeat(50)).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&file_path)
            .unwrap()
            .set_modified(original_mtime)
            .unwrap();

        let opts = PackOptions {
            profile: CompressionProfile::Balanced,
            password: None,
            enable_ecc: false,
            progress: None,
        };
        let footer = pack_with_options(&src_dir, &archive, &opts).unwrap();
        assert_eq!(footer.files[0].modified_unix_secs, original_secs);
        assert!(!tmp_root.join("mtime.nxz.tmp").exists());

        unpack_all_with_password(&archive, &out_dir, None).unwrap();
        let restored: SystemTime = fs::metadata(out_dir.join("docs/report.txt")).unwrap().modified().unwrap();
        assert_eq!(restored.duration_since(UNIX_EPOCH).unwrap().as_secs(), original_secs);

        let single = extract_single_file_with_password(&archive, "docs/report.txt", &single_dir, None).unwrap();
        let restored_single = fs::metadata(&single).unwrap().modified().unwrap();
        assert_eq!(restored_single.duration_since(UNIX_EPOCH).unwrap().as_secs(), original_secs);

        let _ = fs::remove_dir_all(&tmp_root);
    }

    #[test]
    fn test_cancelled_pack_leaves_no_archive_or_tmp() {
        use std::sync::atomic::Ordering;

        let tmp_root = std::env::temp_dir().join("nxz_cancel_test");
        let _ = fs::remove_dir_all(&tmp_root);
        let src_dir = tmp_root.join("src");
        let archive = tmp_root.join("cancelled.nxz");
        let tmp_archive = tmp_root.join("cancelled.nxz.tmp");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("a.txt"), b"abc".repeat(1000)).unwrap();

        let tracker = ProgressTracker::new();
        tracker.cancel_requested.store(true, Ordering::SeqCst);
        let opts = PackOptions {
            profile: CompressionProfile::Balanced,
            password: None,
            enable_ecc: false,
            progress: Some(tracker),
        };

        let result = pack_with_options(&src_dir, &archive, &opts);
        assert!(matches!(result, Err(super::error::NxzError::OperationCancelled)));
        assert!(!archive.exists());
        assert!(!tmp_archive.exists());

        let _ = fs::remove_dir_all(&tmp_root);
    }

    #[test]
    fn test_v1_archive_backward_compatibility() {
        use super::container::{
            ArchiveHeader, BlockDescriptor, FileEntryV1, SeekableIndexFooterV1,
            FLAG_HAS_SEEKABLE_FOOTER, HEADER_SIZE_BYTES, NXZ_MAGIC,
        };
        use super::pipeline::{read_archive_index, unpack_all};
        use super::router::CodecRoute;
        use std::io::Write;

        let tmp_root = std::env::temp_dir().join("nxz_v1_compat_test");
        let _ = fs::remove_dir_all(&tmp_root);
        fs::create_dir_all(&tmp_root).unwrap();
        let archive = tmp_root.join("legacy_v1.nxz");
        let out_dir = tmp_root.join("out_v1");

        let raw_payload = b"Legacy v1.x NXZ Archive Payload without modified_unix_secs timestamp!\n"
            .repeat(64);
        let uncompressed_blake3 = *blake3::hash(&raw_payload).as_bytes();
        let compressed_block = zstd::encode_all(raw_payload.as_slice(), 3).unwrap();
        let stored_blake3 = *blake3::hash(&compressed_block).as_bytes();

        let block_offset = HEADER_SIZE_BYTES as u64;
        let stored_size = compressed_block.len() as u64;
        let uncompressed_size = raw_payload.len() as u64;

        let footer_v1 = SeekableIndexFooterV1 {
            total_files: 1,
            total_uncompressed_bytes: uncompressed_size,
            total_stored_bytes: stored_size,
            encrypted: false,
            ecc_enabled: false,
            blocks: vec![BlockDescriptor {
                block_id: 0,
                codec_route: CodecRoute::HighSpeedZstd,
                archive_byte_offset: block_offset,
                stored_size,
                uncompressed_size,
                uncompressed_blake3,
                stored_blake3,
            }],
            files: vec![FileEntryV1 {
                relative_path: "video/legacy_clip.mp4".to_string(),
                original_size: uncompressed_size,
                file_blake3: uncompressed_blake3,
                block_id: 0,
                offset_in_block: 0,
                length_in_block: uncompressed_size,
                shannon_entropy_bpb: 4.12,
            }],
        };

        let serialized_v1 = bincode::serialize(&footer_v1).unwrap();
        let footer_blob = zstd::encode_all(serialized_v1.as_slice(), 9).unwrap();
        let footer_hash = blake3::hash(&footer_blob);
        let mut tag_prefix = [0u8; 8];
        tag_prefix.copy_from_slice(&footer_hash.as_bytes()[0..8]);

        let index_offset = block_offset + stored_size;
        let header_v1 = ArchiveHeader {
            magic: NXZ_MAGIC,
            version: 1,
            flags: FLAG_HAS_SEEKABLE_FOOTER,
            index_offset,
            index_stored_len: footer_blob.len() as u64,
            index_tag_prefix: tag_prefix,
            crypto_salt: [0u8; 32],
        };

        let mut f = fs::File::create(&archive).unwrap();
        header_v1.write_to(&mut f).unwrap();
        f.write_all(&compressed_block).unwrap();
        f.write_all(&footer_blob).unwrap();
        f.flush().unwrap();
        drop(f);

        let loaded_footer = read_archive_index(&archive).unwrap();
        assert_eq!(loaded_footer.total_files, 1);
        assert_eq!(loaded_footer.files[0].relative_path, "video/legacy_clip.mp4");
        assert_eq!(loaded_footer.files[0].modified_unix_secs, 0);

        let unpacked_footer = unpack_all(&archive, &out_dir).unwrap();
        assert_eq!(unpacked_footer.total_files, 1);
        let extracted_bytes = fs::read(out_dir.join("video/legacy_clip.mp4")).unwrap();
        assert_eq!(extracted_bytes, raw_payload);

        let _ = fs::remove_dir_all(&tmp_root);
    }

    #[test]
    fn test_zip_flag_0x08_data_descriptor_extraction() {
        use super::office::extract_standard_zip;
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write;

        let tmp_root = std::env::temp_dir().join("nxz_zip_flag08_test");
        let _ = fs::remove_dir_all(&tmp_root);
        fs::create_dir_all(&tmp_root).unwrap();
        let zip_path = tmp_root.join("streaming_flag08.zip");
        let out_dir = tmp_root.join("out");

        let file_name = b"docs/streamed.txt";
        let plain_content = b"ZIP mit Streaming-Flag 0x08 (Data Descriptor + Central Directory)!\n".repeat(40);
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&plain_content).unwrap();
        let comp_payload = encoder.finish().unwrap();

        let comp_size = comp_payload.len() as u32;
        let uncomp_size = plain_content.len() as u32;
        let name_len = file_name.len() as u16;

        let mut zip_bytes = Vec::new();
        // Local File Header with Flag 0x0008 and sizes = 0
        zip_bytes.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
        zip_bytes.extend_from_slice(&20u16.to_le_bytes());
        zip_bytes.extend_from_slice(&0x0008u16.to_le_bytes()); // Flag 0x08
        zip_bytes.extend_from_slice(&8u16.to_le_bytes()); // Deflate
        zip_bytes.extend_from_slice(&0u16.to_le_bytes());
        zip_bytes.extend_from_slice(&0u16.to_le_bytes());
        zip_bytes.extend_from_slice(&0u32.to_le_bytes()); // CRC = 0 in local header
        zip_bytes.extend_from_slice(&0u32.to_le_bytes()); // comp_size = 0 in local header
        zip_bytes.extend_from_slice(&0u32.to_le_bytes()); // uncomp_size = 0 in local header
        zip_bytes.extend_from_slice(&name_len.to_le_bytes());
        zip_bytes.extend_from_slice(&0u16.to_le_bytes());
        zip_bytes.extend_from_slice(file_name);
        zip_bytes.extend_from_slice(&comp_payload);

        // Data Descriptor (16 bytes)
        zip_bytes.extend_from_slice(&[0x50, 0x4B, 0x07, 0x08]);
        zip_bytes.extend_from_slice(&0u32.to_le_bytes());
        zip_bytes.extend_from_slice(&comp_size.to_le_bytes());
        zip_bytes.extend_from_slice(&uncomp_size.to_le_bytes());

        // Central Directory Header with real sizes
        let cd_offset = zip_bytes.len() as u32;
        zip_bytes.extend_from_slice(&[0x50, 0x4B, 0x01, 0x02]);
        zip_bytes.extend_from_slice(&20u16.to_le_bytes());
        zip_bytes.extend_from_slice(&20u16.to_le_bytes());
        zip_bytes.extend_from_slice(&0x0008u16.to_le_bytes());
        zip_bytes.extend_from_slice(&8u16.to_le_bytes());
        zip_bytes.extend_from_slice(&0u16.to_le_bytes());
        zip_bytes.extend_from_slice(&0u16.to_le_bytes());
        zip_bytes.extend_from_slice(&0u32.to_le_bytes());
        zip_bytes.extend_from_slice(&comp_size.to_le_bytes());
        zip_bytes.extend_from_slice(&uncomp_size.to_le_bytes());
        zip_bytes.extend_from_slice(&name_len.to_le_bytes());
        zip_bytes.extend_from_slice(&0u16.to_le_bytes());
        zip_bytes.extend_from_slice(&0u16.to_le_bytes());
        zip_bytes.extend_from_slice(&0u16.to_le_bytes());
        zip_bytes.extend_from_slice(&0u16.to_le_bytes());
        zip_bytes.extend_from_slice(&0u32.to_le_bytes());
        zip_bytes.extend_from_slice(&0u32.to_le_bytes()); // local_header_offset = 0
        zip_bytes.extend_from_slice(file_name);
        let cd_size = (zip_bytes.len() as u32) - cd_offset;

        // End of Central Directory (EOCD)
        zip_bytes.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]);
        zip_bytes.extend_from_slice(&0u16.to_le_bytes());
        zip_bytes.extend_from_slice(&0u16.to_le_bytes());
        zip_bytes.extend_from_slice(&1u16.to_le_bytes());
        zip_bytes.extend_from_slice(&1u16.to_le_bytes());
        zip_bytes.extend_from_slice(&cd_size.to_le_bytes());
        zip_bytes.extend_from_slice(&cd_offset.to_le_bytes());
        zip_bytes.extend_from_slice(&0u16.to_le_bytes());

        fs::write(&zip_path, &zip_bytes).unwrap();

        let (files, bytes) = extract_standard_zip(&zip_path, &out_dir).unwrap();
        assert_eq!(files, 1);
        assert_eq!(bytes, uncomp_size as u64);
        assert_eq!(fs::read(out_dir.join("docs/streamed.txt")).unwrap(), plain_content);

        let _ = fs::remove_dir_all(&tmp_root);
    }

    #[test]
    fn test_installer_paths_and_executable_detection() {
        use super::gui::format_size;
        use super::installer::{
            default_install_dir, desktop_shortcut_path, is_setup_executable_name,
            is_uninstall_executable_name, start_menu_shortcut_path,
        };
        use std::path::Path;

        assert!(is_setup_executable_name(Path::new(r"C:\Downloads\NXZ-Studio-Setup.exe")));
        assert!(is_setup_executable_name(Path::new("nxz_installer_v2.2.exe")));
        assert!(!is_setup_executable_name(Path::new(r"C:\Programs\NXZ Studio\NXZ-Studio.exe")));

        assert!(is_uninstall_executable_name(Path::new(r"C:\Programs\NXZ Studio\NXZ-Uninstall.exe")));
        assert!(!is_uninstall_executable_name(Path::new("NXZ-Studio-Setup.exe")));

        let install_dir = default_install_dir();
        assert!(install_dir.to_string_lossy().ends_with("NXZ Studio"));

        if let Some(desktop_lnk) = desktop_shortcut_path() {
            assert!(desktop_lnk.to_string_lossy().ends_with("NXZ Studio.lnk"));
        }
        if let Some(start_lnk) = start_menu_shortcut_path() {
            assert!(start_lnk.to_string_lossy().ends_with("NXZ Studio.lnk"));
        }

        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(2048), "2.0 KB");
        assert_eq!(format_size(1024 * 1024), "1.00 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.00 GB");
    }
}
