use crate::error::NxzError;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};

pub const SALT_LEN: usize = 32;
pub const FOOTER_AAD_BLOCK_ID: u32 = 0xFFFF_FFFF;

pub fn derive_master_key(password: &str, salt: &[u8; SALT_LEN]) -> Result<[u8; 32], NxzError> {
    let params = Params::new(65_536, 3, 4, Some(32))
        .map_err(|e| NxzError::CryptoError(format!("Argon2 parameter error: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| NxzError::CryptoError(format!("Argon2 key derivation failed: {e}")))?;
    Ok(key)
}

fn derive_block_nonce(master_key: &[u8; 32], salt: &[u8; SALT_LEN], block_id: u32) -> XNonce {
    let mut context_input = [0u8; 36];
    context_input[0..32].copy_from_slice(salt);
    context_input[32..36].copy_from_slice(&block_id.to_le_bytes());

    let hash = blake3::keyed_hash(master_key, &context_input);
    let mut nonce_bytes = [0u8; 24];
    nonce_bytes.copy_from_slice(&hash.as_bytes()[0..24]);
    *XNonce::from_slice(&nonce_bytes)
}

pub fn encrypt_block_aead(
    plaintext: &[u8],
    master_key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    block_id: u32,
) -> Result<Vec<u8>, NxzError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(master_key));
    let nonce = derive_block_nonce(master_key, salt, block_id);
    let aad = block_id.to_le_bytes();

    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| NxzError::CryptoError(format!("AEAD encryption failed for block #{block_id}")))
}

pub fn decrypt_block_aead(
    ciphertext: &[u8],
    master_key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    block_id: u32,
) -> Result<Vec<u8>, NxzError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(master_key));
    let nonce = derive_block_nonce(master_key, salt, block_id);
    let aad = block_id.to_le_bytes();

    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| {
            NxzError::CryptoError(
                "AEAD authentication failed (wrong password or archive tampered)".to_string(),
            )
        })
}
