use aes_gcm::aead::{AeadInPlace, KeyInit as AeadKeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce as GcmNonce};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384};

use crate::tls_types::*;

/// Result of a TLS 1.2 PRF key expansion.
#[allow(dead_code)]
struct KeyBlock {
    client_write_mac_key: Vec<u8>,
    server_write_mac_key: Vec<u8>,
    client_write_key: Vec<u8>,
    server_write_key: Vec<u8>,
    client_write_iv: Vec<u8>,
    server_write_iv: Vec<u8>,
}

/// TLS PRF function using HMAC (TLS 1.2 uses SHA-256 or SHA-384).
fn tls12_prf(
    hash: PrfHash,
    secret: &[u8],
    label: &str,
    seed: &[u8],
    out_len: usize,
) -> Vec<u8> {
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label.as_bytes());
    label_seed.extend_from_slice(seed);

    match hash {
        PrfHash::Sha256 => p_hash::<Hmac<Sha256>>(&label_seed, secret, out_len),
        PrfHash::Sha384 => p_hash::<Hmac<Sha384>>(&label_seed, secret, out_len),
    }
}

#[derive(Clone, Copy)]
enum PrfHash {
    Sha256,
    Sha384,
}

/// P_hash function from RFC 5246 section 5.
fn p_hash<M: Mac + KeyInit + Clone>(seed: &[u8], secret: &[u8], out_len: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(out_len);
    // A(0) = seed
    // A(i) = HMAC_hash(secret, A(i-1))
    let mut a = {
        let mut mac = <M as KeyInit>::new_from_slice(secret)
            .expect("HMAC key should be valid");
        mac.update(seed);
        mac.finalize().into_bytes().to_vec()
    };

    while result.len() < out_len {
        // HMAC_hash(secret, A(i) + seed)
        let mut mac = <M as KeyInit>::new_from_slice(secret)
            .expect("HMAC key should be valid");
        mac.update(&a);
        mac.update(seed);
        let output = mac.finalize().into_bytes();
        let to_copy = (out_len - result.len()).min(output.len());
        result.extend_from_slice(&output[..to_copy]);

        // A(i+1) = HMAC_hash(secret, A(i))
        let mut mac = <M as KeyInit>::new_from_slice(secret)
            .expect("HMAC key should be valid");
        mac.update(&a);
        a = mac.finalize().into_bytes().to_vec();
    }

    result
}

/// Generate the key block from the master secret (TLS 1.2).
fn generate_key_block(
    cs: &CipherSuite,
    master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Option<KeyBlock> {
    let mac_len = digest_len(cs.dig);
    let (key_len, iv_len) = cipher_key_iv_len(cs);

    let needed = mac_len * 2 + key_len * 2 + iv_len * 2;

    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);

    let prf_hash = match cs.dig {
        Digest::Sha384 => PrfHash::Sha384,
        _ => PrfHash::Sha256,
    };

    let key_block = tls12_prf(prf_hash, master_secret, "key expansion", &seed, needed);

    let mut offset = 0;
    let client_write_mac_key = key_block[offset..offset + mac_len].to_vec();
    offset += mac_len;
    let server_write_mac_key = key_block[offset..offset + mac_len].to_vec();
    offset += mac_len;
    let client_write_key = key_block[offset..offset + key_len].to_vec();
    offset += key_len;
    let server_write_key = key_block[offset..offset + key_len].to_vec();
    offset += key_len;
    let client_write_iv = key_block[offset..offset + iv_len].to_vec();
    offset += iv_len;
    let server_write_iv = key_block[offset..offset + iv_len].to_vec();
    let _ = offset;

    Some(KeyBlock {
        client_write_mac_key,
        server_write_mac_key,
        client_write_key,
        server_write_key,
        client_write_iv,
        server_write_iv,
    })
}

fn digest_len(dig: Digest) -> usize {
    match dig {
        Digest::Md5 => 16,
        Digest::Sha1 => 20,
        Digest::Sha256 => 32,
        Digest::Sha384 => 48,
        Digest::Na => 0,
    }
}

fn cipher_key_iv_len(cs: &CipherSuite) -> (usize, usize) {
    let key_len = match cs.enc {
        Enc::Aes128 => 16,
        Enc::Aes256 => 32,
        Enc::Chacha20 => 32,
        Enc::TripleDes => 24,
        Enc::Rc4 => 16,
        Enc::Null => 0,
        _ => 16, // fallback
    };

    let iv_len = match cs.mode {
        CipherMode::Gcm | CipherMode::Ccm | CipherMode::Ccm8 => 4,
        CipherMode::Poly1305 => 12,
        CipherMode::Cbc => match cs.enc {
            Enc::Aes128 | Enc::Aes256 => 16,
            Enc::TripleDes => 8,
            _ => 16,
        },
        CipherMode::Stream => 0,
    };

    (key_len, iv_len)
}

/// Attempt to decrypt a TLS 1.2 application data record with a candidate master secret.
/// Returns true if the decryption and authentication tag verification succeed.
pub fn try_decrypt_tls12(
    cs: &CipherSuite,
    master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    record: &TlsRecord,
) -> bool {
    if master_secret.len() != SSL_MASTER_SECRET_LENGTH {
        return false;
    }

    let key_block = match generate_key_block(cs, master_secret, client_random, server_random) {
        Some(kb) => kb,
        None => return false,
    };

    // We attempt to decrypt with the client write key (seq=1, as the first application data
    // record follows the Finished message at seq=0).
    decrypt_aead_record(
        cs,
        &key_block.client_write_key,
        &key_block.client_write_iv,
        record,
        1, // sequence number
        TLSV1DOT2_VERSION,
    )
}

/// Decrypt a single AEAD record (GCM, CCM, or POLY1305).
fn decrypt_aead_record(
    cs: &CipherSuite,
    key: &[u8],
    iv_base: &[u8],
    record: &TlsRecord,
    seq: u64,
    version: u16,
) -> bool {
    let auth_tag_len: usize = match cs.mode {
        CipherMode::Gcm | CipherMode::Ccm | CipherMode::Poly1305 => 16,
        CipherMode::Ccm8 => 8,
        _ => return false,
    };

    let is_v12 = version == TLSV1DOT2_VERSION;
    let data = &record.data;

    let (nonce, ciphertext, tag) = if is_v12 && cs.mode != CipherMode::Poly1305 {
        // TLS 1.2 with explicit nonce: [8 bytes explicit nonce] [ciphertext] [tag]
        if data.len() < 8 + auth_tag_len {
            return false;
        }
        let explicit_nonce = &data[..8];
        let ct_and_tag = &data[8..];
        if ct_and_tag.len() < auth_tag_len {
            return false;
        }
        let ct_len = ct_and_tag.len() - auth_tag_len;
        let ciphertext = &ct_and_tag[..ct_len];
        let tag = &ct_and_tag[ct_len..];

        // Nonce = implicit (4 bytes from IV) || explicit (8 bytes)
        let mut nonce = [0u8; 12];
        nonce[..iv_base.len().min(4)].copy_from_slice(&iv_base[..iv_base.len().min(4)]);
        nonce[4..12].copy_from_slice(explicit_nonce);
        (nonce, ciphertext.to_vec(), tag.to_vec())
    } else {
        // TLS 1.3 or ChaCha20-Poly1305: nonce is XOR of IV with sequence number
        if data.len() < auth_tag_len {
            return false;
        }
        let ct_len = data.len() - auth_tag_len;
        let ciphertext = &data[..ct_len];
        let tag = &data[ct_len..];

        let mut nonce = [0u8; 12];
        if iv_base.len() == 12 {
            nonce.copy_from_slice(iv_base);
        }
        // XOR sequence number into the last 8 bytes
        let seq_bytes = seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        (nonce, ciphertext.to_vec(), tag.to_vec())
    };

    // Construct AAD
    let aad = if is_v12 && cs.mode != CipherMode::Poly1305 {
        // TLS 1.2 AAD: seq(8) || type(1) || version(2) || length(2)
        let ct_len = ciphertext.len() as u16;
        let mut aad = [0u8; 13];
        aad[..8].copy_from_slice(&seq.to_be_bytes());
        aad[8] = SSL_ID_APP_DATA;
        aad[9] = (record.version >> 8) as u8;
        aad[10] = record.version as u8;
        aad[11] = (ct_len >> 8) as u8;
        aad[12] = ct_len as u8;
        aad.to_vec()
    } else if version == TLSV1DOT3_VERSION {
        // TLS 1.3 AAD: type(1) || version(2) || length(2)
        let mut aad = [0u8; 5];
        aad[0] = SSL_ID_APP_DATA;
        aad[1] = (record.version >> 8) as u8;
        aad[2] = record.version as u8;
        let total_len = record.data.len() as u16;
        aad[3] = (total_len >> 8) as u8;
        aad[4] = total_len as u8;
        aad.to_vec()
    } else {
        Vec::new()
    };

    // Perform AEAD decryption + tag verification
    match (cs.mode, cs.enc) {
        (CipherMode::Gcm, Enc::Aes128) => {
            try_aes128_gcm_decrypt(key, &nonce, &aad, &ciphertext, &tag)
        }
        (CipherMode::Gcm, Enc::Aes256) => {
            try_aes256_gcm_decrypt(key, &nonce, &aad, &ciphertext, &tag)
        }
        (CipherMode::Poly1305, Enc::Chacha20) => {
            try_chacha20_poly1305_decrypt(key, &nonce, &aad, &ciphertext, &tag)
        }
        _ => false,
    }
}

fn try_aes128_gcm_decrypt(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> bool {
    let cipher = match <Aes128Gcm as AeadKeyInit>::new_from_slice(key) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let nonce = GcmNonce::from_slice(nonce);
    let mut buffer = ciphertext.to_vec();
    buffer.extend_from_slice(tag);
    cipher.decrypt_in_place(nonce, aad, &mut buffer).is_ok()
}

fn try_aes256_gcm_decrypt(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> bool {
    let cipher = match <Aes256Gcm as AeadKeyInit>::new_from_slice(key) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let nonce = GcmNonce::from_slice(nonce);
    let mut buffer = ciphertext.to_vec();
    buffer.extend_from_slice(tag);
    cipher.decrypt_in_place(nonce, aad, &mut buffer).is_ok()
}

fn try_chacha20_poly1305_decrypt(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> bool {
    let cipher = match <ChaCha20Poly1305 as AeadKeyInit>::new_from_slice(key) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let nonce = chacha20poly1305::Nonce::from_slice(nonce);
    let mut buffer = ciphertext.to_vec();
    buffer.extend_from_slice(tag);
    cipher.decrypt_in_place(nonce, aad, &mut buffer).is_ok()
}

// ============================================================================
// TLS 1.3 decryption
// ============================================================================

/// HKDF-Expand-Label as defined in RFC 8446 section 7.1.
fn hkdf_expand_label(
    hash: PrfHash,
    secret: &[u8],
    label: &str,
    context: &[u8],
    out_len: u16,
) -> Option<Vec<u8>> {
    let prefix = b"tls13 ";
    let full_label_len = prefix.len() + label.len();

    // Build HkdfLabel struct
    let mut info = Vec::with_capacity(2 + 1 + full_label_len + 1 + context.len());
    info.push((out_len >> 8) as u8);
    info.push(out_len as u8);
    info.push(full_label_len as u8);
    info.extend_from_slice(prefix);
    info.extend_from_slice(label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    // HKDF-Expand: T(1) = HMAC-Hash(PRK, info || 0x01)
    match hash {
        PrfHash::Sha256 => {
            let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret).ok()?;
            mac.update(&info);
            mac.update(&[0x01]);
            let result = mac.finalize().into_bytes();
            if (out_len as usize) > result.len() {
                return None;
            }
            Some(result[..out_len as usize].to_vec())
        }
        PrfHash::Sha384 => {
            let mut mac = <Hmac<Sha384> as KeyInit>::new_from_slice(secret).ok()?;
            mac.update(&info);
            mac.update(&[0x01]);
            let result = mac.finalize().into_bytes();
            if (out_len as usize) > result.len() {
                return None;
            }
            Some(result[..out_len as usize].to_vec())
        }
    }
}

/// Derive key and IV from a TLS 1.3 traffic secret, then attempt to decrypt a record.
pub fn try_decrypt_tls13(
    cs: &CipherSuite,
    candidate_secret: &[u8],
    record: &TlsRecord,
    seq: u64,
) -> bool {
    let hash = match cs.dig {
        Digest::Sha384 => PrfHash::Sha384,
        _ => PrfHash::Sha256,
    };

    let key_len = match cs.enc {
        Enc::Aes128 => 16u16,
        Enc::Aes256 => 32,
        Enc::Chacha20 => 32,
        _ => return false,
    };

    let key = match hkdf_expand_label(hash, candidate_secret, "key", &[], key_len) {
        Some(k) => k,
        None => return false,
    };
    let iv = match hkdf_expand_label(hash, candidate_secret, "iv", &[], 12) {
        Some(i) => i,
        None => return false,
    };

    decrypt_aead_record(cs, &key, &iv, record, seq, TLSV1DOT3_VERSION)
}
