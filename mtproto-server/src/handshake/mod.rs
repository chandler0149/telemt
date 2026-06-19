use crate::crypto::{sha256, AesCtr};
use crate::protocol::constants::{DC_IDX_POS, HANDSHAKE_LEN, PREKEY_LEN, PROTO_TAG_POS};
use crate::protocol::tls;
use crate::protocol::ProtoTag;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Length of the secret in bytes (matches ACCESS_SECRET_BYTES in telemt)
pub const MTPROTO_SECRET_BYTES: usize = 16;

#[derive(Clone, Copy)]
pub struct ParsedTlsAuthMaterial {
    pub digest: [u8; tls::TLS_DIGEST_LEN],
    pub session_id: [u8; 32],
    pub session_id_len: usize,
    pub now: i64,
    pub ignore_time_skew: bool,
    pub boot_time_cap_secs: u32,
}

#[derive(Clone, Copy)]
pub struct TlsCandidateValidation {
    pub digest: [u8; tls::TLS_DIGEST_LEN],
    pub session_id: [u8; 32],
    pub session_id_len: usize,
}

pub struct MtprotoCandidateValidation {
    pub proto_tag: ProtoTag,
    pub dc_idx: i16,
    pub dec_key: [u8; 32],
    pub dec_iv: u128,
    pub enc_key: [u8; 32],
    pub enc_iv: u128,
    pub decryptor: AesCtr,
    pub encryptor: AesCtr,
}

pub fn parse_tls_auth_material(
    handshake: &[u8],
    ignore_time_skew: bool,
    replay_window_secs: u64,
) -> Option<ParsedTlsAuthMaterial> {
    if handshake.len() < tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 {
        return None;
    }

    let digest: [u8; tls::TLS_DIGEST_LEN] = handshake
        [tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN]
        .try_into()
        .ok()?;

    let session_id_len_pos = tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN;
    let session_id_len = usize::from(handshake.get(session_id_len_pos).copied()?);
    if session_id_len > 32 {
        return None;
    }
    let session_id_start = session_id_len_pos + 1;
    if handshake.len() < session_id_start + session_id_len {
        return None;
    }

    let mut session_id = [0u8; 32];
    session_id[..session_id_len]
        .copy_from_slice(&handshake[session_id_start..session_id_start + session_id_len]);

    let now = if !ignore_time_skew {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        i64::try_from(d.as_secs()).ok()?
    } else {
        0_i64
    };

    let replay_window_u32 = u32::try_from(replay_window_secs).unwrap_or(u32::MAX);
    let boot_time_cap_secs = if ignore_time_skew {
        0
    } else {
        tls::BOOT_TIME_MAX_SECS
            .min(replay_window_u32)
            .min(tls::BOOT_TIME_COMPAT_MAX_SECS)
    };

    Some(ParsedTlsAuthMaterial {
        digest,
        session_id,
        session_id_len,
        now,
        ignore_time_skew,
        boot_time_cap_secs,
    })
}

pub fn compute_tls_hmac_zeroed_digest(secret: &[u8], handshake: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&handshake[..tls::TLS_DIGEST_POS]);
    mac.update(&[0u8; tls::TLS_DIGEST_LEN]);
    mac.update(&handshake[tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN..]);
    mac.finalize().into_bytes().into()
}

pub fn validate_tls_secret_candidate(
    parsed: &ParsedTlsAuthMaterial,
    handshake: &[u8],
    secret: &[u8],
) -> Option<TlsCandidateValidation> {
    let computed = compute_tls_hmac_zeroed_digest(secret, handshake);
    if !bool::from(parsed.digest[..28].ct_eq(&computed[..28])) {
        return None;
    }

    let timestamp = u32::from_le_bytes([
        parsed.digest[28] ^ computed[28],
        parsed.digest[29] ^ computed[29],
        parsed.digest[30] ^ computed[30],
        parsed.digest[31] ^ computed[31],
    ]);

    if !parsed.ignore_time_skew {
        let is_boot_time = parsed.boot_time_cap_secs > 0 && timestamp < parsed.boot_time_cap_secs;
        if !is_boot_time {
            let time_diff = parsed.now - i64::from(timestamp);
            if !(tls::TIME_SKEW_MIN..=tls::TIME_SKEW_MAX).contains(&time_diff) {
                return None;
            }
        }
    }

    Some(TlsCandidateValidation {
        digest: parsed.digest,
        session_id: parsed.session_id,
        session_id_len: parsed.session_id_len,
    })
}

pub fn validate_mtproto_secret_candidate(
    handshake: &[u8; HANDSHAKE_LEN],
    dec_prekey: &[u8; PREKEY_LEN],
    dec_iv: u128,
    enc_prekey: &[u8; PREKEY_LEN],
    enc_iv: u128,
    secret: &[u8; MTPROTO_SECRET_BYTES],
) -> Option<MtprotoCandidateValidation> {
    let mut dec_key_input = Zeroizing::new(Vec::with_capacity(PREKEY_LEN + secret.len()));
    dec_key_input.extend_from_slice(dec_prekey);
    dec_key_input.extend_from_slice(secret);
    let dec_key = Zeroizing::new(sha256(&dec_key_input));

    let mut decryptor = AesCtr::new(&dec_key, dec_iv);
    let mut decrypted = *handshake;
    decryptor.apply(&mut decrypted);

    let tag_bytes: [u8; 4] = [
        decrypted[PROTO_TAG_POS],
        decrypted[PROTO_TAG_POS + 1],
        decrypted[PROTO_TAG_POS + 2],
        decrypted[PROTO_TAG_POS + 3],
    ];
    let proto_tag = ProtoTag::from_bytes(tag_bytes)?;

    let dc_idx = i16::from_le_bytes([decrypted[DC_IDX_POS], decrypted[DC_IDX_POS + 1]]);

    let mut enc_key_input = Zeroizing::new(Vec::with_capacity(PREKEY_LEN + secret.len()));
    enc_key_input.extend_from_slice(enc_prekey);
    enc_key_input.extend_from_slice(secret);
    let enc_key = Zeroizing::new(sha256(&enc_key_input));

    let encryptor = AesCtr::new(&enc_key, enc_iv);

    Some(MtprotoCandidateValidation {
        proto_tag,
        dc_idx,
        dec_key: *dec_key,
        dec_iv,
        enc_key: *enc_key,
        enc_iv,
        decryptor,
        encryptor,
    })
}
