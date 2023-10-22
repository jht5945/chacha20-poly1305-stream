use crate::chacha20::ChaCha20;
use crate::simdty::Simd4;

const CHACHA20_POLY1305_KEY_LEN: usize = 32;
const CHACHA20_POLY1305_NONCE_LEN: usize = 12;

#[inline]
pub(crate) fn next_chacha20_xor(chacha20: &mut ChaCha20, buf: &mut [Simd4<u32>; 4]) {
    let block = chacha20.next();
    buf[0] = buf[0] ^ block[0];
    buf[1] = buf[1] ^ block[1];
    buf[2] = buf[2] ^ block[2];
    buf[3] = buf[3] ^ block[3];
}

pub(crate) fn verify_key_nonce_length(key: &[u8], nonce: &[u8]) -> Result<(), String> {
    if key.len() != CHACHA20_POLY1305_KEY_LEN {
        return Err("Bad key length".to_string());
    }
    if nonce.len() != CHACHA20_POLY1305_NONCE_LEN {
        return Err("Bad nonce length".to_string());
    }
    Ok(())
}