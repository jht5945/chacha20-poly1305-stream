use crate::chacha20::ChaCha20;
use crate::simdty::Simd4;

pub(crate) fn next_chacha20_xor(chacha20: &mut ChaCha20, buf: &mut [Simd4<u32>; 4]) {
    let block = chacha20.next();
    buf[0] = buf[0] ^ block[0];
    buf[1] = buf[1] ^ block[1];
    buf[2] = buf[2] ^ block[2];
    buf[3] = buf[3] ^ block[3];
}