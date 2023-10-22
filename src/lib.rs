// Copyright 2016 chacha20-poly1305-aead Developers
// Copyright 2016 chacha20-poly1305-stream Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! A pure Rust implementation of the ChaCha20-Poly1305 AEAD from RFC 7539.
//!
//! An Authenticated Encryption with Associated Data (AEAD) mode
//! encrypts data and generates an authentication tag, or decrypts data
//! and verifies an authentication tag, as a single operation. The tag
//! can also validate additional authenticated data (AAD) which is not
//! included in the cyphertext, for instance a plaintext header.
//!
//! The ChaCha20-Poly1305 AEAD uses a 256-bit (32-byte) key, and a
//! 96-bit (12-byte) nonce. For each key, a given nonce should be used
//! only once, otherwise the encryption and authentication can be
//! broken. One way to prevent reuse is for the nonce to contain a
//! sequence number.
//!
//! The amount of data that can be encrypted in a single call is 2^32 - 1
//! blocks of 64 bytes, slightly less than 256 GiB.

#![warn(missing_docs)]

#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]
#![cfg_attr(feature = "clippy", warn(clippy_pedantic))]

#![cfg_attr(all(feature = "bench", test), feature(test))]
#![cfg_attr(feature = "simd", feature(platform_intrinsics, repr_simd))]
#![cfg_attr(feature = "simd_opt", feature(cfg_target_feature))]

extern crate constant_time_eq;
#[cfg(all(feature = "bench", test))]
extern crate test;

pub use stream_decryptor::ChaCha20Poly1305StreamDecryptor;
pub use stream_encryptor::ChaCha20Poly1305StreamEncryptor;

mod as_bytes;

mod simdty;
mod simdint;
mod simdop;
mod simd_opt;
mod simd;

mod chacha20;
mod poly1305;
// mod aead;
mod stream_util;
mod stream_encryptor;
mod stream_decryptor;

/// ChaCha20Policy Encrypt
pub fn chacha20_poly1305_encrypt(key: &[u8], nonce: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    chacha20_poly1305_aad_encrypt(key, nonce, &[], message)
}

/// ChaCha20Policy Decrypt
pub fn chacha20_poly1305_decrypt(key: &[u8], nonce: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    chacha20_poly1305_aad_decrypt(key, nonce, &[], message)
}

/// ChaCha20Policy Encrypt with AAD
pub fn chacha20_poly1305_aad_encrypt(key: &[u8], nonce: &[u8], aad: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let mut encryptor = ChaCha20Poly1305StreamEncryptor::new(key, nonce)?;
    if !aad.is_empty() { encryptor.init_adata(aad); }
    let mut b1 = encryptor.update(message);
    let (last_block, tag) = encryptor.finalize();
    b1.extend_from_slice(&last_block);
    b1.extend_from_slice(&tag);
    Ok(b1)
}

/// ChaCha20Policy Decrypt with AAD
pub fn chacha20_poly1305_aad_decrypt(key: &[u8], nonce: &[u8], aad: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let mut decryptor = ChaCha20Poly1305StreamDecryptor::new(key, nonce)?;
    if !aad.is_empty() { decryptor.init_adata(aad); }
    let mut b1 = decryptor.update(message);
    let last_block = decryptor.finalize()?;
    b1.extend_from_slice(&last_block);
    Ok(b1)
}

/// Runs the self-test for ChaCha20, Poly1305
#[cold]
pub fn selftest() {
    chacha20::selftest();
    poly1305::selftest();
}

#[test]
fn test_enc_dec() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad = b"hello world";
    let plaintext = [0u8; 1000];

    let ciphertext = chacha20_poly1305_aad_encrypt(&key, &nonce, aad, &plaintext).unwrap();

    let mut output = vec![];
    let mut plaintext = plaintext.to_vec();
    let tag = chacha20_poly1305_aead::encrypt(
        &key, &nonce, &aad[..], &mut plaintext, &mut output).unwrap();
    output.extend_from_slice(&tag);

    assert_eq!(ciphertext, output);

    let plaintext_decrypted = chacha20_poly1305_aad_decrypt(&key, &nonce, aad, &ciphertext).unwrap();
    assert_eq!(plaintext, plaintext_decrypted);
}

#[test]
fn test_rfc_7539() {
    let key = hex::decode(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
    let nonce = hex::decode("070000004041424344454647").unwrap();
    let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
    let plaintext = hex::decode(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f6620\
        2739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666\
        f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e").unwrap();

    let expected_ciphertext = hex::decode(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca\
        9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091\
        b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116").unwrap();
    let expected_tag = hex::decode("1ae10b594f09e26a7e902ecbd0600691").unwrap();

    let mut encryptor = ChaCha20Poly1305StreamEncryptor::new(&key, &nonce).unwrap();
    encryptor.init_adata(&aad);
    let mut ciphertext = encryptor.update(&plaintext);
    let (last_block, tag) = encryptor.finalize();
    ciphertext.extend_from_slice(&last_block);

    assert_eq!(expected_ciphertext, ciphertext);
    assert_eq!(expected_tag, tag);
}