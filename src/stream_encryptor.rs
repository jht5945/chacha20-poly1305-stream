use crate::as_bytes::AsBytes;
use crate::chacha20::ChaCha20;
use crate::poly1305::Poly1305;
use crate::simd::u32x4;
use crate::stream_util;

/// ChaCha20Poly1203 Stream Encryptor
pub struct ChaCha20Poly1305StreamEncryptor {
    chacha20: ChaCha20,
    message_buffer: Vec<u8>,
    poly1305: Poly1305,
    adata_len: u64,
    message_len: u64,
}

impl ChaCha20Poly1305StreamEncryptor {
    /// New ChaCha20Poly1305StreamEncryptor
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self, String> {
        stream_util::verify_key_nonce_length(key, nonce)?;

        let mut chacha20 = ChaCha20::new(key, nonce);
        let poly1305 = Poly1305::new(&chacha20.next().as_bytes()[..32]);
        Ok(Self {
            chacha20,
            message_buffer: vec![],
            poly1305,
            adata_len: 0,
            message_len: 0,
        })
    }

    /// Initialize AAD
    pub fn init_adata(&mut self, adata: &[u8]) {
        if !adata.is_empty() {
            self.adata_len += adata.len() as u64;
            self.poly1305.padded_blocks(adata);
        }
    }

    /// Update plaintext message
    pub fn update(&mut self, message: &[u8]) -> Vec<u8> {
        self.message_buffer.extend_from_slice(message);
        let mut buf = [u32x4::default(); 4];
        let b_len = buf.as_bytes().len();

        let b_count = self.message_buffer.len() / b_len;
        if b_count == 0 {
            return vec![];
        }

        let mut encrypted = Vec::with_capacity(b_len * b_count);
        for i in 0..b_count {
            buf.as_mut_bytes()
                .copy_from_slice(&self.message_buffer[(b_len * i)..(b_len * (i + 1))]);
            stream_util::next_chacha20_xor(&mut self.chacha20, &mut buf);
            self.poly1305.padded_blocks(buf.as_bytes());
            encrypted.extend_from_slice(buf.as_bytes());
        }
        self.message_buffer = self.message_buffer[(b_len * b_count)..].to_vec();
        self.message_len += encrypted.len() as u64;
        encrypted
    }

    /// Finalize encrypt
    pub fn finalize(mut self) -> (Vec<u8>, Vec<u8>) {
        let mut last_block = vec![];
        if !self.message_buffer.is_empty() {
            let mut buf = [u32x4::default(); 4];
            let buf_bytes = buf.as_mut_bytes();
            buf_bytes[..self.message_buffer.len()].copy_from_slice(&self.message_buffer[..]);
            stream_util::next_chacha20_xor(&mut self.chacha20, &mut buf);
            let last_block_bytes = &buf.as_bytes()[0..self.message_buffer.len()];
            self.poly1305.padded_blocks(last_block_bytes);
            last_block.extend_from_slice(last_block_bytes);
            self.message_len += last_block.len() as u64;
        }

        self.poly1305.block([self.adata_len.to_le(), self.message_len.to_le()].as_bytes());
        let tag = self.poly1305.tag().as_bytes().to_vec();

        (last_block, tag)
    }
}

#[test]
fn test_stream_001() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let plaintext = [0u8; 1000];
    let mut encryptor = ChaCha20Poly1305StreamEncryptor::new(&key, &nonce).unwrap();
    let mut b1 = encryptor.update(&plaintext);
    let (b2, t) = encryptor.finalize();
    b1.extend_from_slice(&b2);

    let mut output = vec![];
    let mut plaintext = plaintext.to_vec();
    let tag = chacha20_poly1305_aead::encrypt(
        &key, &nonce, &[], &mut plaintext, &mut output).unwrap();

    assert_eq!(b1, output);
    assert_eq!(t, tag.to_vec());
}

#[test]
fn test_stream_002() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad = b"hello world";
    let plaintext = [0u8; 1000];
    let mut encryptor = ChaCha20Poly1305StreamEncryptor::new(&key, &nonce).unwrap();
    encryptor.init_adata(&aad[..]);
    let mut b1 = encryptor.update(&plaintext);
    let (b2, t) = encryptor.finalize();
    b1.extend_from_slice(&b2);

    let mut output = vec![];
    let mut plaintext = plaintext.to_vec();
    let tag = chacha20_poly1305_aead::encrypt(
        &key, &nonce, &aad[..], &mut plaintext, &mut output).unwrap();

    assert_eq!(b1, output);
    assert_eq!(t, tag.to_vec());
}

#[test]
fn test_stream_003() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad = b"hello world";
    let plaintext = [0u8; 1000];
    let mut encryptor = ChaCha20Poly1305StreamEncryptor::new(&key, &nonce).unwrap();
    encryptor.init_adata(&aad[..]);
    let mut b1 = vec![];
    for _ in 0..1000 {
        b1.extend_from_slice(&encryptor.update(&[0u8]));
    }
    let (b2, t) = encryptor.finalize();
    b1.extend_from_slice(&b2);

    let mut output = vec![];
    let mut plaintext = plaintext.to_vec();
    let tag = chacha20_poly1305_aead::encrypt(
        &key, &nonce, &aad[..], &mut plaintext, &mut output).unwrap();

    assert_eq!(b1, output);
    assert_eq!(t, tag.to_vec());
}