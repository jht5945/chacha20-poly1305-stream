use crate::as_bytes::AsBytes;
use crate::chacha20::ChaCha20;
use crate::poly1305::Poly1305;
use crate::simd::u32x4;
use crate::stream_util;

/// ChaCha20Poly1203 Stream Decryptor
pub struct ChaCha20Poly1305StreamDecryptor {
    chacha20: ChaCha20,
    message_buffer: Vec<u8>,
    poly1305: Poly1305,
    adata_len: u64,
    message_len: u64,
}

impl ChaCha20Poly1305StreamDecryptor {
    /// New ChaCha20Poly1305StreamDecryptor
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self, String> {
        if key.len() != 32 { return Err("Bad key length".to_string()); }
        if nonce.len() != 12 { return Err("Bad nonce length".to_string()); }
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

    /// Update encrypted message
    pub fn update(&mut self, message: &[u8]) -> Vec<u8> {
        self.message_buffer.extend_from_slice(message);
        let mut buf = [u32x4::default(); 4];
        let b_len = buf.as_bytes().len();

        let valid_message_len = if self.message_buffer.len() >= 16 { self.message_buffer.len() - 16 } else { 0 };
        let b_count = valid_message_len / b_len;
        if b_count == 0 {
            return vec![];
        }

        let mut decrypted = Vec::with_capacity(b_len * b_count);
        for i in 0..b_count {
            let encrypted = &self.message_buffer[(b_len * i)..(b_len * (i + 1))];
            self.poly1305.padded_blocks(encrypted);
            buf.as_mut_bytes().copy_from_slice(encrypted);
            stream_util::next_chacha20_xor(&mut self.chacha20, &mut buf);
            decrypted.extend_from_slice(buf.as_bytes());
        }
        self.message_buffer = self.message_buffer[(b_len * b_count)..].to_vec();
        self.message_len += decrypted.len() as u64;
        decrypted
    }

    /// Finalize decrypt
    pub fn finalize(mut self) -> Result<Vec<u8>, String> {
        let mut last_block = vec![];
        if self.message_buffer.len() < 16 {
            return Err("Bad tag length".to_string());
        }
        let message_buffer_len = self.message_buffer.len() - 16;
        if message_buffer_len > 0 {
            let mut buf = [u32x4::default(); 4];
            let buf_bytes = buf.as_mut_bytes();
            let encrypted = &self.message_buffer[..message_buffer_len];
            buf_bytes[..message_buffer_len].copy_from_slice(encrypted);
            stream_util::next_chacha20_xor(&mut self.chacha20, &mut buf);
            let last_block_bytes = &buf.as_bytes()[..message_buffer_len];
            self.poly1305.padded_blocks(encrypted);
            last_block.extend_from_slice(last_block_bytes);
            self.message_len += last_block.len() as u64;
        }
        let message_tag = &self.message_buffer[message_buffer_len..];

        self.poly1305.block([self.adata_len.to_le(), self.message_len.to_le()].as_bytes());

        let mut tag = [0; 16];
        tag.clone_from_slice(self.poly1305.tag().as_bytes());
        if message_tag != tag {
            Err(format!("Tag mismatch, expected: {}, actual: {}",
                        hex::encode(tag), hex::encode(message_tag)))
        } else {
            Ok(last_block)
        }
    }
}

#[test]
fn test_stream_001() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let plaintext = [0u8; 1000];

    let mut output = vec![];
    let mut plaintext = plaintext.to_vec();
    let tag = chacha20_poly1305_aead::encrypt(
        &key, &nonce, &[], &mut plaintext, &mut output).unwrap();

    let mut decryptor = ChaCha20Poly1305StreamDecryptor::new(&key, &nonce).unwrap();
    let mut m1 = decryptor.update(&output);
    let m2 = decryptor.update(&tag);
    let m3 = decryptor.finalize().unwrap();
    m1.extend_from_slice(&m2);
    m1.extend_from_slice(&m3);

    assert_eq!(&plaintext[..], &m1);
}

#[test]
fn test_stream_002() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad = b"hello world";
    let plaintext = [0u8; 1000];

    let mut output = vec![];
    let mut plaintext = plaintext.to_vec();
    let tag = chacha20_poly1305_aead::encrypt(
        &key, &nonce, &aad[..], &mut plaintext, &mut output).unwrap();

    let mut decryptor = ChaCha20Poly1305StreamDecryptor::new(&key, &nonce).unwrap();
    decryptor.init_adata(&aad[..]);
    let mut m1 = decryptor.update(&output);
    let m2 = decryptor.update(&tag);
    let m3 = decryptor.finalize().unwrap();
    m1.extend_from_slice(&m2);
    m1.extend_from_slice(&m3);

    assert_eq!(&plaintext[..], &m1);
}

#[test]
fn test_stream_003() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad = b"hello world";
    let plaintext = [0u8; 1000];

    let mut output = vec![];
    let mut plaintext = plaintext.to_vec();
    let tag = chacha20_poly1305_aead::encrypt(
        &key, &nonce, &aad[..], &mut plaintext, &mut output).unwrap();

    let mut decryptor = ChaCha20Poly1305StreamDecryptor::new(&key, &nonce).unwrap();
    decryptor.init_adata(&aad[..]);
    let mut m1 = vec![];
    output.iter().for_each(|c| {
        m1.extend_from_slice(&decryptor.update(&[*c]));
    });
    tag.iter().for_each(|c| {
        m1.extend_from_slice(&decryptor.update(&[*c]));
    });
    let m2 = decryptor.finalize().unwrap();
    m1.extend_from_slice(&m2);

    assert_eq!(&plaintext[..], &m1);
}