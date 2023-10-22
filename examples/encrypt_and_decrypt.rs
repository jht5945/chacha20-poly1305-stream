use chacha20_poly1305_stream::{ChaCha20Poly1305StreamDecryptor, ChaCha20Poly1305StreamEncryptor};

fn main() {
    encrypt();
    decrypt();
}

fn encrypt() {
    // IMPORTANT! key and nonce SHOULD generate by random
    let key = [0u8; 32];
    let nonce = [0; 12];

    let mut encryptor = ChaCha20Poly1305StreamEncryptor::new(&key, &nonce).unwrap();

    let mut ciphertext = vec![];
    ciphertext.extend_from_slice(&encryptor.update(b"Hello "));
    ciphertext.extend_from_slice(&encryptor.update(b" World"));
    ciphertext.extend_from_slice(&encryptor.update(b"!"));
    let (last_block, tag) = encryptor.finalize();
    ciphertext.extend_from_slice(&last_block);
    ciphertext.extend_from_slice(&tag);

    println!("Ciphertext: {}", hex::encode(&ciphertext));
}

fn decrypt() {
    // IMPORTANT! key and nonce SHOULD generate by random
    let key = [0u8; 32];
    let nonce = [0; 12];
    let cipher_text = hex::decode("d7628bd23a71182df7c8fb1852d3dc42b88a61e2fce340d9c5b323884d").unwrap();

    let mut decryptor = ChaCha20Poly1305StreamDecryptor::new(&key, &nonce).unwrap();

    let mut plaintext = decryptor.update(&cipher_text);
    let last_block = decryptor.finalize().unwrap();
    plaintext.extend_from_slice(&last_block);

    println!("Plaintext : {}", String::from_utf8_lossy(&plaintext));
}