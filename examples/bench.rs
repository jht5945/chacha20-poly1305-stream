use benchmark_simple::{Bench, Options};

fn test_chacha20_poly1305_encrypt(m: &mut [u8]) {
    let key = [0u8; 32];
    let nonce = [0u8; 12];

    chacha20_poly1305_stream::chacha20_poly1305_encrypt(&key, &nonce, m).unwrap();
}

fn test_chacha20_poly1305_encrypt_and_decrypt(m: &mut [u8]) {
    let key = [0u8; 32];
    let nonce = [0u8; 12];

    let encrypted = chacha20_poly1305_stream::chacha20_poly1305_encrypt(&key, &nonce, m).unwrap();
    let decrypted = chacha20_poly1305_stream::chacha20_poly1305_decrypt(&key, &nonce, &encrypted).unwrap();

    assert_eq!(m, decrypted.as_slice());
}

fn main() {
    let bench = Bench::new();
    let mut m = vec![0xd0u8; 16384];

    let options = &Options {
        iterations: 1_000,
        warmup_iterations: 1_00,
        min_samples: 5,
        max_samples: 10,
        max_rsd: 1.0,
        ..Default::default()
    };

    let res = bench.run(options, || test_chacha20_poly1305_encrypt(&mut m));
    println!("ChaCha20Poly1305 encrypt         : {}", res.throughput(m.len() as _));

    let res = bench.run(options, || test_chacha20_poly1305_encrypt_and_decrypt(&mut m));
    println!("ChaCha20Poly1305 encrypt/decrypt : {}", res.throughput(m.len() as _));
}