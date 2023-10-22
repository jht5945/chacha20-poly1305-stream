# chacha20-poly1305-stream

ChaCha20 Poly1305 stream encrypt and decrypt library

## Encrypt

```rust
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
```

## Run Example

```shell
$ cargo run --example encrypt_and_decrypt
    Finished dev [unoptimized + debuginfo] target(s) in 0.19s
     Running `target/debug/examples/encrypt_and_decrypt`
Ciphertext: d7628bd23a71182df7c8fb1852d3dc42b88a61e2fce340d9c5b323884d
Plaintext : Hello  World!
```

Benchmark @MacBook Pro (Retina, 15-inch, Late 2013/2 GHz Quad-Core Intel Core i7)

```shell
$ cargo r --release --example bench
ChaCha20Poly1305 encrypt         : 287.06 M/s
ChaCha20Poly1305 encrypt/decrypt : 144.93 M/s
```
