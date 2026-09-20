# 🔐 ChaCha20-Poly1305 CLI

[![Rust](https://img.shields.io/badge/rust-stable-brightgreen.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A high-assurance cryptographic file encryption CLI and library written in pure, dependency-minimal Rust. 

The implementation features RFC 8439 ChaCha20 and Poly1305 with extended 192-bit nonces (XChaCha20 construction via HChaCha20), chunked streaming authenticated encryption (AEAD), constant-time MAC verification, Argon2id key derivation, and defensive memory wiping on drop.

---

## ⚡ Key Architectural Features

- **XChaCha20 Construction:** Uses HChaCha20 intermediate block derivation to map 192-bit (24-byte) random nonces down to ephemeral 256-bit subkeys, eliminating nonce-reuse vulnerabilities inherent to standard 96-bit ChaCha20 across large workloads.
- **Chunked AEAD Framing (64 KiB):** Large files stream in fixed 65,536-byte chunks. Each chunk receives an individual Poly1305 MAC tag and a mutated nonce counter ($nonce \oplus chunk\_index$), keeping memory usage capped at ~128 KiB regardless of file size.
- **Truncation & Reordering Resistance:** Encodes a 1-byte finality flag (`0x01` for the final chunk, `0x00` otherwise) directly into the Associated Data (AAD) of each block to guarantee against truncation, reordering, and block-swap attacks.
- **Constant-Time Verification:** Employs `subtle::ConstantTimeEq` for Poly1305 tag comparisons to prevent side-channel timing leaks.
- **Memory Sanitation:** Sensitive key buffers, keystream blocks, and intermediate Poly1305 states implement `Zeroize` and `ZeroizeOnDrop` to purge cryptographic material from memory immediately upon exit.
- **Atomic Abort / Cleanup Guard:** If MAC authentication fails mid-file or reading is interrupted, an armed RAII drop guard automatically unlinks the incomplete output file from disk.
- **Argon2id Key Derivation:** Passwords are automatically stretched via Argon2id ($m=65535\text{ KiB}, t=3, p=4$) using a per-file random 16-byte salt saved in the file header.

---

## 🏗️ File Format Specification

Encrypted files are structured into a deterministic binary header followed by sequential ciphertext chunks and their respective 16-byte Poly1305 MAC tags:

+-----------------------------------------------------------------------+
|  Header (40 Bytes)                                                    |
|  - Salt:  16 Bytes (Argon2id KDF salt)                                |
|  - Nonce: 24 Bytes (Base XChaCha20 nonce)                             |
+-----------------------------------------------------------------------+
|  Chunk #0 (Up to 64 KiB Payload + 16-Byte Tag)                        |
|  - Ciphertext: [0 .. 65536] Bytes                                     |
|  - Poly1305 Tag: 16 Bytes                                             |
+-----------------------------------------------------------------------+
|  Chunk #1 ... #N                                                      |
+-----------------------------------------------------------------------+
|  Final Chunk (0 to 64 KiB Payload + 16-Byte Tag with AAD final flag)  |
+-----------------------------------------------------------------------+

---

## 🚀 Getting Started

### Prerequisites

Ensure you have a recent stable version of [Rust](https://www.rust-lang.org/tools/install) installed.

### Installation

Build the binary in release mode:

```bash
git clone [https://github.com/KitsuneX7/ChaCha20-Poly1305-CLI-Rust.git](https://github.com/KitsuneX7/ChaCha20-Poly1305-CLI-Rust.git)
cd ChaCha20-Poly1305-CLI-Rust
cargo build --release
```

The compiled binary will be available at `./target/release/aead`.

---

## 💻 Usage

### 1. Password-Based Encryption (Argon2id)

Prompt for password interactively via the terminal (safest, hides input):

```bash
# Encrypt
./target/release/aead encrypt -i plain.txt -o plain.enc

# Decrypt
./target/release/aead decrypt -i plain.enc -o restored.txt
```

Pass password directly via CLI argument:

```bash
./target/release/aead encrypt -i data.tar.gz -o data.tar.gz.enc -p "correct-horse-battery-staple"
./target/release/aead decrypt -i data.tar.gz.enc -o data.tar.gz -p "correct-horse-battery-staple"
```

---

### 2. Raw 256-bit Hex Key Encryption

Use a pre-generated 64-character hexadecimal key (skips Argon2id derivation):

```bash
# Generate a random 32-byte key
KEY=$(openssl rand -hex 32)

# Encrypt
./target/release/aead encrypt -i secret.pdf -o secret.enc -k "$KEY"

# Decrypt
./target/release/aead decrypt -i secret.enc -o output.pdf -k "$KEY"
```

Or reference a key stored inside a file:

```bash
./target/release/aead encrypt -i confidential.docx -o doc.enc -K ./keys/master.key
./target/release/aead decrypt -i doc.enc -o confidential.docx -K ./keys/master.key
```

---

### 3. Authenticated Associated Data (AAD)

Authenticate metadata (such as filenames, user IDs, or environment headers) alongside the ciphertext. Decryption will strictly fail if the AAD does not match:

```bash
# Encrypt with explicit AAD context string
./target/release/aead encrypt -i invoice.pdf -o invoice.enc -a "org:finance|dept:audit"

# Decryption succeeds only when identical AAD is supplied
./target/release/aead decrypt -i invoice.enc -o invoice.pdf -a "org:finance|dept:audit"
```

You can also pass AAD from a binary file using `-A` or `--aad-file <PATH>`.

---

## 🧪 Testing & Verification

The test suite validates RFC 8439 test vectors for ChaCha20 quarter-rounds, diagonal rounds, block generation, and Poly1305 MAC calculations:

```bash
cargo test
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
