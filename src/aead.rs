use crate::chacha20::ChaCha20;
use crate::poly1305::Poly1305;
use std::fs::File;
use std::io::{Read, Write, BufReader, BufWriter};
use std::path::Path;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

const CHUNK_SIZE: usize = 0x10000;
const CHUNK_SIZE_DEC: usize = 0x10010;

struct CleanupGuard<'a> {
    path: &'a Path,
    armed: bool,
}

impl<'a> Drop for CleanupGuard<'a> {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(self.path);
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AEAD {
    key: [u8; 32]
}

impl AEAD {

    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    fn feed_padded(poly: &mut Poly1305, data: &[u8]) {
        let chunks: std::slice::ChunksExact<'_, u8> = data.chunks_exact(16);
        let remainder: &[u8] = chunks.remainder();
        for chunk in chunks {
            poly.update(chunk);
        }
        if !remainder.is_empty() {
            let mut pad_block: [u8; 16] = [0u8; 16];
            pad_block[..remainder.len()].copy_from_slice(remainder);
            poly.update(&pad_block);
        }
    }

    fn process_message(poly: &mut Poly1305, buffer: &[u8], aad: &[u8]) {
        Self::feed_padded(poly, aad);
        Self::feed_padded(poly, buffer);
        let mut lens: [u8; 16] = [0u8; 16];
        lens[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
        lens[8..16].copy_from_slice(&(buffer.len() as u64).to_le_bytes());
        poly.update(&lens);
    }

    fn safe_eq(a: &[u8], b: &[u8]) -> bool {
        a.ct_eq(b).into()
    }

    fn read_full_chunk<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut total: usize = 0;
        while total < buf.len() {
            match reader.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(total)
    }

    fn encrypt(&self, nonce: [u8; 24], buffer: &mut [u8], aad: &[u8]) -> [u8; 16] {
        let mut hchacha: ChaCha20 = ChaCha20::new_h(self.key, nonce);
        let mut subkey: [u8; 32] = hchacha.generate_block_h();
        let mut chacha_nonce: [u8; 12] = [0u8; 12];
        chacha_nonce[4..].copy_from_slice(&nonce[16..]);
        let mut one_time_key: [u8; 32] = Poly1305::generate_key(subkey, chacha_nonce);
        let mut chacha: ChaCha20 = ChaCha20::new(subkey, chacha_nonce, 1);
        chacha.apply_keystream(buffer);
        let mut poly: Poly1305 = Poly1305::new(one_time_key);
        Self::process_message(&mut poly, buffer, aad);
        let tag: [u8; 16] = poly.finalize();
        subkey.zeroize();
        one_time_key.zeroize();
        tag
    }

    fn decrypt(&self, nonce: [u8; 24], buffer: &mut [u8], aad: &[u8], received_tag: [u8; 16]) -> Result<(), ()> {
        let mut hchacha: ChaCha20 = ChaCha20::new_h(self.key, nonce);
        let mut subkey: [u8; 32] = hchacha.generate_block_h();
        let mut chacha_nonce: [u8; 12] = [0u8; 12];
        chacha_nonce[4..].copy_from_slice(&nonce[16..]);
        let mut one_time_key: [u8; 32] = Poly1305::generate_key(subkey, chacha_nonce);
        let mut poly: Poly1305 = Poly1305::new(one_time_key);
        Self::process_message(&mut poly, buffer, aad);
        let calculated_tag: [u8; 16] = poly.finalize();
        if Self::safe_eq(&received_tag, &calculated_tag) == false {
            subkey.zeroize();
            one_time_key.zeroize();
            return Err(());
        }
        let mut chacha: ChaCha20 = ChaCha20::new(subkey, chacha_nonce, 1);
        chacha.apply_keystream(buffer);
        subkey.zeroize();
        one_time_key.zeroize();
        Ok(())
    }

    pub fn encrypt_file(&self, in_path: &Path, out_path: &Path, aad: &[u8], salt: &[u8; 16]) -> std::io::Result<()> {
        if aad.len() >= CHUNK_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "AAD exceeds maximum allowed buffer size",
            ));
        }
        let input_file: File = File::open(in_path)?;
        let mut reader: BufReader<File> = BufReader::new(input_file);
        let output_file: File = File::create(out_path)?;
        let mut writer: BufWriter<File> = BufWriter::new(output_file);
        writer.write_all(salt)?;
        let nonce: [u8; 24] = rand::random();
        writer.write_all(&nonce)?;
        let mut current_chunk: [u8; CHUNK_SIZE] = [0u8; CHUNK_SIZE];
        let mut next_chunk: [u8; CHUNK_SIZE]  = [0u8; CHUNK_SIZE];
        let mut chunk_index: u64 = 0;
        let mut current_len: usize = Self::read_full_chunk(&mut reader, &mut current_chunk)?;
        loop {
            let next_len: usize = Self::read_full_chunk(&mut reader, &mut next_chunk)?;
            let is_final: bool = next_len == 0;
            let mut chunk_nonce: [u8; 24] = nonce;
            let counter_bytes: [u8; 8] = chunk_index.to_le_bytes();
            for i in 0..8 {
                chunk_nonce[16 + i] ^= counter_bytes[i];
            }
            let mut chunk_aad: [u8; CHUNK_SIZE] = [0u8; CHUNK_SIZE];
            chunk_aad[..aad.len()].copy_from_slice(aad);
            chunk_aad[aad.len()] = if is_final { 0x01 } else { 0x00 };
            let total_aad_len: usize = aad.len() + 1;
            let tag: [u8; 16] = self.encrypt(chunk_nonce, &mut current_chunk[..current_len], &chunk_aad[..total_aad_len]);
            writer.write_all(&current_chunk[..current_len])?;
            writer.write_all(&tag)?;
            if is_final {
                break;
            }
            std::mem::swap(&mut current_chunk, &mut next_chunk);
            current_len = next_len;
            chunk_index += 1;
        }
        current_chunk.zeroize();
        next_chunk.zeroize();
        writer.flush()?;
        Ok(())
    }

    pub fn read_salt_from_file(in_path: &Path) -> Result<[u8; 16], String> {
        let mut file: File = File::open(in_path).map_err(|e: std::io::Error| format!("Failed to open file to read salt: {e}"))?;
        let mut salt: [u8; 16] = [0u8; 16];
        file.read_exact(&mut salt).map_err(|e: std::io::Error| format!("Corrupted salt header: {e}"))?;
        Ok(salt)
    }

    pub fn decrypt_file(&self, in_path: &Path, out_path: &Path, aad: &[u8]) -> Result<(), String> {
        if aad.len() >= CHUNK_SIZE {
            return Err("AAD exceeds maximum allowed buffer size".into());
        }
        let input_file: File = File::open(in_path).map_err(|e| format!("Failed to open input: {e}"))?;
        let mut reader: BufReader<File> = BufReader::new(input_file);
        let output_file: File = File::create(out_path).map_err(|e| format!("Failed to create output: {e}"))?;
        let mut writer: BufWriter<File> = BufWriter::new(output_file);
        let mut guard: CleanupGuard<'_> = CleanupGuard { path: out_path, armed: true };
        let mut salt_buf: [u8; 16] = [0u8; 16];
        reader.read_exact(&mut salt_buf).map_err(|e: std::io::Error| format!("Corrupted salt header: {e}"))?;
        let mut nonce: [u8; 24] = [0u8; 24];
        reader.read_exact(&mut nonce).map_err(|e: std::io::Error| format!("Corrupted nonce header: {e}"))?;
        let mut encrypted_chunk: [u8; CHUNK_SIZE_DEC] = [0u8; CHUNK_SIZE_DEC];
        let mut next_encrypted_chunk: [u8; CHUNK_SIZE_DEC] = [0u8; CHUNK_SIZE_DEC];
        let mut chunk_index: u64 = 0;
        let mut current_len: usize = Self::read_full_chunk(&mut reader, &mut encrypted_chunk)
            .map_err(|e: std::io::Error| format!("Read error: {e}"))?;
        if current_len < 16 {
            return Err("File is truncated or corrupted (smaller than one tag)".into());
        }
        loop {
            let next_len: usize = Self::read_full_chunk(&mut reader, &mut next_encrypted_chunk)
                .map_err(|e: std::io::Error| format!("Read error: {e}"))?;
            let is_final: bool = next_len == 0;
            let ciphertext_len: usize = current_len - 16;
            let (ciphertext, tag_slice) = encrypted_chunk[..current_len].split_at_mut(ciphertext_len);
            let mut received_tag: [u8; 16] = [0u8; 16];
            received_tag.copy_from_slice(tag_slice);
            let mut chunk_nonce: [u8; 24] = nonce;
            let counter_bytes: [u8; 8] = chunk_index.to_le_bytes();
            for i in 0..8 {
                chunk_nonce[16 + i] ^= counter_bytes[i];
            }
            let mut chunk_aad: [u8; CHUNK_SIZE] = [0u8; CHUNK_SIZE];
            chunk_aad[..aad.len()].copy_from_slice(aad);
            chunk_aad[aad.len()] = if is_final { 0x01 } else { 0x00 };
            let total_aad_len = aad.len() + 1;
            self.decrypt(chunk_nonce, ciphertext, &chunk_aad[..total_aad_len], received_tag)
                .map_err(|_| format!("Decryption failed at chunk #{chunk_index}: MAC mismatch or wrong key/AAD"))?;
            writer.write_all(ciphertext).map_err(|e: std::io::Error| format!("Write error: {e}"))?;
            if is_final {
                break;
            }
            std::mem::swap(&mut encrypted_chunk, &mut next_encrypted_chunk);
            current_len = next_len;
            chunk_index += 1;
        }
        encrypted_chunk.zeroize();
        next_encrypted_chunk.zeroize();
        writer.flush().map_err(|e: std::io::Error| format!("Flush error: {e}"))?;
        drop(writer);
        guard.armed = false;
        Ok(())
    }

}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_aead() {
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 24] = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        ];
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
            0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext: &[u8; 114] = 
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ciphertext: [u8; 114] = [
            0xbd, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b, 0x95, 0x76, 0x57, 0x94,
            0x93, 0xc0, 0xe9, 0x39, 0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc,
            0xbe, 0xd2, 0x90, 0x2c, 0x21, 0x39, 0x6c, 0xbb, 0x73, 0x1c, 0x7f, 0x1b,
            0x0b, 0x4a, 0xa6, 0x44, 0x0b, 0xf3, 0xa8, 0x2f, 0x4e, 0xda, 0x7e, 0x39,
            0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16, 0xcb, 0x96, 0xb7, 0x2e,
            0x12, 0x13, 0xb4, 0x52, 0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5, 0xd9, 0x45,
            0xb1, 0x1b, 0x69, 0xb9, 0x82, 0xc1, 0xbb, 0x9e, 0x3f, 0x3f, 0xac, 0x2b,
            0xc3, 0x69, 0x48, 0x8f, 0x76, 0xb2, 0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9,
            0x21, 0xf9, 0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9, 0x76, 0x88, 0x12, 0xf6,
            0x15, 0xc6, 0x8b, 0x13, 0xb5, 0x2e,
        ];

        let expected_tag: [u8; 16] = [
            0xc0, 0x87, 0x59, 0x24, 0xc1, 0xc7, 0x98, 0x79,
            0x47, 0xde, 0xaf, 0xd8, 0x78, 0x0a, 0xcf, 0x49,
        ];
        let aead: AEAD = AEAD::new(key);
        let mut buffer: Vec<u8> = plaintext.to_vec();
        let tag: [u8; 16] = aead.encrypt(nonce, &mut buffer, &aad);
        assert_eq!(buffer.as_slice(), &expected_ciphertext[..], "Ciphertext mismatch");
        assert_eq!(tag, expected_tag, "Auth tag mismatch");
        let decrypt_result: Result<(), ()> = aead.decrypt(nonce, &mut buffer, &aad, tag);
        assert!(decrypt_result.is_ok(), "Decryption failed on valid data");
        assert_eq!(buffer.as_slice(), plaintext, "Decrypted text mismatch");
        let mut bad_tag: [u8; 16] = tag;
        bad_tag[0] ^= 0x01;
        let tampered_result: Result<(), ()> = aead.decrypt(nonce, &mut buffer, &aad, bad_tag);
        assert!(tampered_result.is_err(), "Decryption should fail on corrupted tag");
    }

}