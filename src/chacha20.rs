use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ChaCha20 {
    state: [u32; 16],
}

impl ChaCha20 {
    
    pub fn new(mut key: [u8; 32], nonce: [u8; 12], starting_block_count: u32) -> Self {
        let mut state: [u32; 16] = [0u32; 16];
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        for (i, chunk) in key.chunks_exact(4).enumerate() {
            state[4 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        state[12] = starting_block_count;
        for (i, chunk) in nonce.chunks_exact(4).enumerate() {
            state[13 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        key.zeroize();
        Self { state }
    }

    pub fn new_h(mut key: [u8; 32], nonce: [u8; 24]) -> Self {
        let mut state: [u32; 16] = [0u32; 16];
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32; 
        state[3] = 0x6b206574;
        for (i, chunk) in key.chunks_exact(4).enumerate() {
            state[4 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        for (i, chunk) in nonce[..16].chunks_exact(4).enumerate() {
            state[12 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        key.zeroize();
        Self { state }
    }

    pub fn current_counter(&self) -> u32 {
        self.state[12]
    }

    pub fn seek_to_block(&mut self, block: u32) {
        self.state[12] = block;
    }

    fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
        *a = a.wrapping_add(*b);
        *d = (*d ^ *a).rotate_left(16);
        *c = c.wrapping_add(*d);
        *b = (*b ^ *c).rotate_left(12);
        *a = a.wrapping_add(*b);
        *d = (*d ^ *a).rotate_left(8);
        *c = c.wrapping_add(*d);
        *b = (*b ^ *c).rotate_left(7);
    }

    fn quarter_round_state(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        let mut va: u32 = s[a];
        let mut vb: u32 = s[b];
        let mut vc: u32 = s[c];
        let mut vd: u32 = s[d];
        Self::quarter_round(&mut va, &mut vb, &mut vc, &mut vd);
        s[a] = va;
        s[b] = vb;
        s[c] = vc;
        s[d] = vd;
    }

    fn double_round(s: &mut [u32; 16]) {
        Self::quarter_round_state(s, 0, 4, 8, 12);
        Self::quarter_round_state(s, 1, 5, 9, 13);
        Self::quarter_round_state(s, 2, 6, 10, 14);
        Self::quarter_round_state(s, 3, 7, 11, 15);
        Self::quarter_round_state(s, 0, 5, 10, 15);
        Self::quarter_round_state(s, 1, 6, 11, 12);
        Self::quarter_round_state(s, 2, 7, 8, 13);
        Self::quarter_round_state(s, 3, 4, 9, 14);
    }

    pub fn generate_block(&mut self) -> [u8; 64] {
        let mut block: [u32; 16] = self.state;
        for _ in 0..10 {
            Self::double_round(&mut block);
        }
        for i in 0..16 {
            block[i] = block[i].wrapping_add(self.state[i]);
        }
        self.state[12] = self.state[12].wrapping_add(1);
        let mut block_to_bytes: [u8; 64] = [0u8; 64];
        for i in 0..16 {
            block_to_bytes[i << 2..(i + 1) << 2].copy_from_slice(&block[i].to_le_bytes());
        }
        block.zeroize();
        block_to_bytes
    }

    pub fn generate_block_h(&mut self) -> [u8; 32] {
        let mut block: [u32; 16] = self.state;
        for _ in 0..10 {
            Self::double_round(&mut block);
        }
        let mut block_to_bytes: [u8; 32] = [0u8; 32];
        for i in 0..4 {
            block_to_bytes[i << 2..(i + 1) << 2].copy_from_slice(&block[i].to_le_bytes());
        }
        for i in 12..16 {
            block_to_bytes[(i << 2) - 32..((i + 1) << 2) - 32].copy_from_slice(&block[i].to_le_bytes());
        }
        block.zeroize();
        block_to_bytes
    }

    pub fn apply_keystream(&mut self, buffer: &mut [u8]) {
        for chunk in buffer.chunks_mut(64) {
            let mut keystream: [u8; 64] = self.generate_block();
            for (byte, &key_byte) in chunk.iter_mut().zip(&keystream) {
                *byte ^= key_byte;
            }
            keystream.zeroize();
        }
    }

}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_chacha20_quarter_round() {
        let mut a: u32 = 0x11111111;
        let mut b: u32 = 0x01020304;
        let mut c: u32 = 0x9b8d6f43;
        let mut d: u32 = 0x01234567;
        ChaCha20::quarter_round(&mut a, &mut b, &mut c, &mut d);
        assert_eq!(a, 0xea2a92f4);
        assert_eq!(b, 0xcb1cf8ce);
        assert_eq!(c, 0x4581472e);
        assert_eq!(d, 0x5881c4bb);
    }

    #[test]
    fn test_chacha20_diagonal_round() {
        let mut s: [u32; 16] = [
            0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
            0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
            0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
            0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320
        ];
        ChaCha20::quarter_round_state(&mut s, 2, 7, 8, 13);
        assert_eq!(s[0], 0x879531e0);
        assert_eq!(s[1], 0xc5ecf37d);
        assert_eq!(s[2], 0xbdb886dc);
        assert_eq!(s[3], 0xc9a62f8a);
        assert_eq!(s[4], 0x44c20ef3);
        assert_eq!(s[5], 0x3390af7f);
        assert_eq!(s[6], 0xd9fc690b);
        assert_eq!(s[7], 0xcfacafd2); 
        assert_eq!(s[8], 0xe46bea80); 
        assert_eq!(s[9], 0xb00a5631);
        assert_eq!(s[10], 0x974c541a);
        assert_eq!(s[11], 0x359e9963);
        assert_eq!(s[12], 0x5c971061);
        assert_eq!(s[13], 0xccc07c79);
        assert_eq!(s[14], 0x2098d9d6);
        assert_eq!(s[15], 0x91dbd320);
    }

    #[test]
    fn test_chacha20_generate_block() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00
        ];
        let mut cipher = ChaCha20::new(key, nonce, 1);
        let block: [u8; 64] = cipher.generate_block();
        let expected: [u8; 64] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
            0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
            0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
            0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
            0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
            0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
            0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e
        ];
        assert_eq!(block, expected);
    }

    #[test]
    fn test_chacha20_encryption() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00
        ];
        let initial_counter: u32 = 1;
        let plaintext: &[u8; 114] = 
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ciphertext: [u8; 114] = [
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
            0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
            0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
            0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
            0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
            0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
            0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d
        ];
        let mut buffer: Vec<u8> = plaintext.to_vec();
        let mut cipher = ChaCha20::new(key, nonce, initial_counter);
        cipher.apply_keystream(&mut buffer);
        assert_eq!(buffer.as_slice(), &expected_ciphertext[..]);
        let mut decryptor = ChaCha20::new(key, nonce, initial_counter);
        decryptor.apply_keystream(&mut buffer);
        assert_eq!(buffer.as_slice(), plaintext);
    }

    #[test]
    fn test_chacha20_h() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let mut nonce_24: [u8; 24] = [0u8; 24];
        nonce_24[..16].copy_from_slice(&[
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00, 0x31, 0x41, 0x59, 0x27,
        ]);
        let expected_subkey: [u8; 32] = [
            0x82, 0x41, 0x3b, 0x42, 0x27, 0xb2, 0x7b, 0xfe,
            0xd3, 0x0e, 0x42, 0x50, 0x8a, 0x87, 0x7d, 0x73,
            0xa0, 0xf9, 0xe4, 0xd5, 0x8a, 0x74, 0xa8, 0x53,
            0xc1, 0x2e, 0xc4, 0x13, 0x26, 0xd3, 0xec, 0xdc,
        ];
        let mut hchacha: ChaCha20 = ChaCha20::new_h(key, nonce_24);
        let subkey: [u8; 32] = hchacha.generate_block_h();
        assert_eq!(subkey, expected_subkey, "HChaCha20 output mismatch!");
    }

}