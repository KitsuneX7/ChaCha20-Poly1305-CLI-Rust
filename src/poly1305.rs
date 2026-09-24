use crate::chacha20::ChaCha20;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Poly1305 {
    r_key: u128,
    s_key: u128,
    acc: [u128; 2]
}

impl Poly1305 {

    pub fn new(mut key: [u8; 32]) -> Self {
        let r: u128 = u128::from_le_bytes(key[0..16].try_into().unwrap());
        let s: u128 = u128::from_le_bytes(key[16..32].try_into().unwrap());
        key.zeroize();
        Self {
            r_key: r & 0x0ffffffc0ffffffc0ffffffc0fffffff,
            s_key: s,
            acc: [0, 0]
        }
    }

    pub fn generate_key(mut key: [u8; 32], nonce: [u8; 12]) -> [u8; 32] {
        let mut engine: ChaCha20 = ChaCha20::new(key, nonce, 0);
        let block: [u8; 64] = engine.generate_block();
        let mut poly_key: [u8; 32] = [0u8; 32];
        poly_key.copy_from_slice(&block[0..32]);
        key.zeroize();
        poly_key
    }

    fn add_256(a: [u128; 2], b: [u128; 2]) -> [u128; 2] {
        let (low, carry) = a[1].overflowing_add(b[1]);
        let carry_val: u128 = if carry { 1 } else { 0 };
        let high: u128 = a[0].wrapping_add(b[0]).wrapping_add(carry_val);
        [high, low]
    }

    fn mul_256_128(a: [u128; 2], b: u128) -> [u128; 2] {
        let a0: u128 = a[1] & 0xFFFF_FFFF_FFFF_FFFF;
        let a1: u128 = a[1] >> 64;
        let a2: u128 = a[0];
        let b0: u128 = b & 0xFFFF_FFFF_FFFF_FFFF;
        let b1: u128 = b >> 64;
        let r0: u128 = a0 * b0;
        let low_lo: u128 = r0 & 0xFFFF_FFFF_FFFF_FFFF;
        let carry0: u128 = r0 >> 64;
        let r1: u128 = (a0 * b1) + (a1 * b0) + carry0;
        let low_hi: u128 = r1 & 0xFFFF_FFFF_FFFF_FFFF;
        let carry1: u128 = r1 >> 64;
        let r2: u128 = (a1 * b1) + (a2 * b0) + carry1;
        let high_lo: u128 = r2 & 0xFFFF_FFFF_FFFF_FFFF;
        let carry2: u128 = r2 >> 64;
        let r3: u128 = (a2 * b1) + carry2;
        let high_hi: u128 = r3 & 0xFFFF_FFFF_FFFF_FFFF;
        let low: u128 = (low_hi << 64) | low_lo;
        let high: u128 = (high_hi << 64) | high_lo;
        [high, low]
    }

    fn mod_256_1305(a: [u128; 2]) -> [u128; 2] {
        let mut ans: [u128; 2] = a;
        let a_high_times_5: u128 = (ans[0] >> 2) * 5;
        ans[0] &= 0x3;
        ans = Self::add_256([0, a_high_times_5], ans);
        let p: [u128; 2] = [3, 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFB];
        if ans[0] > p[0] || (ans[0] == p[0] && ans[1] >= p[1]) {
            let (low, borrow) = ans[1].overflowing_sub(p[1]);
            let high: u128 = ans[0] - p[0] - borrow as u128;
            ans = [high, low];
        }
        ans
    }

    pub fn update(&mut self, data: &[u8]) {
        for chunk in data.chunks(16) {
            let mut block: [u8; 17] = [0u8; 17];
            block[..chunk.len()].copy_from_slice(chunk);
            block[chunk.len()] = 0x01;
            let n_low: u128 = u128::from_le_bytes(block[0..16].try_into().unwrap());
            let n_high: u128 = block[16] as u128;
            let n: [u128; 2] = [n_high, n_low];
            self.acc = Self::add_256(self.acc, n);
            self.acc = Self::mul_256_128(self.acc, self.r_key);
            self.acc = Self::mod_256_1305(self.acc);
        }
    }

    pub fn finalize(self) -> [u8; 16] {
        let tag: u128 = self.acc[1].wrapping_add(self.s_key);
        tag.to_le_bytes()
    }

    pub fn compute_mac(mut self, buffer: &[u8]) -> [u8; 16] {
        self.update(buffer);
        self.finalize()
    }

}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_rfc8439_compute_mac() {
        let key_bytes: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
            0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
            0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
        ];
        let msg: &[u8; 34] = b"Cryptographic Forum Research Group";
        let expected_tag_bytes: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
            0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9
        ];
        let poly: Poly1305 = Poly1305::new(key_bytes);
        let tag: [u8; 16] = poly.compute_mac(msg);
        assert_eq!(tag, expected_tag_bytes);
    }

    #[test]
    fn test_poly1305_generate_key() {
        let key_bytes: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
        ];
        let nonce_bytes: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07
        ];
        let expected_key_bytes: [u8; 32] = [
            0x8a, 0xd5, 0xa0, 0x8b, 0x90, 0x5f, 0x81, 0xcc,
            0x81, 0x50, 0x40, 0x27, 0x4a, 0xb2, 0x94, 0x71,
            0xa8, 0x33, 0xb6, 0x37, 0xe3, 0xfd, 0x0d, 0xa5,
            0x08, 0xdb, 0xb8, 0xe2, 0xfd, 0xd1, 0xa6, 0x46
        ];
        let generated_key: [u8; 32] = Poly1305::generate_key(key_bytes, nonce_bytes);
        assert_eq!(generated_key, expected_key_bytes);
    }

}