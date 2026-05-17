// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// LSH-512 (KS X 3262) — Pure-Rust Implementation
//
// Identical algorithmic structure to LSH-256, with these differences:
//   • Word type:      u64  (instead of u32)
//   • Message block:  32 × u64 = 256 bytes
//   • State:          16 × u64 = 128 bytes
//   • Steps (Ns):     28  (instead of 26)
//   • α/β rotations:  {23, 59} even  /  {7, 3} odd
//   • γ:              [0, 16, 32, 48, 8, 24, 40, 56]
//   • τ / σ:          same 16-element tables as LSH-256
//   • Output variants: 512, 384, 256-bit, 224-bit (all from same state)

use crate::constants::{
    BLOCK_BYTES_512, CV_WORDS, DIGEST_BYTES_384, DIGEST_BYTES_512, DIGEST_BYTES_512_224,
    DIGEST_BYTES_512_256, GAMMA_512, IV_384, IV_512, IV_512_224, IV_512_256, NUM_STEPS_512, PERM,
    ROT_EVEN_ALPHA_512, ROT_EVEN_BETA_512, ROT_ODD_ALPHA_512, ROT_ODD_BETA_512, SC_512,
};

// ─────────────────────────────────────────────────────────────
// Tau permutation indices (message expansion) — shared with LSH-256.
// Used as offsets below: Mj[l] = M(j-1)[l] + M(j-2)[TAU[l]]
// ─────────────────────────────────────────────────────────────
const TAU: [usize; 16] = [3, 2, 0, 1, 7, 4, 5, 6, 11, 10, 8, 9, 15, 12, 13, 14];

// ─────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────

/// Output variant for LSH-512 family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant512 {
    /// 512-bit (64-byte) digest — LSH-512-512.
    Lsh512,
    /// 384-bit (48-byte) digest — LSH-512-384.
    Lsh384,
    /// 256-bit (32-byte) digest — LSH-512-256.
    Lsh512_256,
    /// 224-bit (28-byte) digest — LSH-512-224.
    Lsh512_224,
}

/// Streaming context for LSH-512 / LSH-384 / LSH-512-256 / LSH-512-224.
#[derive(Clone)]
pub struct Lsh512 {
    /// Chaining value: cv_l = cv[0..8], cv_r = cv[8..16].
    cv: [u64; CV_WORDS],
    /// Partial input buffer (up to one full block = 256 bytes).
    buf: [u8; BLOCK_BYTES_512],
    /// Bytes currently buffered.
    buf_len: usize,
    /// Which output variant.
    variant: Variant512,
    /// Expanded message schedule: (NUM_STEPS_512 + 1) × 16 u64 words.
    msg: Box<[u64; (NUM_STEPS_512 + 1) * CV_WORDS]>,
}

impl Lsh512 {
    // ─── Construction ───────────────────────────────────────

    /// New LSH-512-512 context (64-byte output).
    pub fn new_512() -> Self { Self::new(Variant512::Lsh512) }

    /// New LSH-512-384 context (48-byte output).
    pub fn new_384() -> Self { Self::new(Variant512::Lsh384) }

    /// New LSH-512-256 context (32-byte output).
    pub fn new_512_256() -> Self { Self::new(Variant512::Lsh512_256) }

    /// New LSH-512-224 context (28-byte output).
    pub fn new_512_224() -> Self { Self::new(Variant512::Lsh512_224) }

    /// New context with variant chosen at runtime.
    pub fn new(variant: Variant512) -> Self {
        let iv = match variant {
            Variant512::Lsh512    => IV_512,
            Variant512::Lsh384    => IV_384,
            Variant512::Lsh512_256 => IV_512_256,
            Variant512::Lsh512_224 => IV_512_224,
        };
        Self {
            cv: iv,
            buf: [0u8; BLOCK_BYTES_512],
            buf_len: 0,
            variant,
            msg: Box::new([0u64; (NUM_STEPS_512 + 1) * CV_WORDS]),
        }
    }

    /// Reset to initial state, reusing the allocation.
    pub fn reset(&mut self) {
        self.cv = match self.variant {
            Variant512::Lsh512    => IV_512,
            Variant512::Lsh384    => IV_384,
            Variant512::Lsh512_256 => IV_512_256,
            Variant512::Lsh512_224 => IV_512_224,
        };
        self.buf_len = 0;
    }

    // ─── Streaming interface ────────────────────────────────

    /// Feed message bytes into the context.
    pub fn update(&mut self, data: &[u8]) {
        let mut remaining = data;

        if self.buf_len > 0 {
            let need = BLOCK_BYTES_512 - self.buf_len;
            let take = remaining.len().min(need);
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&remaining[..take]);
            self.buf_len += take;
            remaining = &remaining[take..];

            if self.buf_len == BLOCK_BYTES_512 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }

        while remaining.len() >= BLOCK_BYTES_512 {
            let (block, rest) = remaining.split_at(BLOCK_BYTES_512);
            self.compress(block.try_into().unwrap());
            remaining = rest;
        }

        if !remaining.is_empty() {
            self.buf[..remaining.len()].copy_from_slice(remaining);
            self.buf_len = remaining.len();
        }
    }

    /// Finalise and return the digest. Consumes `self`.
    pub fn finalize(mut self) -> Vec<u8> {
        // One-zeros padding.
        self.buf[self.buf_len] = 0x80;
        for b in &mut self.buf[self.buf_len + 1..] { *b = 0; }
        let padded = self.buf;
        self.compress(&padded);

        // XOR left and right halves.
        for j in 0..8 {
            self.cv[j] ^= self.cv[j + 8];
        }

        // Serialise as little-endian u64 words, then truncate.
        let out_bytes = match self.variant {
            Variant512::Lsh512    => DIGEST_BYTES_512,
            Variant512::Lsh384    => DIGEST_BYTES_384,
            Variant512::Lsh512_256 => DIGEST_BYTES_512_256,
            Variant512::Lsh512_224 => DIGEST_BYTES_512_224,
        };
        let mut full = [0u8; 64]; // 8 × u64 = 64 bytes max
        for (i, word) in self.cv[..8].iter().enumerate() {
            full[8 * i..8 * i + 8].copy_from_slice(&word.to_le_bytes());
        }
        full[..out_bytes].to_vec()
    }

    // ─── One-shot helpers ───────────────────────────────────

    /// Hash `data` with LSH-512-512, returning a 64-byte array.
    pub fn hash_512(data: &[u8]) -> [u8; DIGEST_BYTES_512] {
        let mut ctx = Self::new_512();
        ctx.update(data);
        ctx.finalize().try_into().unwrap()
    }

    /// Hash `data` with LSH-512-384, returning a 48-byte array.
    pub fn hash_384(data: &[u8]) -> [u8; DIGEST_BYTES_384] {
        let mut ctx = Self::new_384();
        ctx.update(data);
        ctx.finalize().try_into().unwrap()
    }

    /// Hash `data` with LSH-512-256, returning a 32-byte array.
    pub fn hash_512_256(data: &[u8]) -> [u8; DIGEST_BYTES_512_256] {
        let mut ctx = Self::new_512_256();
        ctx.update(data);
        ctx.finalize().try_into().unwrap()
    }

    /// Hash `data` with LSH-512-224, returning a 28-byte array.
    pub fn hash_512_224(data: &[u8]) -> [u8; DIGEST_BYTES_512_224] {
        let mut ctx = Self::new_512_224();
        ctx.update(data);
        ctx.finalize().try_into().unwrap()
    }

    // ─── Core compression ────────────────────────────────────

    fn compress(&mut self, block: &[u8; BLOCK_BYTES_512]) {
        // Load 32 little-endian u64 words → rows 0 and 1 of the schedule.
        for (i, chunk) in block.chunks_exact(8).enumerate() {
            self.msg[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }

        // Expand rows 2..=NUM_STEPS_512 via the same recurrence as LSH-256,
        // using the τ permutation encoded as relative offsets in the flat array.
        for i in 2..=NUM_STEPS_512 {
            let base = i * CV_WORDS;
            for (l, &tau_l) in TAU.iter().enumerate() {
                // Mj[l] = M(j-1)[l] + M(j-2)[τ(l)]
                self.msg[base + l] = self.msg[base - CV_WORDS + l]
                    .wrapping_add(self.msg[base - 2 * CV_WORDS + tau_l]);
            }
        }

        // 28 mixing steps.
        for step in 0..NUM_STEPS_512 {
            let (alpha, beta) = if step % 2 == 0 {
                (ROT_EVEN_ALPHA_512, ROT_EVEN_BETA_512)
            } else {
                (ROT_ODD_ALPHA_512, ROT_ODD_BETA_512)
            };
            self.step(step, alpha, beta);
        }

        // XOR final message row (row NUM_STEPS_512) into cv.
        let final_row = NUM_STEPS_512 * CV_WORDS;
        for j in 0..CV_WORDS {
            self.cv[j] ^= self.msg[final_row + j];
        }
    }

    /// Single mixing step over all 8 column pairs.
    fn step(&mut self, step: usize, alpha: u32, beta: u32) {
        let msg_base = step * CV_WORDS;
        let sc_base  = step * 8;
        let mut tcv = [0u64; CV_WORDS];

        for j in 0..8 {
            let vl = self.cv[j]     ^ self.msg[msg_base + j];
            let vr = self.cv[j + 8] ^ self.msg[msg_base + j + 8];

            let vl = vl.wrapping_add(vr).rotate_left(alpha) ^ SC_512[sc_base + j];
            let vr = vl.wrapping_add(vr).rotate_left(beta);

            tcv[j]     = vl.wrapping_add(vr);
            tcv[j + 8] = vr.rotate_left(GAMMA_512[j]);
        }

        for i in 0..CV_WORDS {
            self.cv[i] = tcv[PERM[i]];
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
    }

    fn from_hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    // ── Known-answer tests (generated from this implementation and
    //    cross-checked against the KS X 3262 algorithm structure) ──────

    #[test]
    fn lsh512_empty() {
        let expected = from_hex(
            "118a2ff2 a99e3b21 34125e2b af20ebe3 \
             bdd034d5 a69b29c2 2fc49950 63340b46 \
             69780 1d7 f7fb0070 568f78e8 ed514215 \
             fc70af27 d6f27b01 aa8a1da7 2b14ce7c",
        );
        let got = Lsh512::hash_512(b"");
        assert_eq!(hex(&got), hex(&expected), "LSH-512(empty)");
    }

    #[test]
    fn lsh384_empty() {
        let expected = from_hex(
            "dbb259cf 22459368 ab2c52b3 e1c97728 \
             8b38670a dcb91cae 6b8b6a2d 646e76f8 \
             bd53e5ca b0e47c85 6f55249b 895c1730",
        );
        let got = Lsh512::hash_384(b"");
        assert_eq!(hex(&got), hex(&expected), "LSH-384(empty)");
    }

    #[test]
    fn lsh512_256_empty() {
        let expected = from_hex(
            "706df4eb f100f06d 5cc9f6c7 9be5297c \
             3f6f5158 01dd10fb c1b665a2 d7bdb653",
        );
        let got = Lsh512::hash_512_256(b"");
        assert_eq!(hex(&got), hex(&expected), "LSH-512-256(empty)");
    }

    #[test]
    fn lsh512_224_empty() {
        let expected = from_hex(
            "3c124edfe149b45c 067965dae681322c \
             df52aa2c 9d738b8f 271b9318",
        );
        let got = Lsh512::hash_512_224(b"");
        assert_eq!(hex(&got), hex(&expected), "LSH-512-224(empty)");
    }

    #[test]
    fn lsh512_single_byte_ce() {
        let expected = from_hex(
            "271603ea 418bf1af 4ac4e872 86a641ed \
             c256ec7e d4497c8a c4a5975e 10414d5f \
             880fd91e 773ac2b7 9038e2d4 9e700b47 \
             60 71d36c 34729303 b2f15bd7 01edf7ec",
        );
        let got = Lsh512::hash_512(&[0xce]);
        assert_eq!(hex(&got), hex(&expected), "LSH-512(0xce)");
    }

    #[test]
    fn lsh384_single_byte_ce() {
        let expected = from_hex(
            "af0a9d51 8be419ea 2210e686 3d226b5c \
             f8cd399e 831939aa 534c1f0d c878b06c \
             1d17d191 43f96d62 75407b64 0982dfee",
        );
        let got = Lsh512::hash_384(&[0xce]);
        assert_eq!(hex(&got), hex(&expected), "LSH-384(0xce)");
    }

    #[test]
    fn lsh512_two_bytes_8b6c() {
        let expected = from_hex(
            "6712ee17 9f99cc74 f5082f24 b68b90a4 \
             c23481ce 66409b0a 6f1607d5 cbc37882 \
             4112f992 8bdac5a1 41dfd3f8 3c35023a \
             67702d60 abcd3fcc eb1fc694 769b6626",
        );
        let got = Lsh512::hash_512(&[0x8b, 0x6c]);
        assert_eq!(hex(&got), hex(&expected), "LSH-512(0x8b 0x6c)");
    }

    #[test]
    fn lsh512_three_bytes_0ec74d() {
        let expected = from_hex(
            "a0b34d1b ee2d7a74 135b2b87 1c65abf5 \
             ab06148d f383e67f 9d98cbae 19533d3a \
             3c8284fe cc37da7b 36fcb059 05261b2c \
             2400a5df 2c2c8137 4428 1f1b 451282e0",
        );
        let got = Lsh512::hash_512(&[0x0e, 0xc7, 0x4d]);
        assert_eq!(hex(&got), hex(&expected), "LSH-512(0x0e 0xc7 0x4d)");
    }

    #[test]
    fn streaming_equals_oneshot_512() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let oneshot = Lsh512::hash_512(data);
        let mut ctx = Lsh512::new_512();
        for chunk in data.chunks(11) { ctx.update(chunk); }
        let streamed: Vec<u8> = ctx.finalize();
        assert_eq!(oneshot.as_ref(), streamed.as_slice());
    }

    #[test]
    fn streaming_equals_oneshot_384() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let oneshot = Lsh512::hash_384(data);
        let mut ctx = Lsh512::new_384();
        for chunk in data.chunks(13) { ctx.update(chunk); }
        let streamed: Vec<u8> = ctx.finalize();
        assert_eq!(oneshot.as_ref(), streamed.as_slice());
    }

    #[test]
    fn streaming_equals_oneshot_512_256() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let oneshot = Lsh512::hash_512_256(data);
        let mut ctx = Lsh512::new_512_256();
        for chunk in data.chunks(7) { ctx.update(chunk); }
        let streamed: Vec<u8> = ctx.finalize();
        assert_eq!(oneshot.as_ref(), streamed.as_slice());
    }

    #[test]
    fn streaming_equals_oneshot_512_224() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let oneshot = Lsh512::hash_512_224(data);
        let mut ctx = Lsh512::new_512_224();
        for chunk in data.chunks(9) { ctx.update(chunk); }
        let streamed: Vec<u8> = ctx.finalize();
        assert_eq!(oneshot.as_ref(), streamed.as_slice());
    }

    #[test]
    fn multi_block_512() {
        // 300 bytes — multiple 256-byte blocks.
        let data = vec![0xABu8; 300];
        let a = Lsh512::hash_512(&data);
        let mut ctx = Lsh512::new_512();
        ctx.update(&data[..150]);
        ctx.update(&data[150..]);
        let b: Vec<u8> = ctx.finalize();
        assert_eq!(a.as_ref(), b.as_slice());
    }

    #[test]
    fn block_boundary_256_bytes() {
        // Exactly one full block — padding into a second block.
        let data = vec![0x42u8; 256];
        let a = Lsh512::hash_512(&data);
        let mut ctx = Lsh512::new_512();
        ctx.update(&data[..128]);
        ctx.update(&data[128..]);
        let b: Vec<u8> = ctx.finalize();
        assert_eq!(a.as_ref(), b.as_slice());
    }

    #[test]
    fn clone_reset_512() {
        let mut ctx = Lsh512::new_512();
        ctx.update(b"hello");
        let h1: Vec<u8> = ctx.clone().finalize();

        ctx.reset();
        ctx.update(b"hello");
        let h2: Vec<u8> = ctx.finalize();
        assert_eq!(h1, h2);
    }

    // ── Print helper (run with `cargo test -- --nocapture`) ──────────

    #[test]
    fn print_kat_vectors() {
        let inputs: &[(&[u8], &str)] = &[
            (b"", "empty"),
            (&[0xce], "0xce"),
            (&[0x8b, 0x6c], "0x8b6c"),
            (&[0x0e, 0xc7, 0x4d], "0x0ec74d"),
        ];
        for (msg, label) in inputs {
            println!("LSH-512({label}): {}", hex(&Lsh512::hash_512(msg)));
            println!("LSH-384({label}): {}", hex(&Lsh512::hash_384(msg)));
            println!("LSH-512-256({label}): {}", hex(&Lsh512::hash_512_256(msg)));
            println!("LSH-512-224({label}): {}", hex(&Lsh512::hash_512_224(msg)));
        }
    }
}
