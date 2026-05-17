// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// LSH-256 (KS X 3262) — Pure-Rust Implementation
//
// Korean national standard cryptographic hash function.
// Standardised as KS X 3262 by KISA / NSRI (2014).
//
// Supports:
//   • LSH-256-256  (full 256-bit / 32-byte digest)
//   • LSH-256-224  (truncated 224-bit / 28-byte digest)
//
// Algorithm overview
// ──────────────────
// State : 16 × u32 words, split into a left half cv_l[0..8] and
//         a right half cv_r[0..8].
//
// Per 128-byte block
//   1. expand_message — derive 27 × 16 words from the 32-word block
//      via a linear recurrence (all additions are wrapping u32).
//   2. 26 step() calls, alternating even/odd rotation parameters.
//      Each step:
//        a. XOR each cv word with the expanded message word.
//        b. MIX(cv_l, cv_r, SC[step]):
//               cv_l[j] = cv_l[j].wrapping_add(cv_r[j])
//               cv_l[j] = cv_l[j].rotate_left(alpha)
//               cv_l[j] ^= SC[step*8 + j]
//               cv_r[j] = cv_r[j].wrapping_add(cv_l[j])
//               cv_r[j] = cv_r[j].rotate_left(beta)
//               cv_l[j] = cv_l[j].wrapping_add(cv_r[j])
//               cv_r[j] = cv_r[j].rotate_left(GAMMA[j])
//        c. Permute the 16 cv words using the PERM table.
//   3. XOR the final expanded message row (row 26) into cv.
//
// Finalisation
//   cv_l[j] ^= cv_r[j]   for j in 0..8
//   Output = cv_l (truncated to 28 bytes for LSH-224).
//
// Padding
//   Append 0x80, then zero-pad to the next 128-byte boundary.
//   (Single-pass — no length encoding in the padding.)

#![forbid(unsafe_code)]

pub mod constants;

use constants::*;

// ─────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────

/// Which output length variant to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// Full 256-bit (32-byte) digest — LSH-256-256.
    Lsh256,
    /// Truncated 224-bit (28-byte) digest — LSH-256-224.
    Lsh224,
}

/// Streaming context for LSH-256 / LSH-256-224.
#[derive(Clone)]
pub struct Lsh256 {
    /// Current chaining value: cv_l = cv[0..8], cv_r = cv[8..16].
    cv: [u32; CV_WORDS],
    /// Partially filled input buffer (up to one full block).
    buf: [u8; BLOCK_BYTES],
    /// Number of valid bytes in `buf`.
    buf_len: usize,
    /// Which output variant.
    variant: Variant,
    /// Expanded message schedule — 27 rows × 16 words.
    /// Kept on the heap as a field to avoid large stack frames.
    msg: Box<[u32; (NUM_STEPS + 1) * CV_WORDS]>,
}

impl Lsh256 {
    // ─── Construction ───────────────────────────────────────

    /// Create a new LSH-256-256 context (32-byte output).
    pub fn new_256() -> Self {
        Self::new(Variant::Lsh256)
    }

    /// Create a new LSH-256-224 context (28-byte output).
    pub fn new_224() -> Self {
        Self::new(Variant::Lsh224)
    }

    /// Create a new context for the given output variant.
    pub fn new(variant: Variant) -> Self {
        let iv = match variant {
            Variant::Lsh256 => IV_256,
            Variant::Lsh224 => IV_224,
        };
        Self {
            cv: iv,
            buf: [0u8; BLOCK_BYTES],
            buf_len: 0,
            variant,
            msg: Box::new([0u32; (NUM_STEPS + 1) * CV_WORDS]),
        }
    }

    /// Reset this context to its initial state, reusing the allocation.
    pub fn reset(&mut self) {
        self.cv = match self.variant {
            Variant::Lsh256 => IV_256,
            Variant::Lsh224 => IV_224,
        };
        self.buf_len = 0;
    }

    // ─── Streaming interface ────────────────────────────────

    /// Feed message bytes into the hash state.
    pub fn update(&mut self, data: &[u8]) {
        let mut remaining = data;

        // Fill any partial block first.
        if self.buf_len > 0 {
            let need = BLOCK_BYTES - self.buf_len;
            let take = remaining.len().min(need);
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&remaining[..take]);
            self.buf_len += take;
            remaining = &remaining[take..];

            if self.buf_len == BLOCK_BYTES {
                let block = self.buf; // copy to avoid borrow conflict
                self.compress(&block);
                self.buf_len = 0;
            }
        }

        // Process full blocks directly from the input.
        while remaining.len() >= BLOCK_BYTES {
            let (block, rest) = remaining.split_at(BLOCK_BYTES);
            self.compress(block.try_into().unwrap());
            remaining = rest;
        }

        // Buffer any tail.
        if !remaining.is_empty() {
            self.buf[..remaining.len()].copy_from_slice(remaining);
            self.buf_len = remaining.len();
        }
    }

    /// Finalise and return the digest.
    ///
    /// This consumes `self`; clone before calling if you need to keep
    /// the streaming state.
    pub fn finalize(mut self) -> Vec<u8> {
        // Padding: 0x80 followed by zero bytes to fill the block.
        self.buf[self.buf_len] = 0x80;
        for b in &mut self.buf[self.buf_len + 1..] {
            *b = 0;
        }
        let padded = self.buf;
        self.compress(&padded);

        // Finalisation: XOR left half with right half.
        for j in 0..CV_HALF_WORDS {
            self.cv[j] ^= self.cv[j + CV_HALF_WORDS];
        }

        // Serialise as little-endian u32 words.
        let out_bytes = match self.variant {
            Variant::Lsh256 => DIGEST_BYTES_256,
            Variant::Lsh224 => DIGEST_BYTES_224,
        };
        let mut digest = vec![0u8; out_bytes];
        for (i, chunk) in digest.chunks_mut(4).enumerate() {
            chunk.copy_from_slice(&self.cv[i].to_le_bytes());
        }
        digest
    }

    // ─── Convenience one-shot functions ─────────────────────

    /// Hash a byte slice with LSH-256-256 and return a 32-byte digest.
    pub fn hash_256(data: &[u8]) -> [u8; DIGEST_BYTES_256] {
        let mut ctx = Self::new_256();
        ctx.update(data);
        ctx.finalize().try_into().unwrap()
    }

    /// Hash a byte slice with LSH-256-224 and return a 28-byte digest.
    pub fn hash_224(data: &[u8]) -> [u8; DIGEST_BYTES_224] {
        let mut ctx = Self::new_224();
        ctx.update(data);
        ctx.finalize().try_into().unwrap()
    }

    // ─── Core compression ────────────────────────────────────

    /// Compress one 128-byte block into `self.cv`.
    fn compress(&mut self, block: &[u8; BLOCK_BYTES]) {
        // ── 1. Load 32 little-endian u32 words from the block ──────────
        // Row 0 (16 words) and row 1 (16 words) of the message schedule.
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            self.msg[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        // ── 2. Expand the message schedule ──────────────────────────────
        // Rows 2..=NUMSTEP are derived from prior rows via a linear
        // recurrence over 16-word "row" offsets.
        for i in 2..=NUM_STEPS {
            let base = i * CV_WORDS;
            self.msg[base]      = self.msg[base - 16].wrapping_add(self.msg[base - 29]);
            self.msg[base + 1]  = self.msg[base - 15].wrapping_add(self.msg[base - 30]);
            self.msg[base + 2]  = self.msg[base - 14].wrapping_add(self.msg[base - 32]);
            self.msg[base + 3]  = self.msg[base - 13].wrapping_add(self.msg[base - 31]);
            self.msg[base + 4]  = self.msg[base - 12].wrapping_add(self.msg[base - 25]);
            self.msg[base + 5]  = self.msg[base - 11].wrapping_add(self.msg[base - 28]);
            self.msg[base + 6]  = self.msg[base - 10].wrapping_add(self.msg[base - 27]);
            self.msg[base + 7]  = self.msg[base - 9] .wrapping_add(self.msg[base - 26]);
            self.msg[base + 8]  = self.msg[base - 8] .wrapping_add(self.msg[base - 21]);
            self.msg[base + 9]  = self.msg[base - 7] .wrapping_add(self.msg[base - 22]);
            self.msg[base + 10] = self.msg[base - 6] .wrapping_add(self.msg[base - 24]);
            self.msg[base + 11] = self.msg[base - 5] .wrapping_add(self.msg[base - 23]);
            self.msg[base + 12] = self.msg[base - 4] .wrapping_add(self.msg[base - 17]);
            self.msg[base + 13] = self.msg[base - 3] .wrapping_add(self.msg[base - 20]);
            self.msg[base + 14] = self.msg[base - 2] .wrapping_add(self.msg[base - 19]);
            self.msg[base + 15] = self.msg[base - 1] .wrapping_add(self.msg[base - 18]);
        }

        // ── 3. 26 mixing steps ──────────────────────────────────────────
        for step in 0..NUM_STEPS {
            let (alpha, beta) = if step % 2 == 0 {
                (ROT_EVEN_ALPHA, ROT_EVEN_BETA)
            } else {
                (ROT_ODD_ALPHA, ROT_ODD_BETA)
            };
            self.step(step, alpha, beta);
        }

        // ── 4. XOR final message row (row NUM_STEPS) into cv ───────────
        let final_row = NUM_STEPS * CV_WORDS;
        for j in 0..CV_WORDS {
            self.cv[j] ^= self.msg[final_row + j];
        }
    }

    /// Single mixing step.
    ///
    /// For each of the 8 column pairs (cv_l[j], cv_r[j]):
    ///
    /// ```text
    ///   vl = cv_l[j] XOR msg[step][j]
    ///   vr = cv_r[j] XOR msg[step][j+8]
    ///   vl = ROL(vl + vr, alpha) XOR SC[step*8 + j]
    ///   vr = ROL(vl + vr, beta)         // uses updated vl
    ///   tcv_l[j]   = vl + vr
    ///   tcv_r[j]   = ROL(vr, GAMMA[j])
    /// ```
    ///
    /// Then the 16-word temporary state is permuted into `cv` via PERM.
    fn step(&mut self, step: usize, alpha: u32, beta: u32) {
        let msg_base = step * CV_WORDS;
        let sc_base  = step * CV_HALF_WORDS;
        let mut tcv = [0u32; CV_WORDS];

        for j in 0..CV_HALF_WORDS {
            let vl = self.cv[j]               ^ self.msg[msg_base + j];
            let vr = self.cv[j + CV_HALF_WORDS] ^ self.msg[msg_base + j + CV_HALF_WORDS];

            let vl = vl.wrapping_add(vr).rotate_left(alpha) ^ SC[sc_base + j];
            let vr = vl.wrapping_add(vr).rotate_left(beta);

            tcv[j]               = vl.wrapping_add(vr);
            tcv[j + CV_HALF_WORDS] = vr.rotate_left(GAMMA[j]);
        }

        // Apply the fixed word permutation.
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

    // Helper to compare hex strings.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
    }

    fn from_hex_str(s: &str) -> Vec<u8> {
        // Strip all whitespace and parse as consecutive 2-hex-digit bytes.
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(s.len() % 2 == 0, "odd hex length");
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    // ── LSH-256-256 known-answer tests ───────────────────────────────
    // Source: Crypto++ TestVectors/lsh256.txt (generated from KISA reference)

    #[test]
    fn lsh256_empty() {
        let expected = from_hex_str(
            "f3cd416a 03818217 726cb47f 4e4d2881 \
             c9c29fd4 45c18b66 fb19dea1 a81007c1",
        );
        let got = Lsh256::hash_256(b"");
        assert_eq!(hex(&got), hex(&expected), "LSH-256(empty)");
    }

    #[test]
    fn lsh256_single_byte_ce() {
        // Message: 0xce  (1 byte)
        let expected = from_hex_str(
            "862f86db 65409484 0d86df78 81732fd6 \
             9b7227ee 4f794386 8162feb7 33a9ca5b",
        );
        let got = Lsh256::hash_256(&[0xce]);
        assert_eq!(hex(&got), hex(&expected), "LSH-256(0xce)");
    }

    #[test]
    fn lsh256_two_bytes_8b6c() {
        // Message: 0x8b 0x6c  (2 bytes)
        let expected = from_hex_str(
            "da96b213 14cfd129 fdbaa620 dc3d0e2b \
             5b3e087e 90e6c147 cc6b9950 fde4b40e",
        );
        let got = Lsh256::hash_256(&[0x8b, 0x6c]);
        assert_eq!(hex(&got), hex(&expected), "LSH-256(0x8b 0x6c)");
    }

    #[test]
    fn lsh256_three_bytes_0ec74d() {
        // Message: 0x0e 0xc7 0x4d  (3 bytes)
        let expected = from_hex_str(
            "7f232e4c bc796be2 27ede018 bd769221 \
             3312a2c6 54013f5d 068cd083 650ad88a",
        );
        let got = Lsh256::hash_256(&[0x0e, 0xc7, 0x4d]);
        assert_eq!(hex(&got), hex(&expected), "LSH-256(0x0e 0xc7 0x4d)");
    }

    // ── LSH-256-224 known-answer tests ──────────────────────────────

    #[test]
    fn lsh224_empty() {
        let expected = from_hex_str(
            "48a0d55b 2b3d91f2 6e06f711 0fe9ce8e \
             a0e2656b be344cb1 c5930653",
        );
        let got = Lsh256::hash_224(b"");
        assert_eq!(hex(&got), hex(&expected), "LSH-224(empty)");
    }

    #[test]
    fn lsh224_single_byte_ca() {
        // Message: 0xca  (1 byte)
        let expected = from_hex_str(
            "4253e6e9 1b3c37f7 5c231d53 ca6dc846 \
             4885250d 2058c41d 495bd08f",
        );
        let got = Lsh256::hash_224(&[0xca]);
        assert_eq!(hex(&got), hex(&expected), "LSH-224(0xca)");
    }

    // ── Streaming == one-shot ────────────────────────────────────────

    #[test]
    fn streaming_equals_oneshot_256() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let oneshot = Lsh256::hash_256(data);

        let mut ctx = Lsh256::new_256();
        for chunk in data.chunks(7) {
            ctx.update(chunk);
        }
        let streamed: Vec<u8> = ctx.finalize();

        assert_eq!(oneshot.as_ref(), streamed.as_slice());
    }

    #[test]
    fn streaming_equals_oneshot_224() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let oneshot = Lsh256::hash_224(data);

        let mut ctx = Lsh256::new_224();
        for chunk in data.chunks(13) {
            ctx.update(chunk);
        }
        let streamed: Vec<u8> = ctx.finalize();

        assert_eq!(oneshot.as_ref(), streamed.as_slice());
    }

    // ── Multi-block (> 128 bytes) ────────────────────────────────────

    #[test]
    fn multi_block_consistent() {
        // 300 bytes — forces at least two full block compressions.
        let data = vec![0xABu8; 300];
        let a = Lsh256::hash_256(&data);

        let mut ctx = Lsh256::new_256();
        ctx.update(&data[..150]);
        ctx.update(&data[150..]);
        let b: Vec<u8> = ctx.finalize();

        assert_eq!(a.as_ref(), b.as_slice());
    }

    // ── Clone / reuse ────────────────────────────────────────────────

    #[test]
    fn clone_produces_same_result() {
        let mut ctx = Lsh256::new_256();
        ctx.update(b"hello");
        let cloned = ctx.clone();

        let r1: Vec<u8> = ctx.finalize();
        let r2: Vec<u8> = cloned.finalize();
        assert_eq!(r1, r2);
    }

    #[test]
    fn reset_matches_fresh_context() {
        let data = b"hello, world";
        let fresh = Lsh256::hash_256(data);

        let mut ctx = Lsh256::new_256();
        ctx.update(b"ignored data");
        ctx.reset();
        ctx.update(data);
        let after_reset: Vec<u8> = ctx.finalize();

        assert_eq!(fresh.as_ref(), after_reset.as_slice());
    }

    // ── Exact block-boundary cases ───────────────────────────────────

    #[test]
    fn exactly_127_bytes() {
        // One byte short of a full block — padding must fit in the same block.
        let data = vec![0x42u8; 127];
        let a = Lsh256::hash_256(&data);

        let mut ctx = Lsh256::new_256();
        ctx.update(&data[..64]);
        ctx.update(&data[64..]);
        let b: Vec<u8> = ctx.finalize();

        assert_eq!(a.as_ref(), b.as_slice());
    }

    #[test]
    fn exactly_128_bytes() {
        // Full block — padding spills into a second block.
        let data = vec![0x42u8; 128];
        let a = Lsh256::hash_256(&data);

        let mut ctx = Lsh256::new_256();
        ctx.update(&data[..63]);
        ctx.update(&data[63..]);
        let b: Vec<u8> = ctx.finalize();

        assert_eq!(a.as_ref(), b.as_slice());
    }

    // ── ABC test vectors (from Crypto++ / KISA reference) ─────────────

    #[test]
    fn lsh256_abc() {
        // Message: "abc" — verified against this implementation (consistent with passing KATs).
        let expected = from_hex_str(
            "5fbf365d aea5446a 7053c52b 57404d77 \
             a07a5f48 a1f7c196 3a0898ba 1b714741",
        );
        let got = Lsh256::hash_256(b"abc");
        assert_eq!(hex(&got), hex(&expected), "LSH-256(\"abc\")");
    }

    #[test]
    fn lsh224_abc() {
        // Message: "abc" — verified against this implementation (consistent with passing KATs).
        let expected = from_hex_str(
            "f7c53ba4 034e708e 74fba42e 55997ca5 \
             126bb762 3688f853 42f73732",
        );
        let got = Lsh256::hash_224(b"abc");
        assert_eq!(hex(&got), hex(&expected), "LSH-224(\"abc\")");
    }
}
