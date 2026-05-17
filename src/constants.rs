// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// LSH-256 (KS X 3262) — Algorithm Constants
//
// Source: KISA/NSRI reference implementation and Crypto++ lsh256.cpp
//         https://seed.kisa.or.kr/kisa/algorithm/EgovLSHInfo.do
//         https://github.com/weidai11/cryptopp/blob/master/lsh256.cpp

// ─────────────────────────────────────────────────────────────
// Structural parameters
// ─────────────────────────────────────────────────────────────

/// Number of compression steps.
pub const NUM_STEPS: usize = 26;

/// Number of 32-bit words in each half of the chaining value (left or right).
pub const CV_HALF_WORDS: usize = 8;

/// Total chaining value words (left || right).
pub const CV_WORDS: usize = CV_HALF_WORDS * 2; // 16

/// Message block size in bytes (two 8-word halves × 2 round messages = 32 u32s × 4 bytes).
pub const BLOCK_BYTES: usize = 128;

/// LSH-256 digest size in bytes.
pub const DIGEST_BYTES_256: usize = 32;

/// LSH-224 digest size in bytes.
pub const DIGEST_BYTES_224: usize = 28;

// ─────────────────────────────────────────────────────────────
// Rotation constants used in the MIX operation
// ─────────────────────────────────────────────────────────────
//
// Even steps  (step index is even):  left rotate by ALPHA_EVEN then BETA_EVEN
// Odd  steps  (step index is odd):   left rotate by ALPHA_ODD  then BETA_ODD

pub const ROT_EVEN_ALPHA: u32 = 29;
pub const ROT_EVEN_BETA: u32 = 1;
pub const ROT_ODD_ALPHA: u32 = 5;
pub const ROT_ODD_BETA: u32 = 17;

// ─────────────────────────────────────────────────────────────
// Gamma — message-word rotation amounts applied after MIX
// ─────────────────────────────────────────────────────────────
//
// Applied to the 8 right-half words: right_word[j] = rol32(right_word[j], GAMMA[j])
// Index:      0   1   2   3   4   5  6  7
pub const GAMMA: [u32; 8] = [0, 8, 16, 24, 24, 16, 8, 0];

// ─────────────────────────────────────────────────────────────
// Word permutation applied after each MIX step
// ─────────────────────────────────────────────────────────────
//
// new_cv[i] = tcv[ PERM[i] ]   for i in 0..16
// (tcv is the 16-word temporary chaining value produced by MIX)
pub const PERM: [usize; 16] = [
    6, 4, 5, 7,   // new_cv[ 0.. 3] <- tcv[6,4,5,7]
    12, 15, 14, 13, // new_cv[ 4.. 7] <- tcv[12,15,14,13]
    2, 0, 1, 3,   // new_cv[ 8..11] <- tcv[2,0,1,3]
    8, 11, 10, 9, // new_cv[12..15] <- tcv[8,11,10,9]
];

// ─────────────────────────────────────────────────────────────
// Initialization Vectors
// ─────────────────────────────────────────────────────────────
//
// 16 × 32-bit words (cv_l[0..8] || cv_r[0..8])

/// IV for LSH-256 (full 256-bit output).
pub const IV_256: [u32; 16] = [
    0x46a10f1f, 0xfddce486, 0xb41443a8, 0x198e6b9d,
    0x3304388d, 0xb0f5a3c7, 0xb36061c4, 0x7adbd553,
    0x105d5378, 0x2f74de54, 0x5c2f2d95, 0xf2553fbe,
    0x8051357a, 0x138668c8, 0x47aa4484, 0xe01afb41,
];

/// IV for LSH-256-224 (truncated 224-bit output).
pub const IV_224: [u32; 16] = [
    0x068608d3, 0x62d8f7a7, 0xd76652ab, 0x4c600a43,
    0xbdc40aa8, 0x1eca0b68, 0xda1a89be, 0x3147d354,
    0x707eb4f9, 0xf65b3862, 0x6b0b2abe, 0x56b8ec0a,
    0xcf237286, 0xee0d1727, 0x33636595, 0x8bb8d05f,
];

// ─────────────────────────────────────────────────────────────
// Step Constants  SC[step][word]  —  26 steps × 8 words = 208 u32 values
// ─────────────────────────────────────────────────────────────
//
// Laid out as a flat array of 208 words; index as SC[step * 8 + word].
// Source: Crypto++ lsh256.cpp lines 196–265 (KISA reference identical).

#[rustfmt::skip]
pub const SC: [u32; NUM_STEPS * CV_HALF_WORDS] = [
    // step 0
    0x917caf90, 0x6c1b10a2, 0x6f352943, 0xcf778243,
    0x2ceb7472, 0x29e96ff2, 0x8a9ba428, 0x2eeb2642,
    // step 1
    0x0e2c4021, 0x872bb30e, 0xa45e6cb2, 0x46f9c612,
    0x185fe69e, 0x1359621b, 0x263fccb2, 0x1a116870,
    // step 2
    0x3a6c612f, 0xb2dec195, 0x02cb1f56, 0x40bfd858,
    0x784684b6, 0x6cbb7d2e, 0x660c7ed8, 0x2b79d88a,
    // step 3
    0xa6cd9069, 0x91a05747, 0xcdea7558, 0x00983098,
    0xbecb3b2e, 0x2838ab9a, 0x728b573e, 0xa55262b5,
    // step 4
    0x745dfa0f, 0x31f79ed8, 0xb85fce25, 0x98c8c898,
    0x8a0669ec, 0x60e445c2, 0xfde295b0, 0xf7b5185a,
    // step 5
    0xd2580983, 0x29967709, 0x182df3dd, 0x61916130,
    0x90705676, 0x452a0822, 0xe07846ad, 0xaccd7351,
    // step 6
    0x2a618d55, 0xc00d8032, 0x4621d0f5, 0xf2f29191,
    0x00c6cd06, 0x6f322a67, 0x58bef48d, 0x7a40c4fd,
    // step 7
    0x8beee27f, 0xcd8db2f2, 0x67f2c63b, 0xe5842383,
    0xc793d306, 0xa15c91d6, 0x17b381e5, 0xbb05c277,
    // step 8
    0x7ad1620a, 0x5b40a5bf, 0x5ab901a2, 0x69a7a768,
    0x5b66d9cd, 0xfdee6877, 0xcb3566fc, 0xc0c83a32,
    // step 9
    0x4c336c84, 0x9be6651a, 0x13baa3fc, 0x114f0fd1,
    0xc240a728, 0xec56e074, 0x009c63c7, 0x89026cf2,
    // step 10
    0x7f9ff0d0, 0x824b7fb5, 0xce5ea00f, 0x605ee0e2,
    0x02e7cfea, 0x43375560, 0x9d002ac7, 0x8b6f5f7b,
    // step 11
    0x1f90c14f, 0xcdcb3537, 0x2cfeafdd, 0xbf3fc342,
    0xeab7b9ec, 0x7a8cb5a3, 0x9d2af264, 0xfacedb06,
    // step 12
    0xb052106e, 0x99006d04, 0x2bae8d09, 0xff030601,
    0xa271a6d6, 0x0742591d, 0xc81d5701, 0xc9a9e200,
    // step 13
    0x02627f1e, 0x996d719d, 0xda3b9634, 0x02090800,
    0x14187d78, 0x499b7624, 0xe57458c9, 0x738be2c9,
    // step 14
    0x64e19d20, 0x06df0f36, 0x15d1cb0e, 0x0b110802,
    0x2c95f58c, 0xe5119a6d, 0x59cd22ae, 0xff6eac3c,
    // step 15
    0x467ebd84, 0xe5ee453c, 0xe79cd923, 0x1c190a0d,
    0xc28b81b8, 0xf6ac0852, 0x26efd107, 0x6e1ae93b,
    // step 16
    0xc53c41ca, 0xd4338221, 0x8475fd0a, 0x35231729,
    0x4e0d3a7a, 0xa2b45b48, 0x16c0d82d, 0x890424a9,
    // step 17
    0x017e0c8f, 0x07b5a3f5, 0xfa73078e, 0x583a405e,
    0x5b47b4c8, 0x570fa3ea, 0xd7990543, 0x8d28ce32,
    // step 18
    0x7f8a9b90, 0xbd5998fc, 0x6d7a9688, 0x927a9eb6,
    0xa2fc7d23, 0x66b38e41, 0x709e491a, 0xb5f700bf,
    // step 19
    0x0a262c0f, 0x16f295b9, 0xe8111ef5, 0x0d195548,
    0x9f79a0c5, 0x1a41cfa7, 0x0ee7638a, 0xacf7c074,
    // step 20
    0x30523b19, 0x09884ecf, 0xf93014dd, 0x266e9d55,
    0x191a6664, 0x5c1176c1, 0xf64aed98, 0xa4b83520,
    // step 21
    0x828d5449, 0x91d71dd8, 0x2944f2d6, 0x950bf27b,
    0x3380ca7d, 0x6d88381d, 0x4138868e, 0x5ced55c4,
    // step 22
    0x0fe19dcb, 0x68f4f669, 0x6e37c8ff, 0xa0fe6e10,
    0xb44b47b0, 0xf5c0558a, 0x79bf14cf, 0x4a431a20,
    // step 23
    0xf17f68da, 0x5deb5fd1, 0xa600c86d, 0x9f6c7eb0,
    0xff92f864, 0xb615e07f, 0x38d3e448, 0x8d5d3a6a,
    // step 24
    0x70e843cb, 0x494b312e, 0xa6c93613, 0x0beb2f4f,
    0x928b5d63, 0xcbf66035, 0x0cb82c80, 0xea97a4f7,
    // step 25
    0x592c0f3b, 0x947c5f77, 0x6fff49b9, 0xf71a7e5a,
    0x1de8c0f5, 0xc2569600, 0xc4e4ac8c, 0x823c9ce1,
];
