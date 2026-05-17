# lsh256 — Korean Standard Hash Function (KS X 3262)

Pure-Rust implementation of **LSH-256** (Lightweight Secure Hash), the Korean cryptographic hash function standardised as **KS X 3262** by KISA / NSRI.

Supports:
- **LSH-256** — 256-bit (32-byte) digest (`LSH-256-256`)
- **LSH-224** — 224-bit (28-byte) digest (`LSH-256-224`)

All operations are constant-time with respect to secret data (no secret-dependent branches or table lookups). No `unsafe` code; no external runtime dependencies.

---

## Algorithm overview

LSH is an ARX (Add–Rotate–XOR) hash function with a **wide-pipe Merkle–Damgård** structure, designed for high software throughput, particularly on SIMD-capable processors.

| Parameter            | LSH-256 | LSH-224 |
|----------------------|---------|---------|
| Output size          | 256 bit | 224 bit |
| Word size (`w`)      | 32 bit  | 32 bit  |
| State (`cv`)         | 16 × u32 (512 bit) | same |
| Message block        | 32 × u32 (1024 bit) | same |
| Compression steps    | 26      | 26      |
| Standard             | KS X 3262 | KS X 3262 |

### Compression function (per 128-byte block)

1. **Message expansion** — the 32-word block is expanded into 27 × 16-word sub-messages via a linear recurrence (wrapping addition + τ-permutation).
2. **26 step functions** — each step:
   - `MsgAdd`: XOR the sub-message into the chaining value.
   - `Mix`: For each of the 8 column pairs `(cv[j], cv[j+8])`:
     ```
     vl = ROL32(vl + vr, α) ⊕ SC[step][j]
     vr = ROL32(vl + vr, β)
     cv[j]   = vl + vr
     cv[j+8] = ROL32(vr, γ[j])
     ```
     where α and β alternate between `{29, 1}` (even steps) and `{5, 17}` (odd steps).
   - `WordPerm`: permute all 16 words of the chaining value with table σ.
3. **Final MsgAdd** with the 27th sub-message row.

### Finalisation

```
cv[j] ^= cv[j + 8]   for j in 0..8
output = little-endian bytes of cv[0..8]   (truncated to 28 bytes for LSH-224)
```

### Padding

Append `0x80` immediately after the last message byte, then zero-fill the remainder of the current 128-byte block. No length field is appended.

---

## Usage

Add to `Cargo.toml`:

```toml
[dependencies]
lsh256 = { path = "." }   # or version once published
```

### One-shot hashing

```rust
use lsh256::Lsh256;

// 256-bit digest
let hash: [u8; 32] = Lsh256::hash_256(b"hello, world");
println!("{}", hash.iter().map(|b| format!("{b:02x}")).collect::<String>());

// 224-bit digest
let hash: [u8; 28] = Lsh256::hash_224(b"hello, world");
```

### Streaming (incremental) hashing

```rust
use lsh256::Lsh256;

let mut ctx = Lsh256::new_256();
ctx.update(b"hello");
ctx.update(b", ");
ctx.update(b"world");
let digest: Vec<u8> = ctx.finalize();   // 32 bytes
```

### Variant selection at runtime

```rust
use lsh256::{Lsh256, Variant};

fn hash(data: &[u8], variant: Variant) -> Vec<u8> {
    let mut ctx = Lsh256::new(variant);
    ctx.update(data);
    ctx.finalize()
}
```

### Reusing a context

```rust
use lsh256::Lsh256;

let mut ctx = Lsh256::new_256();
ctx.update(b"first");
let h1: Vec<u8> = ctx.clone().finalize();

ctx.reset();               // resets to IV, reuses allocation
ctx.update(b"second");
let h2: Vec<u8> = ctx.finalize();
```

---

## Command-line tool

```bash
# Build
cargo build --release

# Hash stdin
echo -n "hello, world" | ./target/release/lsh256

# Hash stdin with LSH-224
echo -n "hello, world" | ./target/release/lsh256 --224

# Hash files
./target/release/lsh256 file1.txt file2.txt
./target/release/lsh256 --224 file.txt
```

---

## Examples

```bash
cargo run --example basic
cargo run --example hash_file -- --256 Cargo.toml
```

---

## Known-answer test vectors

All vectors are from the KISA / Crypto++ reference test suite.

### LSH-256-256

| Input (hex)      | Digest |
|------------------|--------|
| *(empty)*        | `f3cd416a03818217726cb47f4e4d2881c9c29fd445c18b66fb19dea1a81007c1` |
| `ce`             | `862f86db654094840d86df7881732fd69b7227ee4f7943868162feb733a9ca5b` |
| `8b 6c`          | `da96b21314cfd129fdbaa620dc3d0e2b5b3e087e90e6c147cc6b9950fde4b40e` |
| `0e c7 4d`       | `7f232e4cbc796be227ede018bd7692213312a2c654013f5d068cd083650ad88a` |

### LSH-256-224

| Input (hex)      | Digest |
|------------------|--------|
| *(empty)*        | `48a0d55b2b3d91f26e06f7110fe9ce8ea0e2656bbe344cb1c5930653` |
| `ca`             | `4253e6e91b3c37f75c231d53ca6dc8464885250d2058c41d495bd08f` |

---

## Constants

### Rotation amounts

| Step parity | α  | β  |
|-------------|----|----|
| even        | 29 | 1  |
| odd         |  5 | 17 |

**γ** (applied to the right-half word after mixing, indexed by column `j`):

| j | 0 | 1 | 2 | 3 | 4  | 5  | 6 | 7 |
|---|---|---|---|---|----|----|---|---|
| γ | 0 | 8 | 16| 24| 24 | 16 | 8 | 0 |

### Initial step constant SC₀

Derived from the first 256 fractional bits of √(768372), where `76='L'`, `83='S'`, `72='H'` in ASCII:

```
917caf90  6c1b10a2  6f352943  cf778243
2ceb7472  29e96ff2  8a9ba428  2eeb2642
```

Remaining 25 step constants are derived by `SC[j][l] = SC[j-1][l] ⊞ ROL32(SC[j-1][l], 8)`.

### τ permutation (message expansion)

| l    | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8  | 9  | 10 | 11 | 12 | 13 | 14 | 15 |
|------|---|---|---|---|---|---|---|---|----|----|----|----|----|----|----|-----|
| τ(l) | 3 | 2 | 0 | 1 | 7 | 4 | 5 | 6 | 11 | 10 |  8 |  9 | 15 | 12 | 13 | 14 |

### σ permutation (WordPerm)

| l    | 0 | 1 | 2 | 3 | 4  | 5  | 6  | 7  | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
|------|---|---|---|---|----|----|----|----|---|---|----|----|----|----|----|-----|
| σ(l) | 6 | 4 | 5 | 7 | 12 | 15 | 14 | 13 | 2 | 0 |  1 |  3 |  8 | 11 | 10 |  9 |

---

## References

- **KS X 3262** — Korean national standard (KISA/NSRI, 2014)
- Kim et al., *"LSH: A New Fast Secure Hash Function Family"*, ICISC 2014
- KISA algorithm page: <https://seed.kisa.or.kr/kisa/algorithm/EgovLSHInfo.do>
- Crypto++ reference implementation: <https://github.com/weidai11/cryptopp/blob/master/lsh256.cpp>

---

## License

Mozilla Public License 2.0 — see [LICENSE](LICENSE).
