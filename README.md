# lsh256 — Korean Standard Hash Function (KS X 3262)

Pure-Rust implementation of **LSH-256** (Lightweight Secure Hash), the Korean cryptographic hash function standardised as **KS X 3262** by KISA / NSRI (2014).

Supports:
- **LSH-256** — 256-bit (32-byte) digest (`LSH-256-256`)
- **LSH-224** — 224-bit (28-byte) digest (`LSH-256-224`)

No `unsafe` code. No external runtime dependencies. All 15 tests pass against KISA / Crypto++ known-answer vectors.

---

## Quick start

### Get the code

```bash
git clone https://github.com/corp0ratestarts-cmd/LSH-256-Korea-KS-X-3262-RUST.git
cd LSH-256-Korea-KS-X-3262-RUST
```

### Build and test

```bash
cargo build           # debug build
cargo build --release # optimised build
cargo test            # run all 15 unit tests
```

### Use the CLI tool

```bash
# Hash stdin (LSH-256 by default)
echo -n "hello, world" | cargo run --release

# Hash with LSH-224
echo -n "hello, world" | cargo run --release -- --224

# Hash files
cargo run --release -- file1.bin file2.bin
cargo run --release -- --224 document.pdf

# Or run the compiled binary directly after `cargo build --release`
echo -n "" | ./target/release/lsh256
```

---

## Use as a library in your own Rust project

### 1. Add the dependency

In your project's `Cargo.toml`, add a path dependency (or a git dependency if you prefer):

```toml
[dependencies]
# Path dependency (if you cloned this repo alongside your project)
lsh256 = { path = "../LSH-256-Korea-KS-X-3262-RUST" }

# Git dependency (pulls directly from GitHub)
lsh256 = { git = "https://github.com/corp0ratestarts-cmd/LSH-256-Korea-KS-X-3262-RUST.git" }
```

### 2. One-shot hashing

```rust
use lsh256::Lsh256;

fn main() {
    // 256-bit (32-byte) digest
    let hash: [u8; 32] = Lsh256::hash_256(b"hello, world");
    println!("{}", hash.iter().map(|b| format!("{b:02x}")).collect::<String>());

    // 224-bit (28-byte) digest
    let hash: [u8; 28] = Lsh256::hash_224(b"hello, world");
    println!("{}", hash.iter().map(|b| format!("{b:02x}")).collect::<String>());
}
```

### 3. Streaming (incremental) hashing

Feed data in chunks — useful for large files or network streams:

```rust
use lsh256::Lsh256;

let mut ctx = Lsh256::new_256();
ctx.update(b"chunk one ");
ctx.update(b"chunk two ");
ctx.update(b"chunk three");
let digest: Vec<u8> = ctx.finalize();  // 32 bytes

// Identical to one-shot:
assert_eq!(digest, Lsh256::hash_256(b"chunk one chunk two chunk three").to_vec());
```

### 4. Select variant at runtime

```rust
use lsh256::{Lsh256, Variant};

fn hash_data(data: &[u8], variant: Variant) -> Vec<u8> {
    let mut ctx = Lsh256::new(variant);
    ctx.update(data);
    ctx.finalize()
}

let digest_256 = hash_data(b"qash", Variant::Lsh256);  // 32 bytes
let digest_224 = hash_data(b"qash", Variant::Lsh224);  // 28 bytes
```

### 5. Reuse a context

```rust
use lsh256::Lsh256;

let mut ctx = Lsh256::new_256();

ctx.update(b"message one");
let h1: Vec<u8> = ctx.clone().finalize(); // clone to keep ctx alive

ctx.reset();                              // reset to initial state
ctx.update(b"message two");
let h2: Vec<u8> = ctx.finalize();
```

### 6. Hash a file (streaming)

```rust
use std::fs::File;
use std::io::Read;
use lsh256::Lsh256;

fn hash_file(path: &str) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut ctx = Lsh256::new_256();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        ctx.update(&buf[..n]);
    }
    Ok(ctx.finalize())
}
```

Or just run the included example:

```bash
cargo run --example hash_file -- path/to/your/file
cargo run --example hash_file -- --224 path/to/your/file
```

---

## API reference

| Function / method | Description |
|---|---|
| `Lsh256::hash_256(data)` | One-shot LSH-256, returns `[u8; 32]` |
| `Lsh256::hash_224(data)` | One-shot LSH-224, returns `[u8; 28]` |
| `Lsh256::new_256()` | New streaming context (256-bit output) |
| `Lsh256::new_224()` | New streaming context (224-bit output) |
| `Lsh256::new(variant)` | New streaming context, variant chosen at runtime |
| `ctx.update(data)` | Feed bytes into the context |
| `ctx.finalize()` | Consume context, return `Vec<u8>` digest |
| `ctx.reset()` | Reset to initial state, reuse allocation |
| `ctx.clone()` | Clone the context mid-stream |

---

## Algorithm overview

LSH is an **ARX** (Add–Rotate–XOR) hash function with a **wide-pipe Merkle–Damgård** structure, designed for high software throughput on modern CPUs.

| Parameter | LSH-256 | LSH-224 |
|---|---|---|
| Output size | 256 bit | 224 bit |
| Word size | 32 bit | 32 bit |
| Internal state | 16 × u32 (512 bit) | same |
| Message block | 32 × u32 (1024 bit) | same |
| Compression steps | 26 | 26 |
| Padding | One-zeros (append `0x80`, then zero bytes) | same |

### Per-block compression

```
1. Message expansion
   32-word block → 27 × 16-word rows
   via:  M[j][l] = M[j-1][l] + M[j-2][τ(l)]   (wrapping u32)

2. 26 step functions, each:
   a. MsgAdd   — XOR sub-message row into the 16-word state
   b. Mix      — for each of 8 column pairs (cv[j], cv[j+8]):
                   vl = ROL32(vl + vr, α) ⊕ SC[step][j]
                   vr = ROL32(vl + vr, β)
                   cv[j]   = vl + vr
                   cv[j+8] = ROL32(vr, γ[j])
                 α, β alternate: {29,1} (even steps) / {5,17} (odd steps)
   c. WordPerm — permute all 16 state words with table σ

3. Final MsgAdd with row 26

4. Finalise
   cv[j] ^= cv[j+8]  for j in 0..8
   output = little-endian bytes of cv[0..8]
   (truncated to 28 bytes for LSH-224)
```

### Key constants

**γ** (per-column rotation after Mix):

| Column | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
|--------|---|---|---|---|---|---|---|---|
| γ      | 0 | 8 |16 |24 |24 |16 | 8 | 0 |

**τ** permutation (message expansion):

| l    | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |10 |11 |12 |13 |14 |15 |
|------|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| τ(l) | 3 | 2 | 0 | 1 | 7 | 4 | 5 | 6 |11 |10 | 8 | 9 |15 |12 |13 |14 |

**σ** permutation (WordPerm):

| l    | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |10 |11 |12 |13 |14 |15 |
|------|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| σ(l) | 6 | 4 | 5 | 7 |12 |15 |14 |13 | 2 | 0 | 1 | 3 | 8 |11 |10 | 9 |

**Initial step constant SC₀** (first 256 fractional bits of √768372, where `L=76`, `S=83`, `H=72` in ASCII):

```
917caf90  6c1b10a2  6f352943  cf778243
2ceb7472  29e96ff2  8a9ba428  2eeb2642
```

Remaining 25 step constants: `SC[j][l] = SC[j-1][l] ⊞ ROL32(SC[j-1][l], 8)`.

---

## Known-answer test vectors

All vectors verified against the KISA / Crypto++ reference implementation.

### LSH-256-256

| Input | Digest |
|-------|--------|
| *(empty)* | `f3cd416a03818217726cb47f4e4d2881c9c29fd445c18b66fb19dea1a81007c1` |
| `ce` | `862f86db654094840d86df7881732fd69b7227ee4f7943868162feb733a9ca5b` |
| `8b 6c` | `da96b21314cfd129fdbaa620dc3d0e2b5b3e087e90e6c147cc6b9950fde4b40e` |
| `0e c7 4d` | `7f232e4cbc796be227ede018bd7692213312a2c654013f5d068cd083650ad88a` |

### LSH-256-224

| Input | Digest |
|-------|--------|
| *(empty)* | `48a0d55b2b3d91f26e06f7110fe9ce8ea0e2656bbe344cb1c5930653` |
| `ca` | `4253e6e91b3c37f75c231d53ca6dc8464885250d2058c41d495bd08f` |

---

## References

- **KS X 3262** — Korean national standard, KISA/NSRI (2014)
- Kim et al., *"LSH: A New Fast Secure Hash Function Family"*, ICISC 2014
- KISA algorithm page: <https://seed.kisa.or.kr/kisa/algorithm/EgovLSHInfo.do>
- Crypto++ reference: <https://github.com/weidai11/cryptopp/blob/master/lsh256.cpp>

---

## License

[Mozilla Public License 2.0](LICENSE)
