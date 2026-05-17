# lsh256 — Korean Standard Hash Function (KS X 3262)

Pure-Rust implementation of the **LSH** (Lightweight Secure Hash) family, the Korean cryptographic hash function standardised as **KS X 3262** by KISA / NSRI (2014).

Covers the complete standard — both word-size families and all six named output variants:

| Variant | Word | Steps | Output | Type |
|---------|------|-------|--------|------|
| **LSH-256** | 32-bit | 26 | 256-bit (32 bytes) | `Lsh256` / `Variant::Lsh256` |
| **LSH-224** | 32-bit | 26 | 224-bit (28 bytes) | `Lsh256` / `Variant::Lsh224` |
| **LSH-512** | 64-bit | 28 | 512-bit (64 bytes) | `Lsh512` / `Variant512::Lsh512` |
| **LSH-384** | 64-bit | 28 | 384-bit (48 bytes) | `Lsh512` / `Variant512::Lsh384` |
| **LSH-512-256** | 64-bit | 28 | 256-bit (32 bytes) | `Lsh512` / `Variant512::Lsh512_256` |
| **LSH-512-224** | 64-bit | 28 | 224-bit (28 bytes) | `Lsh512` / `Variant512::Lsh512_224` |

No `unsafe` code. No external runtime dependencies.

---

## Quick start

### Clone and build

```bash
git clone https://github.com/corp0ratestarts-cmd/LSH-256-Korea-KS-X-3262-RUST.git
cd LSH-256-Korea-KS-X-3262-RUST

cargo build           # debug
cargo build --release # optimised
cargo test            # run all 31 unit tests
```

### Command-line tool

```bash
# LSH-256 (default)
echo -n "hello" | cargo run --release

# Select any variant with a flag
echo -n "hello" | cargo run --release -- --224
echo -n "hello" | cargo run --release -- --512
echo -n "hello" | cargo run --release -- --384
echo -n "hello" | cargo run --release -- --512-256
echo -n "hello" | cargo run --release -- --512-224

# Hash files
cargo run --release -- --512 file.bin
cargo run --release -- --256 doc.pdf report.txt

# Or use the compiled binary directly
echo -n "" | ./target/release/lsh256 --512
```

---

## Use as a library in your Rust project

### 1. Add the dependency

```toml
[dependencies]
# Path dependency (if cloned alongside your project)
lsh256 = { path = "../LSH-256-Korea-KS-X-3262-RUST" }

# Git dependency (pulls from GitHub)
lsh256 = { git = "https://github.com/corp0ratestarts-cmd/LSH-256-Korea-KS-X-3262-RUST.git" }
```

### 2. One-shot hashing

```rust
use lsh256::{Lsh256, Lsh512};

// LSH-256 family
let h256: [u8; 32] = Lsh256::hash_256(b"hello, world");
let h224: [u8; 28] = Lsh256::hash_224(b"hello, world");

// LSH-512 family
let h512:     [u8; 64] = Lsh512::hash_512(b"hello, world");
let h384:     [u8; 48] = Lsh512::hash_384(b"hello, world");
let h512_256: [u8; 32] = Lsh512::hash_512_256(b"hello, world");
let h512_224: [u8; 28] = Lsh512::hash_512_224(b"hello, world");

println!("{}", h512.iter().map(|b| format!("{b:02x}")).collect::<String>());
```

### 3. Streaming (incremental) hashing

Feed data in chunks — useful for large files or network streams:

```rust
use lsh256::Lsh512;

let mut ctx = Lsh512::new_512();
ctx.update(b"chunk one ");
ctx.update(b"chunk two");
let digest: Vec<u8> = ctx.finalize();  // 64 bytes

// Identical to one-shot:
assert_eq!(digest, Lsh512::hash_512(b"chunk one chunk two").to_vec());
```

The same pattern works for `Lsh256` (128-byte blocks) and `Lsh512` (256-byte blocks).

### 4. Select variant at runtime

```rust
use lsh256::{Lsh256, Lsh512, Variant, Variant512};

fn hash_256_family(data: &[u8], variant: Variant) -> Vec<u8> {
    let mut ctx = Lsh256::new(variant);
    ctx.update(data);
    ctx.finalize()
}

fn hash_512_family(data: &[u8], variant: Variant512) -> Vec<u8> {
    let mut ctx = Lsh512::new(variant);
    ctx.update(data);
    ctx.finalize()
}

let d = hash_512_family(b"qash protocol", Variant512::Lsh384); // 48 bytes
```

### 5. Reuse a context with reset

```rust
use lsh256::Lsh512;

let mut ctx = Lsh512::new_512();

ctx.update(b"message one");
let h1: Vec<u8> = ctx.clone().finalize();

ctx.reset();                      // wipes state, reuses allocation
ctx.update(b"message two");
let h2: Vec<u8> = ctx.finalize();

assert_ne!(h1, h2);
```

### 6. Hash a file (streaming)

```rust
use std::fs::File;
use std::io::Read;
use lsh256::Lsh512;

fn hash_file_512(path: &str) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut ctx  = Lsh512::new_512();
    let mut buf  = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        ctx.update(&buf[..n]);
    }
    Ok(ctx.finalize())
}
```

Or run the included example:

```bash
cargo run --example hash_file -- --512 path/to/file
cargo run --example hash_file -- --384 path/to/file
```

---

## API reference

### `Lsh256` (32-bit word family)

| Method | Description |
|--------|-------------|
| `Lsh256::hash_256(data)` | One-shot LSH-256, returns `[u8; 32]` |
| `Lsh256::hash_224(data)` | One-shot LSH-224, returns `[u8; 28]` |
| `Lsh256::new_256()` | New streaming context (256-bit output) |
| `Lsh256::new_224()` | New streaming context (224-bit output) |
| `Lsh256::new(variant)` | New context with variant chosen at runtime |
| `ctx.update(data)` | Feed bytes into the context |
| `ctx.finalize()` | Consume context, return `Vec<u8>` digest |
| `ctx.reset()` | Reset to initial state, reuse allocation |
| `ctx.clone()` | Clone mid-stream |

### `Lsh512` (64-bit word family)

| Method | Description |
|--------|-------------|
| `Lsh512::hash_512(data)` | One-shot LSH-512, returns `[u8; 64]` |
| `Lsh512::hash_384(data)` | One-shot LSH-384, returns `[u8; 48]` |
| `Lsh512::hash_512_256(data)` | One-shot LSH-512-256, returns `[u8; 32]` |
| `Lsh512::hash_512_224(data)` | One-shot LSH-512-224, returns `[u8; 28]` |
| `Lsh512::new_512()` | New streaming context (512-bit output) |
| `Lsh512::new_384()` | New streaming context (384-bit output) |
| `Lsh512::new_512_256()` | New streaming context (256-bit output) |
| `Lsh512::new_512_224()` | New streaming context (224-bit output) |
| `Lsh512::new(variant)` | New context with variant chosen at runtime |
| `ctx.update(data)` | Feed bytes into the context |
| `ctx.finalize()` | Consume context, return `Vec<u8>` digest |
| `ctx.reset()` | Reset to initial state, reuse allocation |
| `ctx.clone()` | Clone mid-stream |

---

## Algorithm overview

Both families share identical structure — only word size, step count, block size, and rotation constants differ.

### Compression function (per block)

```
1. Message expansion
   The N-word block is split into two 16-word sub-messages (rows 0 and 1).
   Rows 2 … Ns are derived by the recurrence:
       M_j[l] = M_{j-1}[l] ⊞ M_{j-2}[τ(l)]    (wrapping addition)
   where τ is a fixed 16-element permutation.

2. Ns step functions (26 for LSH-256, 28 for LSH-512), each:
   a. MsgAdd   — XOR the current sub-message row into the 16-word state.
   b. Mix      — For each of 8 column pairs (cv[j], cv[j+8]):
                   vl = ROL(vl + vr, α) ⊕ SC[step][j]
                   vr = ROL(vl + vr, β)         ← uses updated vl
                   cv[j]   = vl + vr
                   cv[j+8] = ROL(vr, γ[j])
                 α and β alternate between two pairs (even vs. odd step).
   c. WordPerm — permute all 16 state words with the σ table.

3. Final MsgAdd — XOR sub-message row Ns into the state.

4. Finalisation
   cv[j] ^= cv[j + 8]   for j in 0 .. 8
   output = little-endian bytes of cv[0 .. 8], truncated to n/8 bytes.
```

### Parameters

|  | LSH-256 family | LSH-512 family |
|--|----------------|----------------|
| Word type | `u32` | `u64` |
| Steps (Ns) | 26 | 28 |
| Block size | 128 bytes | 256 bytes |
| State | 16 × u32 | 16 × u64 |
| α (even / odd) | 29 / 5 | 23 / 7 |
| β (even / odd) | 1 / 17 | 59 / 3 |
| γ | `[0, 8, 16, 24, 24, 16, 8, 0]` | `[0, 16, 32, 48, 8, 24, 40, 56]` |
| Padding | `0x80` then zeros | same |

### τ permutation (message expansion, shared by both families)

| l    | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |10 |11 |12 |13 |14 |15 |
|------|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| τ(l) | 3 | 2 | 0 | 1 | 7 | 4 | 5 | 6 |11 |10 | 8 | 9 |15 |12 |13 |14 |

### σ permutation (WordPerm, shared by both families)

| l    | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |10 |11 |12 |13 |14 |15 |
|------|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| σ(l) | 6 | 4 | 5 | 7 |12 |15 |14 |13 | 2 | 0 | 1 | 3 | 8 |11 |10 | 9 |

### Initial step constants

**LSH-256 SC₀** — first 256 fractional bits of √768372:
```
917caf90  6c1b10a2  6f352943  cf778243
2ceb7472  29e96ff2  8a9ba428  2eeb2642
```

**LSH-512 SC₀** — first 512 fractional bits of ∛768372:
```
97884283c938982a  ba1fca93533e2355
c519a2e87aeb1c03  9a0fc95462af17b1
fc3dda8ab019a82b  02825d079a895407
79f2d0a7ee06a6f7  d76d15eed9fdf5fe
```

All subsequent step constants: `SC[j][l] = SC[j-1][l] ⊞ ROL(SC[j-1][l], 8)`.

---

## Known-answer test vectors

All vectors are consistent with the KS X 3262 algorithm specification.

### LSH-256 family

| Input | Variant | Digest |
|-------|---------|--------|
| *(empty)* | LSH-256 | `f3cd416a03818217726cb47f4e4d2881c9c29fd445c18b66fb19dea1a81007c1` |
| *(empty)* | LSH-224 | `48a0d55b2b3d91f26e06f7110fe9ce8ea0e2656bbe344cb1c5930653` |
| `ce` | LSH-256 | `862f86db654094840d86df7881732fd69b7227ee4f7943868162feb733a9ca5b` |
| `8b 6c` | LSH-256 | `da96b21314cfd129fdbaa620dc3d0e2b5b3e087e90e6c147cc6b9950fde4b40e` |
| `0e c7 4d` | LSH-256 | `7f232e4cbc796be227ede018bd7692213312a2c654013f5d068cd083650ad88a` |
| `ca` | LSH-224 | `4253e6e91b3c37f75c231d53ca6dc8464885250d2058c41d495bd08f` |

### LSH-512 family

| Input | Variant | Digest |
|-------|---------|--------|
| *(empty)* | LSH-512 | `118a2ff2a99e3b2134125e2baf20ebe3bdd034d5a69b29c22fc4995063340b46697801d7f7fb0070568f78e8ed514215fc70af27d6f27b01aa8a1da72b14ce7c` |
| *(empty)* | LSH-384 | `dbb259cf22459368ab2c52b3e1c977288b38670adcb91cae6b8b6a2d646e76f8bd53e5cab0e47c856f55249b895c1730` |
| *(empty)* | LSH-512-256 | `706df4ebf100f06d5cc9f6c79be5297c3f6f515801dd10fbc1b665a2d7bdb653` |
| *(empty)* | LSH-512-224 | `3c124edfe149b45c067965dae681322cdf52aa2c9d738b8f271b9318` |
| `ce` | LSH-512 | `271603ea418bf1af4ac4e87286a641edc256ec7ed4497c8ac4a5975e10414d5f880fd91e773ac2b79038e2d49e700b476071d36c34729303b2f15bd701edf7ec` |
| `8b 6c` | LSH-512 | `6712ee179f99cc74f5082f24b68b90a4c23481ce66409b0a6f1607d5cbc378824112f9928bdac5a141dfd3f83c35023a67702d60abcd3fcceb1fc694769b6626` |

---

## References

- **KS X 3262** — Korean national standard (KISA/NSRI, 2014)
- Kim et al., *"LSH: A New Fast Secure Hash Function Family"*, ICISC 2014
- KISA algorithm page: <https://seed.kisa.or.kr/kisa/algorithm/EgovLSHInfo.do>
- Crypto++ reference: <https://github.com/weidai11/cryptopp/blob/master/lsh256.cpp>

---

## License

[Mozilla Public License 2.0](LICENSE)
