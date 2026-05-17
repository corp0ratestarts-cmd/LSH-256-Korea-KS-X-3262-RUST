// Basic usage examples for the lsh256 crate — covers both LSH-256 and LSH-512.

use lsh256::{Lsh256, Lsh512, Variant, Variant512};

fn main() {
    // ── LSH-256 family ────────────────────────────────────────────────

    let h256 = Lsh256::hash_256(b"hello, world");
    let h224 = Lsh256::hash_224(b"hello, world");
    println!("LSH-256: {}", hex(&h256));
    println!("LSH-224: {}", hex(&h224));

    // ── LSH-512 family ────────────────────────────────────────────────

    let h512     = Lsh512::hash_512(b"hello, world");
    let h384     = Lsh512::hash_384(b"hello, world");
    let h512_256 = Lsh512::hash_512_256(b"hello, world");
    let h512_224 = Lsh512::hash_512_224(b"hello, world");
    println!("LSH-512:     {}", hex(&h512));
    println!("LSH-384:     {}", hex(&h384));
    println!("LSH-512-256: {}", hex(&h512_256));
    println!("LSH-512-224: {}", hex(&h512_224));

    // ── Streaming (incremental) ───────────────────────────────────────

    let mut ctx = Lsh256::new_256();
    ctx.update(b"hello");
    ctx.update(b", ");
    ctx.update(b"world");
    let streamed: Vec<u8> = ctx.finalize();
    assert_eq!(h256.as_ref(), streamed.as_slice());
    println!("LSH-256 streaming == one-shot: ✓");

    let mut ctx512 = Lsh512::new_512();
    ctx512.update(b"hello");
    ctx512.update(b", ");
    ctx512.update(b"world");
    let streamed512: Vec<u8> = ctx512.finalize();
    assert_eq!(h512.as_ref(), streamed512.as_slice());
    println!("LSH-512 streaming == one-shot: ✓");

    // ── Runtime variant selection ─────────────────────────────────────

    for (label, v) in [
        ("LSH-256", Variant::Lsh256),
        ("LSH-224", Variant::Lsh224),
    ] {
        let mut ctx = Lsh256::new(v);
        ctx.update(b"qash protocol");
        println!("{label}: {}", hex(&ctx.finalize()));
    }

    for (label, v) in [
        ("LSH-512",     Variant512::Lsh512),
        ("LSH-384",     Variant512::Lsh384),
        ("LSH-512-256", Variant512::Lsh512_256),
        ("LSH-512-224", Variant512::Lsh512_224),
    ] {
        let mut ctx = Lsh512::new(v);
        ctx.update(b"qash protocol");
        println!("{label}: {}", hex(&ctx.finalize()));
    }

    // ── Context reuse ─────────────────────────────────────────────────

    let mut ctx = Lsh512::new_512();
    ctx.update(b"message one");
    let h1: Vec<u8> = ctx.clone().finalize();
    ctx.reset();
    ctx.update(b"message two");
    let h2: Vec<u8> = ctx.finalize();
    assert_ne!(h1, h2);
    println!("reset works: ✓");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
