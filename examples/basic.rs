// Basic usage examples for the lsh256 crate.

use lsh256::{Lsh256, Variant};

fn main() {
    // ── One-shot hashing ──────────────────────────────────────────────

    let digest_256 = Lsh256::hash_256(b"hello, world");
    println!("LSH-256: {}", hex(&digest_256));

    let digest_224 = Lsh256::hash_224(b"hello, world");
    println!("LSH-224: {}", hex(&digest_224));

    // ── Streaming (incremental) hashing ──────────────────────────────

    let mut ctx = Lsh256::new_256();
    ctx.update(b"hello");
    ctx.update(b", ");
    ctx.update(b"world");
    let streamed: Vec<u8> = ctx.finalize();

    // Streaming and one-shot produce identical results.
    assert_eq!(digest_256.as_ref(), streamed.as_slice());
    println!("Streaming LSH-256 (same): {}", hex(&streamed));

    // ── Variant selection at runtime ─────────────────────────────────

    for (label, variant) in [("LSH-256", Variant::Lsh256), ("LSH-224", Variant::Lsh224)] {
        let mut ctx = Lsh256::new(variant);
        ctx.update(b"qash protocol");
        let d = ctx.finalize();
        println!("{label}: {}", hex(&d));
    }

    // ── Reusing a context ────────────────────────────────────────────

    let mut ctx = Lsh256::new_256();
    ctx.update(b"first message");
    let h1: Vec<u8> = ctx.clone().finalize();

    ctx.reset();
    ctx.update(b"second message");
    let h2: Vec<u8> = ctx.finalize();

    println!("h1: {}", hex(&h1));
    println!("h2: {}", hex(&h2));
    assert_ne!(h1, h2);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
