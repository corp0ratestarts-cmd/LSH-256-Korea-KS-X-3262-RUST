// Hash one or more files and print digest(s) in the style of sha256sum.
//
// Usage:
//   cargo run --example hash_file -- path/to/file1 path/to/file2
//   cargo run --example hash_file -- --224 path/to/file

use std::env;
use std::fs::File;
use std::io::{self, Read};

use lsh256::{Lsh256, Variant};

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut variant = Variant::Lsh256;
    let mut paths: Vec<&str> = Vec::new();

    for arg in &args[1..] {
        match arg.as_str() {
            "--224" => variant = Variant::Lsh224,
            "--256" => variant = Variant::Lsh256,
            p => paths.push(p),
        }
    }

    if paths.is_empty() {
        eprintln!("Usage: hash_file [--224|--256] <file> [<file> ...]");
        std::process::exit(1);
    }

    for path in paths {
        let mut file = File::open(path)?;
        let mut ctx = Lsh256::new(variant);
        let mut buf = [0u8; 8192];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            ctx.update(&buf[..n]);
        }
        let digest = ctx.finalize();
        println!("{}  {}", hex(&digest), path);
    }

    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
