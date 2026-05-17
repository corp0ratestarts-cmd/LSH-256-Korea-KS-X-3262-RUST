// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// LSH-256 command-line driver
//
// Usage:
//   echo -n "hello" | lsh256          # LSH-256-256 of stdin
//   echo -n "hello" | lsh256 --224    # LSH-256-224 of stdin
//   lsh256 file.txt                   # LSH-256-256 of a file
//   lsh256 --224 file.txt             # LSH-256-224 of a file

use std::env;
use std::fs::File;
use std::io::{self, Read};

use lsh256::{Lsh256, Variant};

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    let mut variant = Variant::Lsh256;
    let mut files: Vec<&str> = Vec::new();

    for arg in &args[1..] {
        match arg.as_str() {
            "--224" | "-224" => variant = Variant::Lsh224,
            "--256" | "-256" => variant = Variant::Lsh256,
            other => files.push(other),
        }
    }

    if files.is_empty() {
        // Hash stdin.
        let mut data = Vec::new();
        io::stdin().read_to_end(&mut data)?;
        let digest = hash_bytes(&data, variant);
        println!("{}", hex_string(&digest));
    } else {
        for path in &files {
            let mut data = Vec::new();
            File::open(path)?.read_to_end(&mut data)?;
            let digest = hash_bytes(&data, variant);
            println!("{}  {}", hex_string(&digest), path);
        }
    }

    Ok(())
}

fn hash_bytes(data: &[u8], variant: Variant) -> Vec<u8> {
    let mut ctx = Lsh256::new(variant);
    ctx.update(data);
    ctx.finalize()
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
