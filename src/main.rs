// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// LSH command-line driver
//
// Usage:
//   echo -n "hello" | lsh256              # LSH-256 (default)
//   echo -n "hello" | lsh256 --224        # LSH-224
//   echo -n "hello" | lsh256 --512        # LSH-512
//   echo -n "hello" | lsh256 --384        # LSH-384
//   echo -n "hello" | lsh256 --512-256    # LSH-512-256
//   echo -n "hello" | lsh256 --512-224    # LSH-512-224
//   lsh256 [--<variant>] file1 file2 ...

use std::env;
use std::fs::File;
use std::io::{self, Read};

use lsh256::{Lsh256, Lsh512, Variant, Variant512};

#[derive(Clone, Copy)]
enum HashVariant {
    V256(Variant),
    V512(Variant512),
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    let mut variant = HashVariant::V256(Variant::Lsh256);
    let mut files: Vec<&str> = Vec::new();

    for arg in &args[1..] {
        match arg.as_str() {
            "--256"     => variant = HashVariant::V256(Variant::Lsh256),
            "--224"     => variant = HashVariant::V256(Variant::Lsh224),
            "--512"     => variant = HashVariant::V512(Variant512::Lsh512),
            "--384"     => variant = HashVariant::V512(Variant512::Lsh384),
            "--512-256" => variant = HashVariant::V512(Variant512::Lsh512_256),
            "--512-224" => variant = HashVariant::V512(Variant512::Lsh512_224),
            other       => files.push(other),
        }
    }

    if files.is_empty() {
        let mut data = Vec::new();
        io::stdin().read_to_end(&mut data)?;
        println!("{}", hex_string(&hash_bytes(&data, variant)));
    } else {
        for path in &files {
            let mut data = Vec::new();
            File::open(path)?.read_to_end(&mut data)?;
            println!("{}  {}", hex_string(&hash_bytes(&data, variant)), path);
        }
    }

    Ok(())
}

fn hash_bytes(data: &[u8], variant: HashVariant) -> Vec<u8> {
    match variant {
        HashVariant::V256(v) => {
            let mut ctx = Lsh256::new(v);
            ctx.update(data);
            ctx.finalize()
        }
        HashVariant::V512(v) => {
            let mut ctx = Lsh512::new(v);
            ctx.update(data);
            ctx.finalize()
        }
    }
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
