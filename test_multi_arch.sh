#!/bin/sh

# Run tests for platforms other than the current one.
# Only tested on linux.

export RUSTFLAGS="-C target-cpu=native"

cargo test --package oxicrypt-core --target x86_64-unknown-linux-gnu
cargo test --package oxicrypt-core --target x86_64-unknown-linux-gnu --release

cargo test --package oxicrypt-core --target x86_64-unknown-linux-gnu --features asm
cargo test --package oxicrypt-core --target x86_64-unknown-linux-gnu --release --features asm

cargo test --package oxicrypt-core --target i686-unknown-linux-gnu
cargo test --package oxicrypt-core --target i686-unknown-linux-gnu --release

cargo test --package oxicrypt-core --target i686-unknown-linux-gnu --features asm
cargo test --package oxicrypt-core --target i686-unknown-linux-gnu --release --features asm

cargo test --package oxicrypt-core --target x86_64-pc-windows-gnu
cargo test --package oxicrypt-core --target x86_64-pc-windows-gnu --release

cargo test --package oxicrypt-core --target x86_64-pc-windows-gnu --features asm
cargo test --package oxicrypt-core --target x86_64-pc-windows-gnu --release --features asm

cargo test --package oxicrypt-core --target i686-pc-windows-gnu
cargo test --package oxicrypt-core --target i686-pc-windows-gnu --release

cargo test --package oxicrypt-core --target i686-pc-windows-gnu --features asm
cargo test --package oxicrypt-core --target i686-pc-windows-gnu --release --features asm
