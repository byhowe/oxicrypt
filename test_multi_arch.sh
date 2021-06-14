#!/bin/sh

# Run tests for platforms other than the current one.
# Only tested on linux.

cargo test --package oxicrypt-core --target x86_64-unknown-linux-gnu
cargo test --package oxicrypt-core --target x86_64-unknown-linux-gnu --release

cargo test --package oxicrypt-core --target i686-unknown-linux-gnu
cargo test --package oxicrypt-core --target i686-unknown-linux-gnu --release

cargo test --package oxicrypt-core --target x86_64-pc-windows-gnu
cargo test --package oxicrypt-core --target x86_64-pc-windows-gnu --release

cargo test --package oxicrypt-core --target i686-pc-windows-gnu
cargo test --package oxicrypt-core --target i686-pc-windows-gnu --release
