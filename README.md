# OxiCrypt

A cryptography library that is mainly implemented in Rust. I aim to implement bindings to other languages such as C/C++ and Python. This project is just to learn more about cryptographic algorithms and experimenting with FFI. I don't know much about cryptography, so if you want to use a cryptography library you should use other libraries that are well-tested and written by people who know their stuff.

## Structure of this library

This library contains one crate: `oxicrypt`. `oxicrypt` is the core of this library. It implements and exposes primitive cryptography functions. It also exposes a higher level API for Rust applications. This library also supports FFI through exposing a C API that many other languages can understand as well. The C API is built using `meson`, which will enable the `c` cfg flag during compilation to activate parts of the library that implements the C interface. There is also a Python API in the works, but it is not yet available.

## Instsallation

### Rust

Put the following in your Cargo.toml.
```
oxicrypt = { version = "0.1", git = "https://github.com/byhowe/oxicrypt.git" }
```

### C/C++

Run the following commands to install the headers, a static library and a shared library.
```
$ meson --prefix /usr --buildtype release --default-library both target
$ meson install -C target
```

### Python

WIP

## Issues

This crate uses a lot of nightly features, thus is prone to breakages. As of writing this (2021-07-07), the crate will not compile using the latest nightly compiler (`nightly-2021-07-06`). `nightly-2021-07-01` is known to work. To install it simply run `rustup toolchain install nightly-2021-07-01` and use `cargo +nightly-2021-07-01` instead of `cargo`.
