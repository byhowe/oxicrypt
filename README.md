# OxiCrypt

A cryptography library that is mainly implemented in Rust. I aim to implement bindings to other languages such as C/C++ and Python. This project is just to learn more about cryptographic algorithms and experimenting with FFI. I don't know much about cryptography, so if you want to use a cryptography library you should use other libraries that are well-tested and written by people who know their stuff.

## Structure of this library

This library contains the following crates:

* `oxicrypt` is the core of this library. It implements and exposes primitive cryptography functions. It also exposes a higher level API for Rust applications.
* `oxicrypt_c` is the C/C++ API. The C API is built using `meson`, which enables the `c` feature during compilation to activate parts of the library that implements the C interface.

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
