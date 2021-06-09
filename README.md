# OxiCrypt

A cryptography library that is mainly implemented in Rust. I aim to implement bindings to other languages such as C/C++ and Python. This project is just to learn more about cryptographic algorithms and experimenting with FFI. I don't know much about cryptography, so if you want to use a cryptography library you should use other libraries that are well-tested and written by people who know their stuff.

## Structure of this library

This library is divided up into 3 crates:
* `oxicrypt-core`
* `oxicrypt-sys`
* `oxicrypt`

`oxicrypt-core` is the main crate that implements the cryptographic functions that other crates use to build a usable API. For example, `oxicrypt-core` implements the compression functions for the SHA algorithms that work on a single block, while the `oxicrypt` crate implements the user-level API that deals with things like updating the inner state and padding. `oxicrypt` is the main library that regular Rust users should use. It exposes an API that is (I hope) safe. `oxicrypt-sys` is similar to `oxicrypt`, but it exposes an API that C/C++ users should use. It is not as safe as the Rust API. In most cases users should check that the arguments they apply to functions are valid. There is also a Python API in the works, but it is not yet available.

It should be noted, however, that this library is still in works and the API will not be finilized until much later.
