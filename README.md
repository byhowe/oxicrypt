# OxiCrypt

This is one of my abandoned projects. I started this when Rust didn't have the
features I wanted in my library. However, it does seem to me that they added
really coold features which I would like to try. I will get around to working
on this library eventually. But please, **DO NOT USE THIS LIBRARY FOR SERIOUS
THINGS**. It is just a hobby project.

---

A cryptography library that is mainly implemented in Rust. I aim to implement
bindings to other languages such as C/C++ and Python. This project is just to
learn more about cryptographic algorithms and experimenting with FFI. I don't
know much about cryptography, so if you want to use a cryptography library you
should use other libraries that are well-tested and written by people who know
their stuff.

## Structure of this library

This library contains the following crates:

* `oxicrypt` includes the source files for the Rust API. It implements the high
  level API.
* `oxicrypt_c` is the C/C++ API. The C API is built using `meson`, which enables
  the `c` feature during compilation to activate parts of the library that
  implement the C interface.
* `oxicrypt_core` is the crate the implements the low level functions. Things
  like the compression functions for the digest algorithms or the raw AES
  functions for different kinds of architectures as well as generic
  implementations are handled by this library. You need not interface with this
  library directly unless you need low level access.
* `oxicrypt_python` implements the FFI between Rust and Python. The crate
  exposes the FFI module with the help of PyO3. The Python module imports the
  FFI crate and implements a higher level API for Python.
* `oxicrypt_test` includes test vectors for the algorithms. This crate is only
  used when in development mode.

## Installation

### Rust

Put the following in your Cargo.toml.
```
oxicrypt = { version = "0.1", git = "https://github.com/byhowe/oxicrypt.git" }
```

### C/C++

Run the following commands to install the headers, a static library and a shared
library.

```
$ meson --prefix /usr --buildtype release --default-library both target
$ meson install -C target
```

### Python

Currently, the Python API does not expose much. That being said, much of the
functionality of OxiCrypt will be included. The current Python module can be
installed with the following command.

``` sh
$ cd oxicrypt_python
$ maturin build
$ pip install ../target/wheels/oxicrypt-0.1.0-cp310-cp310-manylinux_2_34_x86_64.whl
```

Maturin will generate a wheel file that is usually located under the target
directory. Based on the output of Maturin, change the path to the wheel file
accordingly.
