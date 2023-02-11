#![feature(generic_const_exprs)]

use pyo3::prelude::*;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
mod aes_arm;
mod aes_lut;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod aesni;
mod digest;
mod hmac;
mod md_compress;

/// Version of the library.
#[pyfunction]
fn version() -> &'static str { env!("CARGO_PKG_VERSION") }

/// A Python module implemented in Rust.
#[pymodule]
fn oxicrypt(py: Python, m: &PyModule) -> PyResult<()>
{
    m.add_function(wrap_pyfunction!(version, m)?)?;

    // register the core library
    let m_core = PyModule::new(py, "core")?;
    aes_lut::register(py, m_core)?;
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    aesni::register(py, m_core)?;
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    aes_arm::register(py, m_core)?;
    md_compress::register(py, m_core)?;
    m.add_submodule(m_core)?;

    // register the digest library
    let m_digest = PyModule::new(py, "digest")?;
    digest::register(py, m_digest)?;
    m.add_submodule(m_digest)?;

    // register the hmac library
    let m_hmac = PyModule::new(py, "hmac")?;
    hmac::register(py, m_hmac)?;
    m.add_submodule(m_hmac)?;

    Ok(())
}
