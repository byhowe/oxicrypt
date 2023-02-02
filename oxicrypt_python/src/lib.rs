use pyo3::prelude::*;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
mod aes_arm_aes;
mod aes_lut;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod aes_x86_aesni;
mod digest_compress;
mod digest;

/// Version of the library.
#[pyfunction]
fn version() -> &'static str
{
  env!("CARGO_PKG_VERSION")
}

/// A Python module implemented in Rust.
#[pymodule]
fn oxicrypt(py: Python, m: &PyModule) -> PyResult<()>
{
  m.add_function(wrap_pyfunction!(version, m)?)?;

  // register the core library
  let m_core = PyModule::new(py, "core")?;
  aes_lut::register(py, m_core)?;
  #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
  aes_x86_aesni::register(py, m_core)?;
  #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
  aes_arm_aes::register(py, m_core)?;
  digest_compress::register(py, m_core)?;
  m.add_submodule(m_core)?;

  // register the digest library
  let m_digest = PyModule::new(py, "digest")?;
  digest::register(py, m_digest)?;
  m.add_submodule(m_digest)?;

  Ok(())
}
