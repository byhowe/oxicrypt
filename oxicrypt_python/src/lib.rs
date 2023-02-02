use ::oxicrypt::digest::FinishInternal;
use ::oxicrypt::digest::Update;
use ::oxicrypt::md5::Md5;
use ::oxicrypt::sha::Sha1;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
mod aes_arm_aes;
mod aes_lut;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod aes_x86_aesni;
mod digest_compress;

/// Version of the library.
#[pyfunction]
fn version() -> &'static str
{
  env!("CARGO_PKG_VERSION")
}

#[pyfunction]
fn sha1_oneshot(py: Python, data: &PyBytes) -> PyObject
{
  let mut ctx = Sha1::default();
  ctx.update(data.as_bytes());
  PyBytes::new(py, ctx.finish_internal()).into()
}

#[pyfunction]
fn md5_oneshot(py: Python, data: &PyBytes) -> PyObject
{
  let mut ctx = Md5::default();
  ctx.update(data.as_bytes());
  PyBytes::new(py, ctx.finish_internal()).into()
}

/// A Python module implemented in Rust.
#[pymodule]
fn oxicrypt(py: Python, m: &PyModule) -> PyResult<()>
{
  m.add_function(wrap_pyfunction!(version, m)?)?;

  // register the core library
  let core = PyModule::new(py, "core")?;
  aes_lut::register(py, core)?;
  #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
  aes_x86_aesni::register(py, core)?;
  #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
  aes_arm_aes::register(py, core)?;

  digest_compress::register(py, core)?;
  m.add_submodule(core)?;

  m.add_function(wrap_pyfunction!(sha1_oneshot, m)?)?;
  m.add_function(wrap_pyfunction!(md5_oneshot, m)?)?;

  Ok(())
}
