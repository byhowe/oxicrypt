use ::oxicrypt::digest::DigestMeta;
use ::oxicrypt::digest::FinishInternal;
use ::oxicrypt::digest::OneshotToSlice;
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
fn sha1_oneshot<'py>(py: Python<'py>, data: &PyBytes) -> PyResult<&'py PyBytes>
{
  PyBytes::new_with(py, Sha1::DIGEST_LEN, |buf: &mut [u8]| {
    Sha1::oneshot_to_slice(data.as_bytes(), buf);
    Ok(())
  })
}

#[pyfunction]
fn md5_oneshot<'py>(py: Python<'py>, data: &PyBytes) -> PyResult<&'py PyBytes>
{
  PyBytes::new_with(py, Md5::DIGEST_LEN, |buf: &mut [u8]| {
    Md5::oneshot_to_slice(data.as_bytes(), buf);
    Ok(())
  })
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
