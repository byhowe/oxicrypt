use pyo3::prelude::*;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
mod aes_arm_aes;
mod aes_lut;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod aes_x86_aesni;

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
  let core = PyModule::new(py, "core")?;
  aes_lut::register(py, core)?;
  #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
  aes_x86_aesni::register(py, core)?;
  #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
  aes_arm_aes::register(py, core)?;
  m.add_submodule(core)?;

  Ok(())
}
