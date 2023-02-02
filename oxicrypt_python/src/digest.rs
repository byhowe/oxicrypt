use oxicrypt::digest::DigestMeta;
use oxicrypt::digest::FinishToSlice;
use oxicrypt::digest::OneshotToSlice;
use oxicrypt::digest::Reset;
use oxicrypt::digest::Update;
use oxicrypt::md5::Md5;
use oxicrypt::sha::Sha1;
use oxicrypt::sha::Sha224;
use oxicrypt::sha::Sha256;
use oxicrypt::sha::Sha384;
use oxicrypt::sha::Sha512;
use oxicrypt::sha::Sha512_224;
use oxicrypt::sha::Sha512_256;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

macro_rules! impl_digest {
  (
    struct $py_struct:ident;
    type Ctx = $ctx:ident;
    const MAGIC: &'static str = $magic:expr;
  ) => {
    #[pyclass(name = $magic)]
    struct $py_struct
    {
      ctx: $ctx,
    }

    #[pymethods]
    impl $py_struct
    {
      #[classattr]
      const BLOCK_LEN: usize = $ctx::BLOCK_LEN;
      #[classattr]
      const DIGEST_LEN: usize = $ctx::DIGEST_LEN;
      #[classattr]
      const MAGIC: &'static str = $magic;

      #[new]
      fn new() -> Self
      {
        Self { ctx: $ctx::new() }
      }

      fn reset(&mut self)
      {
        self.ctx.reset();
      }

      fn update(&mut self, data: &PyBytes)
      {
        self.ctx.update(data.as_bytes());
      }

      fn finish<'py>(&mut self, py: Python<'py>) -> PyResult<&'py PyBytes>
      {
        PyBytes::new_with(py, $ctx::DIGEST_LEN, |buf: &mut [u8]| {
          self.ctx.finish_to_slice(buf);
          Ok(())
        })
      }

      #[staticmethod]
      fn oneshot<'py>(py: Python<'py>, data: &PyBytes) -> PyResult<&'py PyBytes>
      {
        PyBytes::new_with(py, $ctx::DIGEST_LEN, |buf: &mut [u8]| {
          $ctx::oneshot_to_slice(data.as_bytes(), buf);
          Ok(())
        })
      }
    }
  };
}

impl_digest! {
  struct PySha1;
  type Ctx = Sha1;
  const MAGIC: &'static str = "sha1";
}

impl_digest! {
  struct PySha224;
  type Ctx = Sha224;
  const MAGIC: &'static str = "sha224";
}

impl_digest! {
  struct PySha256;
  type Ctx = Sha256;
  const MAGIC: &'static str = "sha256";
}

impl_digest! {
  struct PySha384;
  type Ctx = Sha384;
  const MAGIC: &'static str = "sha384";
}

impl_digest! {
  struct PySha512;
  type Ctx = Sha512;
  const MAGIC: &'static str = "sha512";
}

impl_digest! {
  struct PySha512_224;
  type Ctx = Sha512_224;
  const MAGIC: &'static str = "sha512_224";
}

impl_digest! {
  struct PySha512_256;
  type Ctx = Sha512_256;
  const MAGIC: &'static str = "sha512_256";
}

impl_digest! {
  struct PyMd5;
  type Ctx = Md5;
  const MAGIC: &'static str = "md5";
}

#[inline(always)]
pub fn register(_py: Python, m: &PyModule) -> PyResult<()>
{
  m.add_class::<PySha1>()?;
  m.add_class::<PySha224>()?;
  m.add_class::<PySha256>()?;
  m.add_class::<PySha384>()?;
  m.add_class::<PySha512>()?;
  m.add_class::<PySha512_224>()?;
  m.add_class::<PySha512_256>()?;
  m.add_class::<PyMd5>()?;

  Ok(())
}
