use oxicrypt::digest::*;
use oxicrypt::hmac::*;
use oxicrypt::merkle_damgard::*;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

macro_rules! impl_hmac {
    (
        struct $py_struct:ident;
        type Ctx = $ctx:ident;
        const MAGIC: &'static str = $magic:expr;
    ) => {
        #[pyclass(name = $magic)]
        struct $py_struct
        {
            ctx: Hmac<$ctx>,
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
            fn with_key(key: &PyBytes) -> Self
            {
                Self {
                    ctx: Hmac::<$ctx>::with_key(key.as_bytes()),
                }
            }

            fn set_key(&mut self, key: &PyBytes) { self.ctx.set_key(key.as_bytes()); }

            fn update(&mut self, data: &PyBytes) { self.ctx.update(data.as_bytes()); }

            fn finish<'py>(&mut self, py: Python<'py>) -> PyResult<&'py PyBytes>
            {
                PyBytes::new_with(py, $ctx::DIGEST_LEN, |buf: &mut [u8]| {
                    self.ctx.finish_to_slice(buf);
                    Ok(())
                })
            }

            #[staticmethod]
            fn oneshot<'py>(
                py: Python<'py>,
                data: &PyBytes,
                key: &PyBytes,
            ) -> PyResult<&'py PyBytes>
            {
                PyBytes::new_with(py, $ctx::DIGEST_LEN, |buf: &mut [u8]| {
                    Hmac::<$ctx>::oneshot_to_slice(data.as_bytes(), key.as_bytes(), buf);
                    Ok(())
                })
            }
        }
    };
}

impl_hmac! {
    struct PyHmacSha1;
    type Ctx = Sha1;
    const MAGIC: &'static str = "hmac_sha1";
}

impl_hmac! {
    struct PyHmacSha224;
    type Ctx = Sha224;
    const MAGIC: &'static str = "hmac_sha224";
}

impl_hmac! {
    struct PyHmacSha256;
    type Ctx = Sha256;
    const MAGIC: &'static str = "hmac_sha256";
}

impl_hmac! {
    struct PyHmacSha384;
    type Ctx = Sha384;
    const MAGIC: &'static str = "hmac_sha384";
}

impl_hmac! {
    struct PyHmacSha512;
    type Ctx = Sha512;
    const MAGIC: &'static str = "hmac_sha512";
}

impl_hmac! {
    struct PyHmacSha512_224;
    type Ctx = Sha512_224;
    const MAGIC: &'static str = "hmac_sha512_224";
}

impl_hmac! {
    struct PyHmacSha512_256;
    type Ctx = Sha512_256;
    const MAGIC: &'static str = "hmac_sha512_256";
}

impl_hmac! {
    struct PyHmacMd5;
    type Ctx = Md5;
    const MAGIC: &'static str = "hmac_md5";
}

#[inline(always)]
pub fn register(_py: Python, m: &PyModule) -> PyResult<()>
{
    // hmac digest algorithms
    m.add_class::<PyHmacSha1>()?;
    m.add_class::<PyHmacSha224>()?;
    m.add_class::<PyHmacSha256>()?;
    m.add_class::<PyHmacSha384>()?;
    m.add_class::<PyHmacSha512>()?;
    m.add_class::<PyHmacSha512_224>()?;
    m.add_class::<PyHmacSha512_256>()?;
    m.add_class::<PyHmacMd5>()?;

    Ok(())
}
