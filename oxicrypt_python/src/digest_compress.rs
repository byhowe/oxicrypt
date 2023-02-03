use pyo3::prelude::*;
use pyo3::types::PyByteArray;
use pyo3::types::PyBytes;

#[pyfunction]
pub unsafe fn md5_generic_md5_compress(state: &PyByteArray, block: &PyBytes)
{
    oxicrypt_core::md5_generic_md5_compress(
        state.as_bytes_mut().as_mut_ptr().cast(),
        block.as_bytes().as_ptr().cast(),
    )
}
#[pyfunction]
pub unsafe fn sha_generic_sha1_compress(state: &PyByteArray, block: &PyBytes)
{
    oxicrypt_core::sha_generic_sha1_compress(
        state.as_bytes_mut().as_mut_ptr().cast(),
        block.as_bytes().as_ptr().cast(),
    )
}
#[pyfunction]
pub unsafe fn sha_generic_sha256_compress(state: &PyByteArray, block: &PyBytes)
{
    oxicrypt_core::sha_generic_sha256_compress(
        state.as_bytes_mut().as_mut_ptr().cast(),
        block.as_bytes().as_ptr().cast(),
    )
}
#[pyfunction]
pub unsafe fn sha_generic_sha512_compress(state: &PyByteArray, block: &PyBytes)
{
    oxicrypt_core::sha_generic_sha512_compress(
        state.as_bytes_mut().as_mut_ptr().cast(),
        block.as_bytes().as_ptr().cast(),
    )
}

#[inline(always)]
pub fn register(_py: Python, m: &PyModule) -> PyResult<()>
{
    m.add_function(wrap_pyfunction!(md5_generic_md5_compress, m)?)?;
    m.add_function(wrap_pyfunction!(sha_generic_sha1_compress, m)?)?;
    m.add_function(wrap_pyfunction!(sha_generic_sha256_compress, m)?)?;
    m.add_function(wrap_pyfunction!(sha_generic_sha512_compress, m)?)?;

    Ok(())
}
