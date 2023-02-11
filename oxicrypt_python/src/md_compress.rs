use oxicrypt_core::md_compress;
use pyo3::prelude::*;
use pyo3::types::PyByteArray;
use pyo3::types::PyBytes;

#[pyfunction]
pub unsafe fn md5(state: &PyByteArray, block: &PyBytes)
{
    md_compress::md5(
        state.as_bytes_mut().as_mut_ptr().cast(),
        block.as_bytes().as_ptr().cast(),
    )
}
#[pyfunction]
pub unsafe fn sha1(state: &PyByteArray, block: &PyBytes)
{
    md_compress::sha1(
        state.as_bytes_mut().as_mut_ptr().cast(),
        block.as_bytes().as_ptr().cast(),
    )
}
#[pyfunction]
pub unsafe fn sha256(state: &PyByteArray, block: &PyBytes)
{
    md_compress::sha256(
        state.as_bytes_mut().as_mut_ptr().cast(),
        block.as_bytes().as_ptr().cast(),
    )
}
#[pyfunction]
pub unsafe fn sha512(state: &PyByteArray, block: &PyBytes)
{
    md_compress::sha512(
        state.as_bytes_mut().as_mut_ptr().cast(),
        block.as_bytes().as_ptr().cast(),
    )
}

#[inline(always)]
pub fn register(py: Python, m_core: &PyModule) -> PyResult<()>
{
    let m = PyModule::new(py, "md_compress")?;

    m.add_function(wrap_pyfunction!(md5, m)?)?;
    m.add_function(wrap_pyfunction!(sha1, m)?)?;
    m.add_function(wrap_pyfunction!(sha256, m)?)?;
    m.add_function(wrap_pyfunction!(sha512, m)?)?;

    m_core.add_submodule(m)?;

    Ok(())
}
