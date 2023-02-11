use oxicrypt_core::aes_lut;
use pyo3::prelude::*;
use pyo3::types::PyByteArray;
use pyo3::types::PyBytes;

#[pyfunction]
unsafe fn aes128_encrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_lut::aes128_encrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes192_encrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_lut::aes192_encrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes256_encrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_lut::aes256_encrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}

#[pyfunction]
unsafe fn aes128_decrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_lut::aes128_decrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes192_decrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_lut::aes192_decrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes256_decrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_lut::aes256_decrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}

#[pyfunction]
unsafe fn aes128_inverse_key(key_schedule: &PyByteArray)
{
    aes_lut::aes128_inverse_key(key_schedule.as_bytes_mut().as_mut_ptr())
}
#[pyfunction]
unsafe fn aes192_inverse_key(key_schedule: &PyByteArray)
{
    aes_lut::aes192_inverse_key(key_schedule.as_bytes_mut().as_mut_ptr())
}
#[pyfunction]
unsafe fn aes256_inverse_key(key_schedule: &PyByteArray)
{
    aes_lut::aes256_inverse_key(key_schedule.as_bytes_mut().as_mut_ptr())
}

#[pyfunction]
unsafe fn aes128_expand_key(key: &PyBytes, key_schedule: &PyByteArray)
{
    aes_lut::aes128_expand_key(
        key.as_bytes().as_ptr(),
        key_schedule.as_bytes_mut().as_mut_ptr(),
    )
}
#[pyfunction]
unsafe fn aes192_expand_key(key: &PyBytes, key_schedule: &PyByteArray)
{
    aes_lut::aes192_expand_key(
        key.as_bytes().as_ptr(),
        key_schedule.as_bytes_mut().as_mut_ptr(),
    )
}
#[pyfunction]
unsafe fn aes256_expand_key(key: &PyBytes, key_schedule: &PyByteArray)
{
    aes_lut::aes256_expand_key(
        key.as_bytes().as_ptr(),
        key_schedule.as_bytes_mut().as_mut_ptr(),
    )
}

#[inline(always)]
pub fn register(py: Python, m_core: &PyModule) -> PyResult<()>
{
    let m = PyModule::new(py, "aes_lut")?;

    m.add_function(wrap_pyfunction!(aes128_encrypt1, m)?)?;
    m.add_function(wrap_pyfunction!(aes192_encrypt1, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_encrypt1, m)?)?;

    m.add_function(wrap_pyfunction!(aes128_decrypt1, m)?)?;
    m.add_function(wrap_pyfunction!(aes192_decrypt1, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_decrypt1, m)?)?;

    m.add_function(wrap_pyfunction!(aes128_inverse_key, m)?)?;
    m.add_function(wrap_pyfunction!(aes192_inverse_key, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_inverse_key, m)?)?;

    m.add_function(wrap_pyfunction!(aes128_expand_key, m)?)?;
    m.add_function(wrap_pyfunction!(aes192_expand_key, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_expand_key, m)?)?;

    m_core.add_submodule(m)?;

    Ok(())
}
