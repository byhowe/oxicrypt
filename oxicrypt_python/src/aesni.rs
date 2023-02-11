use oxicrypt_core::aesni;
use pyo3::prelude::*;
use pyo3::types::PyByteArray;
use pyo3::types::PyBytes;

#[pyfunction]
unsafe fn aes128_encrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes128_encrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes128_encrypt2(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes128_encrypt2(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes128_encrypt4(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes128_encrypt4(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes128_encrypt8(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes128_encrypt8(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes192_encrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes192_encrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes192_encrypt2(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes192_encrypt2(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes192_encrypt4(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes192_encrypt4(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes192_encrypt8(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes192_encrypt8(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes256_encrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes256_encrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes256_encrypt2(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes256_encrypt2(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes256_encrypt4(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes256_encrypt4(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes256_encrypt8(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes256_encrypt8(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}

#[pyfunction]
unsafe fn aes128_decrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes128_decrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes128_decrypt2(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes128_decrypt2(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes128_decrypt4(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes128_decrypt4(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes128_decrypt8(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes128_decrypt8(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes192_decrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes192_decrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes192_decrypt2(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes192_decrypt2(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes192_decrypt4(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes192_decrypt4(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes192_decrypt8(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes192_decrypt8(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes256_decrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes256_decrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes256_decrypt2(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes256_decrypt2(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes256_decrypt4(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes256_decrypt4(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes256_decrypt8(block: &PyByteArray, key_schedule: &PyBytes)
{
    aesni::aes256_decrypt8(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}

#[pyfunction]
unsafe fn aes128_inverse_key(key_schedule: &PyByteArray)
{
    aesni::aes128_inverse_key(key_schedule.as_bytes_mut().as_mut_ptr())
}
#[pyfunction]
unsafe fn aes192_inverse_key(key_schedule: &PyByteArray)
{
    aesni::aes192_inverse_key(key_schedule.as_bytes_mut().as_mut_ptr())
}
#[pyfunction]
unsafe fn aes256_inverse_key(key_schedule: &PyByteArray)
{
    aesni::aes256_inverse_key(key_schedule.as_bytes_mut().as_mut_ptr())
}

#[pyfunction]
unsafe fn aes128_expand_key(key: &PyBytes, key_schedule: &PyByteArray)
{
    aesni::aes128_expand_key(
        key.as_bytes().as_ptr(),
        key_schedule.as_bytes_mut().as_mut_ptr(),
    )
}
#[pyfunction]
unsafe fn aes192_expand_key(key: &PyBytes, key_schedule: &PyByteArray)
{
    aesni::aes192_expand_key(
        key.as_bytes().as_ptr(),
        key_schedule.as_bytes_mut().as_mut_ptr(),
    )
}
#[pyfunction]
unsafe fn aes256_expand_key(key: &PyBytes, key_schedule: &PyByteArray)
{
    aesni::aes256_expand_key(
        key.as_bytes().as_ptr(),
        key_schedule.as_bytes_mut().as_mut_ptr(),
    )
}

#[inline(always)]
pub fn register(py: Python, m_core: &PyModule) -> PyResult<()>
{
    let m = PyModule::new(py, "aesni")?;

    m.add_function(wrap_pyfunction!(aes128_encrypt1, m)?)?;
    m.add_function(wrap_pyfunction!(aes128_encrypt2, m)?)?;
    m.add_function(wrap_pyfunction!(aes128_encrypt4, m)?)?;
    m.add_function(wrap_pyfunction!(aes128_encrypt8, m)?)?;
    m.add_function(wrap_pyfunction!(aes192_encrypt1, m)?)?;
    m.add_function(wrap_pyfunction!(aes192_encrypt2, m)?)?;
    m.add_function(wrap_pyfunction!(aes192_encrypt4, m)?)?;
    m.add_function(wrap_pyfunction!(aes192_encrypt8, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_encrypt1, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_encrypt2, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_encrypt4, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_encrypt8, m)?)?;

    m.add_function(wrap_pyfunction!(aes128_decrypt1, m)?)?;
    m.add_function(wrap_pyfunction!(aes128_decrypt2, m)?)?;
    m.add_function(wrap_pyfunction!(aes128_decrypt4, m)?)?;
    m.add_function(wrap_pyfunction!(aes128_decrypt8, m)?)?;
    m.add_function(wrap_pyfunction!(aes192_decrypt1, m)?)?;
    m.add_function(wrap_pyfunction!(aes192_decrypt2, m)?)?;
    m.add_function(wrap_pyfunction!(aes192_decrypt4, m)?)?;
    m.add_function(wrap_pyfunction!(aes192_decrypt8, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_decrypt1, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_decrypt2, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_decrypt4, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_decrypt8, m)?)?;

    m.add_function(wrap_pyfunction!(aes128_inverse_key, m)?)?;
    m.add_function(wrap_pyfunction!(aes192_inverse_key, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_inverse_key, m)?)?;

    m.add_function(wrap_pyfunction!(aes128_expand_key, m)?)?;
    m.add_function(wrap_pyfunction!(aes192_expand_key, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_expand_key, m)?)?;

    m_core.add_submodule(m)?;

    Ok(())
}
