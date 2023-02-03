use pyo3::prelude::*;
use pyo3::types::PyByteArray;
use pyo3::types::PyBytes;

#[pyfunction]
unsafe fn aes_x86_aesni_aes128_encrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes128_encrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes128_encrypt2(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes128_encrypt2(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes128_encrypt4(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes128_encrypt4(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes128_encrypt8(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes128_encrypt8(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes192_encrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes192_encrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes192_encrypt2(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes192_encrypt2(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes192_encrypt4(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes192_encrypt4(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes192_encrypt8(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes192_encrypt8(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes256_encrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes256_encrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes256_encrypt2(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes256_encrypt2(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes256_encrypt4(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes256_encrypt4(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes256_encrypt8(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes256_encrypt8(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}

#[pyfunction]
unsafe fn aes_x86_aesni_aes128_decrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes128_decrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes128_decrypt2(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes128_decrypt2(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes128_decrypt4(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes128_decrypt4(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes128_decrypt8(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes128_decrypt8(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes192_decrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes192_decrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes192_decrypt2(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes192_decrypt2(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes192_decrypt4(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes192_decrypt4(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes192_decrypt8(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes192_decrypt8(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes256_decrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes256_decrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes256_decrypt2(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes256_decrypt2(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes256_decrypt4(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes256_decrypt4(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes256_decrypt8(block: &PyByteArray, key_schedule: &PyBytes)
{
    oxicrypt_core::aes_x86_aesni_aes256_decrypt8(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}

#[pyfunction]
unsafe fn aes_x86_aesni_aes128_inverse_key(key_schedule: &PyByteArray)
{
    oxicrypt_core::aes_x86_aesni_aes128_inverse_key(key_schedule.as_bytes_mut().as_mut_ptr())
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes192_inverse_key(key_schedule: &PyByteArray)
{
    oxicrypt_core::aes_x86_aesni_aes192_inverse_key(key_schedule.as_bytes_mut().as_mut_ptr())
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes256_inverse_key(key_schedule: &PyByteArray)
{
    oxicrypt_core::aes_x86_aesni_aes256_inverse_key(key_schedule.as_bytes_mut().as_mut_ptr())
}

#[pyfunction]
unsafe fn aes_x86_aesni_aes128_expand_key(key: &PyBytes, key_schedule: &PyByteArray)
{
    oxicrypt_core::aes_x86_aesni_aes128_expand_key(
        key.as_bytes().as_ptr(),
        key_schedule.as_bytes_mut().as_mut_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes192_expand_key(key: &PyBytes, key_schedule: &PyByteArray)
{
    oxicrypt_core::aes_x86_aesni_aes192_expand_key(
        key.as_bytes().as_ptr(),
        key_schedule.as_bytes_mut().as_mut_ptr(),
    )
}
#[pyfunction]
unsafe fn aes_x86_aesni_aes256_expand_key(key: &PyBytes, key_schedule: &PyByteArray)
{
    oxicrypt_core::aes_x86_aesni_aes256_expand_key(
        key.as_bytes().as_ptr(),
        key_schedule.as_bytes_mut().as_mut_ptr(),
    )
}

#[inline(always)]
pub fn register(_py: Python, m: &PyModule) -> PyResult<()>
{
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes128_encrypt1, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes128_encrypt2, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes128_encrypt4, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes128_encrypt8, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes192_encrypt1, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes192_encrypt2, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes192_encrypt4, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes192_encrypt8, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes256_encrypt1, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes256_encrypt2, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes256_encrypt4, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes256_encrypt8, m)?)?;

    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes128_decrypt1, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes128_decrypt2, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes128_decrypt4, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes128_decrypt8, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes192_decrypt1, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes192_decrypt2, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes192_decrypt4, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes192_decrypt8, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes256_decrypt1, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes256_decrypt2, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes256_decrypt4, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes256_decrypt8, m)?)?;

    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes128_inverse_key, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes192_inverse_key, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes256_inverse_key, m)?)?;

    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes128_expand_key, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes192_expand_key, m)?)?;
    m.add_function(wrap_pyfunction!(aes_x86_aesni_aes256_expand_key, m)?)?;

    Ok(())
}
