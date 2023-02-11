use pyo3::prelude::*;
use pyo3::types::PyByteArray;
use pyo3::types::PyBytes;
use oxicrypt_core::aes_arm;

#[pyfunction]
unsafe fn aes128_encrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes128_encrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes128_encrypt2(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes128_encrypt2(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes128_encrypt4(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes128_encrypt4(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes128_encrypt8(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes128_encrypt8(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes192_encrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes192_encrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes192_encrypt2(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes192_encrypt2(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes192_encrypt4(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes192_encrypt4(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes192_encrypt8(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes192_encrypt8(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes256_encrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes256_encrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes256_encrypt2(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes256_encrypt2(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes256_encrypt4(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes256_encrypt4(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes256_encrypt8(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes256_encrypt8(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}

#[pyfunction]
unsafe fn aes128_decrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes128_decrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes128_decrypt2(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes128_decrypt2(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes128_decrypt4(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes128_decrypt4(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes128_decrypt8(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes128_decrypt8(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes192_decrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes192_decrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes192_decrypt2(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes192_decrypt2(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes192_decrypt4(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes192_decrypt4(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes192_decrypt8(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes192_decrypt8(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes256_decrypt1(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes256_decrypt1(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes256_decrypt2(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes256_decrypt2(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes256_decrypt4(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes256_decrypt4(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}
#[pyfunction]
unsafe fn aes256_decrypt8(block: &PyByteArray, key_schedule: &PyBytes)
{
    aes_arm::aes256_decrypt8(
        block.as_bytes_mut().as_mut_ptr(),
        key_schedule.as_bytes().as_ptr(),
    )
}

#[inline(always)]
pub fn register(py: Python, m_core: &PyModule) -> PyResult<()>
{
    let m = PyModule::new(py, "aes_arm")?;

    // AES-128
    m.add_function(wrap_pyfunction!(aes128_encrypt1, m)?)?;
    m.add_function(wrap_pyfunction!(aes128_encrypt2, m)?)?;
    m.add_function(wrap_pyfunction!(aes128_encrypt4, m)?)?;
    m.add_function(wrap_pyfunction!(aes128_encrypt8, m)?)?;

    m.add_function(wrap_pyfunction!(aes128_decrypt1, m)?)?;
    m.add_function(wrap_pyfunction!(aes128_decrypt2, m)?)?;
    m.add_function(wrap_pyfunction!(aes128_decrypt4, m)?)?;
    m.add_function(wrap_pyfunction!(aes128_decrypt8, m)?)?;

    // AES-192
    m.add_function(wrap_pyfunction!(aes192_encrypt1, m)?)?;
    m.add_function(wrap_pyfunction!(aes192_encrypt2, m)?)?;
    m.add_function(wrap_pyfunction!(aes192_encrypt4, m)?)?;
    m.add_function(wrap_pyfunction!(aes192_encrypt8, m)?)?;

    m.add_function(wrap_pyfunction!(aes192_decrypt1, m)?)?;
    m.add_function(wrap_pyfunction!(aes192_decrypt2, m)?)?;
    m.add_function(wrap_pyfunction!(aes192_decrypt4, m)?)?;
    m.add_function(wrap_pyfunction!(aes192_decrypt8, m)?)?;

    // AES-256
    m.add_function(wrap_pyfunction!(aes256_encrypt1, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_encrypt2, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_encrypt4, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_encrypt8, m)?)?;

    m.add_function(wrap_pyfunction!(aes256_decrypt1, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_decrypt2, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_decrypt4, m)?)?;
    m.add_function(wrap_pyfunction!(aes256_decrypt8, m)?)?;

    m_core.add_submodule(m)?;

    Ok(())
}
