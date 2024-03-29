use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use oxicrypt_test_vectors::Aes;
use oxicrypt_test_vectors::AesVectors;

const VECTORS_LEN: u32 = 128;

fn main()
{
    let outpath = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-vectors");

    let mut buffer = [0; 2048];

    let mut aes128 = File::create(outpath.join("aes128.bin")).unwrap();
    aes128.write_all(&VECTORS_LEN.to_be_bytes()).unwrap();
    for _ in 0..VECTORS_LEN {
        let mut vectors = Box::new(AesVectors::<{ Aes::Aes128 }>::default());
        vectors.set_random();
        let n = vectors.write_to_bytes(&mut buffer);
        aes128.write_all(&buffer[0..n]).unwrap();
    }

    let mut aes192 = File::create(outpath.join("aes192.bin")).unwrap();
    aes192.write_all(&VECTORS_LEN.to_be_bytes()).unwrap();
    for _ in 0..VECTORS_LEN {
        let mut vectors = Box::new(AesVectors::<{ Aes::Aes192 }>::default());
        vectors.set_random();
        let n = vectors.write_to_bytes(&mut buffer);
        aes192.write_all(&buffer[0..n]).unwrap();
    }

    let mut aes256 = File::create(outpath.join("aes256.bin")).unwrap();
    aes256.write_all(&VECTORS_LEN.to_be_bytes()).unwrap();
    for _ in 0..VECTORS_LEN {
        let mut vectors = Box::new(AesVectors::<{ Aes::Aes256 }>::default());
        vectors.set_random();
        let n = vectors.write_to_bytes(&mut buffer);
        aes256.write_all(&buffer[0..n]).unwrap();
    }
}
