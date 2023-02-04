use criterion::black_box;
use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;
use oxicrypt::aes::Key128;
use oxicrypt_core::*;

#[rustfmt::skip]
const K: [u8; 32] = [33, 152, 222, 107, 113, 149, 196, 10, 65, 100, 219, 106, 231, 142, 24, 242, 77, 107, 85, 175, 174, 39, 244, 198, 78, 178, 180, 125, 153, 225, 65, 254];
#[rustfmt::skip]
const B: [u8; 16*8] = [219, 22, 130, 140, 0, 172, 123, 93, 123, 136, 44, 123, 135, 208, 179, 16, 94, 210, 176, 98, 168, 145, 181, 13, 215, 24, 118, 22, 116, 21, 115, 108, 151, 88, 76, 199, 204, 206, 6, 199, 144, 22, 203, 170, 116, 197, 144, 218, 38, 58, 95, 150, 93, 147, 4, 61, 166, 247, 220, 0, 139, 203, 57, 127, 85, 199, 85, 196, 141, 108, 60, 187, 182, 116, 72, 255, 147, 51, 29, 186, 198, 116, 202, 71, 176, 32, 121, 149, 169, 62, 239, 193, 171, 89, 11, 249, 237, 18, 123, 31, 197, 148, 91, 166, 220, 93, 87, 98, 111, 16, 196, 170, 58, 195, 156, 106, 176, 225, 157, 187, 182, 238, 127, 229, 109, 112, 146, 100];

pub fn criterion_benchmark(c: &mut Criterion)
{
    let keysched = Key128::with_encrypt_key(&K[0..16]).unwrap();
    let mut block = B;

    let mut group = c.benchmark_group("aes 128");
    group.bench_function("aes 128 1", |b| {
        b.iter(|| unsafe {
            aes_x86_aesni_aes128_encrypt1(
                black_box(block.as_mut_ptr().add(0 * 16)),
                black_box(keysched.as_ptr()),
            );
            aes_x86_aesni_aes128_encrypt1(
                black_box(block.as_mut_ptr().add(1 * 16)),
                black_box(keysched.as_ptr()),
            );
            aes_x86_aesni_aes128_encrypt1(
                black_box(block.as_mut_ptr().add(2 * 16)),
                black_box(keysched.as_ptr()),
            );
            aes_x86_aesni_aes128_encrypt1(
                black_box(block.as_mut_ptr().add(3 * 16)),
                black_box(keysched.as_ptr()),
            );
            aes_x86_aesni_aes128_encrypt1(
                black_box(block.as_mut_ptr().add(4 * 16)),
                black_box(keysched.as_ptr()),
            );
            aes_x86_aesni_aes128_encrypt1(
                black_box(block.as_mut_ptr().add(5 * 16)),
                black_box(keysched.as_ptr()),
            );
            aes_x86_aesni_aes128_encrypt1(
                black_box(block.as_mut_ptr().add(6 * 16)),
                black_box(keysched.as_ptr()),
            );
            aes_x86_aesni_aes128_encrypt1(
                black_box(block.as_mut_ptr().add(7 * 16)),
                black_box(keysched.as_ptr()),
            );
        })
    });

    let mut block = B;
    group.bench_function("aes 128 8", |b| {
        b.iter(|| unsafe {
            aes_x86_aesni_aes128_encrypt8(
                black_box(block.as_mut_ptr()),
                black_box(keysched.as_ptr()),
            )
        })
    });
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
