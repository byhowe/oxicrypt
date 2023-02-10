use alloc::boxed::Box;
use core::slice;

use oxicrypt::digest::*;
use oxicrypt::merkle_damgard::*;

macro_rules! impl_digest {
    (
        type $ctx:ident;
        fn new = $new:ident;
        fn drop = $drop:ident;
        fn reset = $reset:ident;
        fn update = $update:ident;
        fn finish = $finish:ident;
        fn oneshot = $oneshot:ident;
    ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $new() -> Box<$ctx>
        {
            let mut ctx = Box::<$ctx>::new_uninit();
            ctx.assume_init_mut().reset();
            ctx.assume_init()
        }

        #[no_mangle]
        pub unsafe extern "C" fn $drop(_ctx: Option<Box<$ctx>>) {}

        #[no_mangle]
        pub unsafe extern "C" fn $reset(ctx: &mut $ctx) { ctx.reset(); }

        #[no_mangle]
        pub unsafe extern "C" fn $update(ctx: &mut $ctx, data: *const u8, len: usize)
        {
            ctx.update(slice::from_raw_parts(data, len));
        }

        #[no_mangle]
        pub unsafe extern "C" fn $finish(ctx: &mut $ctx) -> *const u8
        {
            ctx.finish_internal().as_ptr()
        }

        #[no_mangle]
        pub unsafe extern "C" fn $oneshot(
            data: *const u8,
            data_len: usize,
            digest: *mut u8,
            digest_len: usize,
        )
        {
            $ctx::oneshot_to_slice(
                slice::from_raw_parts(data, data_len),
                slice::from_raw_parts_mut(digest, digest_len),
            );
        }
    };
}

impl_digest! {
    type Md5;
    fn new = oxi_digest_md5_new;
    fn drop = oxi_digest_md5_drop;
    fn reset = oxi_digest_md5_reset;
    fn update = oxi_digest_md5_update;
    fn finish = oxi_digest_md5_finish;
    fn oneshot = oxi_digest_md5_oneshot;
}

impl_digest! {
    type Sha1;
    fn new = oxi_digest_sha1_new;
    fn drop = oxi_digest_sha1_drop;
    fn reset = oxi_digest_sha1_reset;
    fn update = oxi_digest_sha1_update;
    fn finish = oxi_digest_sha1_finish;
    fn oneshot = oxi_digest_sha1_oneshot;
}

impl_digest! {
    type Sha224;
    fn new = oxi_digest_sha224_new;
    fn drop = oxi_digest_sha224_drop;
    fn reset = oxi_digest_sha224_reset;
    fn update = oxi_digest_sha224_update;
    fn finish = oxi_digest_sha224_finish;
    fn oneshot = oxi_digest_sha224_oneshot;
}

impl_digest! {
    type Sha256;
    fn new = oxi_digest_sha256_new;
    fn drop = oxi_digest_sha256_drop;
    fn reset = oxi_digest_sha256_reset;
    fn update = oxi_digest_sha256_update;
    fn finish = oxi_digest_sha256_finish;
    fn oneshot = oxi_digest_sha256_oneshot;
}

impl_digest! {
    type Sha384;
    fn new = oxi_digest_sha384_new;
    fn drop = oxi_digest_sha384_drop;
    fn reset = oxi_digest_sha384_reset;
    fn update = oxi_digest_sha384_update;
    fn finish = oxi_digest_sha384_finish;
    fn oneshot = oxi_digest_sha384_oneshot;
}

impl_digest! {
    type Sha512;
    fn new = oxi_digest_sha512_new;
    fn drop = oxi_digest_sha512_drop;
    fn reset = oxi_digest_sha512_reset;
    fn update = oxi_digest_sha512_update;
    fn finish = oxi_digest_sha512_finish;
    fn oneshot = oxi_digest_sha512_oneshot;
}

impl_digest! {
    type Sha512_224;
    fn new = oxi_digest_sha512_224_new;
    fn drop = oxi_digest_sha512_224_drop;
    fn reset = oxi_digest_sha512_224_reset;
    fn update = oxi_digest_sha512_224_update;
    fn finish = oxi_digest_sha512_224_finish;
    fn oneshot = oxi_digest_sha512_224_oneshot;
}

impl_digest! {
    type Sha512_256;
    fn new = oxi_digest_sha512_256_new;
    fn drop = oxi_digest_sha512_256_drop;
    fn reset = oxi_digest_sha512_256_reset;
    fn update = oxi_digest_sha512_256_update;
    fn finish = oxi_digest_sha512_256_finish;
    fn oneshot = oxi_digest_sha512_256_oneshot;
}
