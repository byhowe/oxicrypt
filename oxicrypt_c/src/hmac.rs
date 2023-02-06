use alloc::boxed::Box;
use core::slice;

use oxicrypt::digest::*;
use oxicrypt::hmac::*;
use oxicrypt::merkle_damgard::*;

macro_rules! impl_hmac {
    (
        type $ctx:ident;
        fn new = $new:ident;
        fn drop = $drop:ident;
        fn set_key = $set_key:ident;
        fn update = $update:ident;
        fn finish = $finish:ident;
        fn oneshot = $oneshot:ident;
    ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $new(key: *const u8, key_len: usize) -> Box<Hmac<$ctx>>
        {
            let mut ctx = Box::<Hmac<$ctx>>::new_uninit();
            ctx.assume_init_mut()
                .set_key(slice::from_raw_parts(key, key_len));
            ctx.assume_init()
        }

        #[no_mangle]
        pub unsafe extern "C" fn $drop(_ctx: Box<Hmac<$ctx>>) {}

        #[no_mangle]
        pub unsafe extern "C" fn $set_key(ctx: &mut Hmac<$ctx>, key: *const u8, key_len: usize)
        {
            ctx.set_key(slice::from_raw_parts(key, key_len));
        }

        #[no_mangle]
        pub unsafe extern "C" fn $update(ctx: &mut Hmac<$ctx>, data: *const u8, len: usize)
        {
            ctx.update(slice::from_raw_parts(data, len));
        }

        #[no_mangle]
        pub unsafe extern "C" fn $finish(ctx: &mut Hmac<$ctx>) -> *const u8
        {
            ctx.finish_internal().as_ptr()
        }

        #[no_mangle]
        pub unsafe extern "C" fn $oneshot(
            data: *const u8,
            data_len: usize,
            key: *const u8,
            key_len: usize,
            digest: *mut u8,
            digest_len: usize,
        )
        {
            hmac_to_slice::<$ctx>(
                slice::from_raw_parts(data, data_len),
                slice::from_raw_parts(key, key_len),
                slice::from_raw_parts_mut(digest, digest_len),
            );
        }
    };
}

impl_hmac! {
    type Md5;
    fn new = oxi_hmac_md5_new;
    fn drop = oxi_hmac_md5_drop;
    fn set_key = oxi_hmac_md5_set_key;
    fn update = oxi_hmac_md5_update;
    fn finish = oxi_hmac_md5_finish;
    fn oneshot = oxi_hmac_md5_oneshot;
}

impl_hmac! {
    type Sha1;
    fn new = oxi_hmac_sha1_new;
    fn drop = oxi_hmac_sha1_drop;
    fn set_key = oxi_hmac_sha1_set_key;
    fn update = oxi_hmac_sha1_update;
    fn finish = oxi_hmac_sha1_finish;
    fn oneshot = oxi_hmac_sha1_oneshot;
}

impl_hmac! {
    type Sha224;
    fn new = oxi_hmac_sha224_new;
    fn drop = oxi_hmac_sha224_drop;
    fn set_key = oxi_hmac_sha224_set_key;
    fn update = oxi_hmac_sha224_update;
    fn finish = oxi_hmac_sha224_finish;
    fn oneshot = oxi_hmac_sha224_oneshot;
}

impl_hmac! {
    type Sha256;
    fn new = oxi_hmac_sha256_new;
    fn drop = oxi_hmac_sha256_drop;
    fn set_key = oxi_hmac_sha256_set_key;
    fn update = oxi_hmac_sha256_update;
    fn finish = oxi_hmac_sha256_finish;
    fn oneshot = oxi_hmac_sha256_oneshot;
}

impl_hmac! {
    type Sha384;
    fn new = oxi_hmac_sha384_new;
    fn drop = oxi_hmac_sha384_drop;
    fn set_key = oxi_hmac_sha384_set_key;
    fn update = oxi_hmac_sha384_update;
    fn finish = oxi_hmac_sha384_finish;
    fn oneshot = oxi_hmac_sha384_oneshot;
}

impl_hmac! {
    type Sha512;
    fn new = oxi_hmac_sha512_new;
    fn drop = oxi_hmac_sha512_drop;
    fn set_key = oxi_hmac_sha512_set_key;
    fn update = oxi_hmac_sha512_update;
    fn finish = oxi_hmac_sha512_finish;
    fn oneshot = oxi_hmac_sha512_oneshot;
}

impl_hmac! {
    type Sha512_224;
    fn new = oxi_hmac_sha512_224_new;
    fn drop = oxi_hmac_sha512_224_drop;
    fn set_key = oxi_hmac_sha512_224_set_key;
    fn update = oxi_hmac_sha512_224_update;
    fn finish = oxi_hmac_sha512_224_finish;
    fn oneshot = oxi_hmac_sha512_224_oneshot;
}

impl_hmac! {
    type Sha512_256;
    fn new = oxi_hmac_sha512_256_new;
    fn drop = oxi_hmac_sha512_256_drop;
    fn set_key = oxi_hmac_sha512_256_set_key;
    fn update = oxi_hmac_sha512_256_update;
    fn finish = oxi_hmac_sha512_256_finish;
    fn oneshot = oxi_hmac_sha512_256_oneshot;
}
