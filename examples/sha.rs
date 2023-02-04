use oxicrypt::digest::Digest;
use oxicrypt::digest::DigestMeta;
use oxicrypt::sha::Sha256;

fn main()
{
    let mut ctx = Sha256::new();
    ctx.update(b"Hello, World!");
    let d = ctx.finish_internal();
    println!(" d = {}", hex::encode(d));
    ctx.reset();
    ctx.update(b"Hei, Werden!");
    let dd = ctx.finish_boxed();
    println!("dd = {}", hex::encode(dd));
    println!("Block size is {}.", Sha256::BLOCK_LEN);
    println!("Digest size is {}.", Sha256::DIGEST_LEN);
}
