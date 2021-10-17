use oxicrypt::digest;
use oxicrypt::sha::Implementation;
use oxicrypt::sha::Sha256;

fn main()
{
  let mut ctx = digest::generic(digest::DigestAlgo::Sha256);
  ctx.update(b"Hello, World!");
  let d = ctx.finish_internal();
  println!(" d = {:?}", d);
  ctx.reset();
  ctx.update(b"Hei, Werden!");
  let dd = ctx.finish_boxed();
  println!("dd = {:?}", dd);
  println!("Block size is {}.", ctx.block_len());
  println!("Digest size is {}.", ctx.digest_len());
}
