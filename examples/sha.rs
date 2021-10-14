use oxicrypt::digest::Digest;
use oxicrypt::sha::Implementation;
use oxicrypt::sha::Sha256;

fn main()
{
  let mut ctx = Sha256::<{ Implementation::Generic }>::new();
  ctx.update(b"Hello, World!");
  let d = ctx.finish();
  println!(" d = {:?}", d);
  ctx.reset();
  ctx.update(b"Hei, Werden!");
  let dd = ctx.finish();
  println!("dd = {:?}", dd);
}
