use crate::sha::Sha512_256;

const TESTS: &[(&str, &str, usize)] = &include!("sha512_256_test_vectors.txt");

#[test]
fn regular()
{
  let mut ctx = Sha512_256::new();
  for (md, msg, len) in TESTS {
    let mdb = hex::decode(md).unwrap();
    let msgb = hex::decode(msg).unwrap();
    ctx.update(&msgb);
    let digest = ctx.finish();
    assert_eq!(
      mdb,
      digest,
      "\nlen: {},\nexpected: {},\ngot:      {}",
      len,
      md,
      hex::encode(&digest)
    );
  }
}

#[test]
#[cfg(feature = "alloc")]
fn regular_boxed()
{
  let mut ctx = Sha512_256::new_boxed();
  for (md, msg, len) in TESTS {
    let mdb = hex::decode(md).unwrap();
    let msgb = hex::decode(msg).unwrap();
    ctx.update(&msgb);
    let digest = ctx.finish_boxed();
    assert_eq!(
      mdb,
      digest.as_ref(),
      "\nlen: {},\nexpected: {},\ngot:      {}",
      len,
      md,
      hex::encode(&digest)
    );
  }
}

#[test]
fn chunks()
{
  let mut ctx = Sha512_256::new();
  let (md, msg, len) = TESTS.last().unwrap();
  for i in 1 .. 128 {
    let mdb = hex::decode(md).unwrap();
    let msgb = hex::decode(msg).unwrap();
    msgb.chunks(i).for_each(|data| ctx.update(data));
    let digest = ctx.finish();
    assert_eq!(
      mdb,
      digest,
      "\nlen: {},\nexpected: {},\ngot:      {}",
      len,
      md,
      hex::encode(&digest)
    );
  }
}

#[test]
#[cfg(feature = "alloc")]
fn irregular_len()
{
  use alloc::vec;
  use core::cmp;
  let mut ctx = Sha512_256::new();
  for i in 0 .. 34 {
    let mut digest = vec![0; i];
    let (md, msg, len) = TESTS.last().unwrap();
    let mdb = hex::decode(md).unwrap();
    let msgb = hex::decode(msg).unwrap();
    ctx.update(&msgb);
    ctx.finish_into(&mut digest);
    assert_eq!(
      mdb[.. cmp::min(32, i)],
      digest[.. cmp::min(32, i)],
      "\nlen: {},\nexpected: {},\ngot:      {}",
      len,
      md,
      hex::encode(&digest)
    );
  }
}
