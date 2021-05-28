use crate::sha::Sha1;

const TESTS: &[(&str, &str, usize)] = &include!("sha1_test_vectors.txt");

#[test]
fn regular()
{
  let mut ctx = Sha1::new();
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
fn regular_boxed()
{
  let mut ctx = Sha1::new_boxed();
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
  let mut ctx = Sha1::new();
  let (md, msg, len) = TESTS.last().unwrap();
  for i in 1 .. 64 {
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
fn irregular_len()
{
  let mut ctx = Sha1::new();
  for i in 0 .. 22 {
    let mut digest = vec![0; i];
    let (md, msg, len) = TESTS.last().unwrap();
    let mdb = hex::decode(md).unwrap();
    let msgb = hex::decode(msg).unwrap();
    ctx.update(&msgb);
    ctx.finish_into(&mut digest);
    assert_eq!(
      mdb[.. std::cmp::min(20, i)],
      digest[.. std::cmp::min(20, i)],
      "\nlen: {},\nexpected: {},\ngot:      {}",
      len,
      md,
      hex::encode(&digest)
    );
  }
}
