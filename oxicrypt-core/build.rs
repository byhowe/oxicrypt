use std::path::PathBuf;
use std::env;

fn main()
{
  let manifest_path: PathBuf = env::var("CARGO_MANIFEST_DIR").unwrap().parse().unwrap();
  let test_vectors = manifest_path.parent().unwrap().join("test-vectors");
  println!(
    "cargo:rustc-env=OXICRYPT_TEST_VECS={}{}",
    test_vectors.display(),
    std::path::MAIN_SEPARATOR
  );
}
