use std::path::PathBuf;
use std::env;
use std::fs;

fn main()
{
  let manifest_path: PathBuf = env::var("CARGO_MANIFEST_DIR").unwrap().parse().unwrap();
  let test_vectors = manifest_path.join("test-vectors");
  for entry in fs::read_dir(&test_vectors).unwrap() {
    let entry = entry.unwrap();
    println!(
      "cargo:rustc-env=OXI_TEST_{}={}",
      entry.path().file_name().unwrap().to_str().unwrap(),
      entry.path().display()
    );
  }
}
