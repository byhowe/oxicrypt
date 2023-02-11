use std::env;
use std::fs;
use std::path::PathBuf;

fn export_test_vector_paths()
{
    let manifest_path: PathBuf = env::var("CARGO_MANIFEST_DIR").unwrap().parse().unwrap();
    let test_vectors = manifest_path.join("test-vectors");
    let cavp = test_vectors.join("cavp");
    for entry in fs::read_dir(&test_vectors).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            continue;
        }
        println!(
            "cargo:rustc-env=OXI_TEST_{}={}",
            entry.path().file_name().unwrap().to_str().unwrap(),
            entry.path().display()
        );
    }
    for entry in fs::read_dir(&cavp).unwrap() {
        let entry = entry.unwrap();
        println!(
            "cargo:rustc-env=OXI_CAVP_{}={}",
            entry.path().file_name().unwrap().to_str().unwrap(),
            entry.path().display()
        );
    }
}

fn main() { export_test_vector_paths(); }
