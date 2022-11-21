use std::{env, fs, path::PathBuf};

fn export_test_vector_paths() {
    let test_vectors = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-vectors");
    for entry in fs::read_dir(test_vectors).unwrap() {
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
}

fn main() {
    if cfg!(feature = "generate") {
        cc::Build::new()
            .file("src/aesni-intel.c")
            .flag("-maes")
            .flag("-msse2")
            .warnings(false)
            .compile("aesni-intel");

        println!("cargo:rerun-if-changed=src/aesni-intel.h");
        println!("cargo:rerun-if-changed=src/aesni-intel.c");
        let bindings = bindgen::builder()
            .header("src/aesni-intel.h")
            .derive_default(true)
            .generate()
            .expect("Failed to generate bindings from `aesni-intel.h`");
        let outpath = PathBuf::from(env::var("OUT_DIR").unwrap());
        bindings
            .write_to_file(outpath.join("aesni_intel_bindings.rs"))
            .expect("Failed to write to `aesni_intel_bindings.rs`");
    }

    export_test_vector_paths();
}
