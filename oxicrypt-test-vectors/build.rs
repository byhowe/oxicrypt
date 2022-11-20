use std::{env, path::PathBuf};

fn main() {
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
        .generate()
        .expect("Failed to generate bindings from `aesni-intel.h`");
    let outpath = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(outpath.join("aesni_intel_bindings.rs"))
        .expect("Failed to write to `aesni_intel_bindings.rs`");
}
