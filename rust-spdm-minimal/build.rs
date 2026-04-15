fn main() {
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/ffi/");
    
    if std::env::var("CARGO_FEATURE_FFI").is_ok() {
        let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        
        cbindgen::Builder::new()
            .with_crate(&crate_dir)
            .with_language(cbindgen::Language::C)
            .with_header("/* rust-spdm-minimal FFI header */")
            .with_include_guard("RUST_SPDM_MINIMAL_H")
            .generate()
            .expect("Unable to generate bindings")
            .write_to_file("include/rust_spdm.h");
    }
}