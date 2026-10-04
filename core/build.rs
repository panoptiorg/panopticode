fn main() {
    // Compile the canonical shared protos (single source of truth in ../proto).
    println!("cargo:rerun-if-changed=../proto/cgf.proto");
    println!("cargo:rerun-if-changed=../proto/summary.proto");
    let mut cfg = prost_build::Config::new();
    cfg.compile_protos(&["../proto/cgf.proto", "../proto/summary.proto"], &["../proto"])
        .expect("compile protos");
}
