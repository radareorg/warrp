use std::path::PathBuf;

fn main() {
    let schemas_dir = PathBuf::from("schemas");

    if schemas_dir.exists() {
        println!("cargo:rerun-if-changed=schemas/");

        for entry in std::fs::read_dir(&schemas_dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "fbs") {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }

    // Add radare2 library search path
    println!("cargo:rustc-link-search=/usr/local/lib");

    // Print cargo directives for linking
    // r_sign is part of r_anal, not a separate library
    println!("cargo:rustc-link-lib=r_core");
    println!("cargo:rustc-link-lib=r_anal");
    println!("cargo:rustc-link-lib=r_io");
    println!("cargo:rustc-link-lib=r_cons");
    println!("cargo:rustc-link-lib=r_util");
}
