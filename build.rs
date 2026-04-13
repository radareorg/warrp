use std::env;
use std::process::Command;

fn r2_env(key: &str) -> String {
    String::from_utf8_lossy(
        &Command::new("radare2")
            .args(["-H", key])
            .output()
            .unwrap_or_else(|_| panic!("failed to run radare2 -H {key}"))
            .stdout,
    )
    .trim()
    .to_string()
}

fn main() {
    let ldflags = r2_env("R2_LDFLAGS");

    for flag in ldflags.split_whitespace() {
        if let Some(path) = flag.strip_prefix("-L") {
            println!("cargo:rustc-link-search={path}");
        } else if let Some(lib) = flag.strip_prefix("-l") {
            println!("cargo:rustc-link-lib={lib}");
        }
    }

    if env::var("TARGET").unwrap_or_default().contains("windows") {
        println!("cargo:rustc-link-lib=shlwapi");
    }

    let r2_version = r2_env("R2_VERSION");
    let r2_abiversion: u32 = r2_env("R2_ABIVERSION")
        .parse()
        .expect("R2_ABIVERSION is not a valid u32");

    println!("cargo:rustc-env=R2_VERSION={r2_version}");
    println!("cargo:rustc-env=R2_ABIVERSION={r2_abiversion}");

    println!("cargo:rerun-if-changed=build.rs");
}
