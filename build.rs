use std::env;
use std::process::Command;

fn main() {
    let (_cflags, ldflags) = match Command::new("pkg-config")
        .args(["--cflags", "r_core"])
        .output()
    {
        Ok(output) if output.status.success() && !output.stdout.is_empty() => {
            let cflags = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let ldflags_output = Command::new("pkg-config")
                .arg("--libs")
                .arg("r_core")
                .output()
                .expect("failed to run pkg-config --libs r_core");
            let ldflags = String::from_utf8_lossy(&ldflags_output.stdout)
                .trim()
                .to_string();
            (cflags, ldflags)
        }
        _ => {
            let cflags = Command::new("r2")
                .args(["-H", "R2_CFLAGS"])
                .output()
                .expect("failed to run r2 -H R2_CFLAGS");
            let ldflags = Command::new("r2")
                .args(["-H", "R2_LDFLAGS"])
                .output()
                .expect("failed to run r2 -H R2_LDFLAGS");
            (
                String::from_utf8_lossy(&cflags.stdout).trim().to_string(),
                String::from_utf8_lossy(&ldflags.stdout).trim().to_string(),
            )
        }
    };

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

    println!("cargo:rerun-if-changed=build.rs");
}
