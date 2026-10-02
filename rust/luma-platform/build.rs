use std::{env, path::PathBuf, process::Command};

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let source = "src/tpm_esys.c";
    println!("cargo:rerun-if-changed={source}");
    // Only a fixed-width ABI shim. Policy, journal, identity and state machines
    // remain in Rust; the distribution's TSS implements the TPM protocol.
    assert!(Command::new("cc")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fPIC", "-c", source, "-o"])
        .arg(out.join("tpm_esys.o"))
        .status()
        .expect("C compiler")
        .success());
    assert!(Command::new("ar")
        .arg("crs")
        .arg(out.join("libluma_tpm.a"))
        .arg(out.join("tpm_esys.o"))
        .status()
        .expect("archiver")
        .success());
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=luma_tpm");
    println!("cargo:rustc-link-lib=tss2-esys");
    println!("cargo:rustc-link-lib=tss2-mu");
    println!("cargo:rustc-link-lib=tss2-tctildr");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rerun-if-changed=src/auth_pam.c");
    assert!(Command::new("cc")
        .args([
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "src/auth_pam.c",
            "-lpam",
            "-o"
        ])
        .arg(out.join("luma-auth-helper"))
        .status()
        .expect("PAM helper compiler")
        .success());
}
