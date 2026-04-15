fn main() {
    // Compile the C implementation of the SRTP KDF (RFC 3711 §4.3.1)
    // for the key_derivation benchmark. Uses libsrtp2's internal cipher
    // abstraction (copy-pasted from srtp.c).

    // finding the srtp2-sys crate source for libsrtp2 headers
    let srtp2_sys = std::path::PathBuf::from(
        std::env::var("CARGO_HOME")
            .unwrap_or_else(|_| format!("{}/.cargo", std::env::var("HOME").unwrap())),
    );

    // finding the exact srtp2-sys directory
    let registry_src = srtp2_sys.join("registry/src/index.crates.io-1949cf8c6b5b557f");
    let srtp2_dir = std::fs::read_dir(&registry_src)
        .expect("failed to read cargo registry")
        .filter_map(|e| e.ok())
        .find(|e| e.file_name().to_string_lossy().starts_with("srtp2-sys-"))
        .expect("srtp2-sys not found in cargo registry")
        .path();

    let libsrtp_dir = srtp2_dir.join("libsrtp");

    // finding the generated config.h from the srtp2-sys build
    let out_dir = std::env::var("OUT_DIR").unwrap();
    // config.h is in target/{profile}/build/srtp2-sys-{hash}/out/crypto/include/
    let target_dir = std::path::Path::new(&out_dir)
        .ancestors()
        .find(|p| p.file_name().map(|f| f == "build").unwrap_or(false))
        .expect("could not find build dir");
    let srtp2_out = std::fs::read_dir(target_dir)
        .expect("failed to read build dir")
        .filter_map(|e| e.ok())
        .find(|e| e.file_name().to_string_lossy().starts_with("srtp2-sys-"))
        .expect("srtp2-sys build output not found")
        .path()
        .join("out");

    let openssl = pkg_config::probe_library("openssl")
        .expect("failed to find OpenSSL via pkg-config");

    let mut build = cc::Build::new();
    build.file("benches/c/srtp_kdf.c");

    // libsrtp2 internal headers
    build.include(libsrtp_dir.join("crypto/include"));
    build.include(libsrtp_dir.join("include"));

    // generated config.h
    build.include(srtp2_out.join("crypto/include"));

    // OpenSSL headers (needed by libsrtp2's cipher backends)
    for path in &openssl.include_paths {
        build.include(path);
    }

    // OPENSSL is defined when libsrtp2 is built with --enable-openssl
    build.define("HAVE_CONFIG_H", None);
    build.define("OPENSSL", None);

    build.compile("srtp_kdf");
}
