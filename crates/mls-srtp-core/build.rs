fn main() {
    // Compile the C implementation of the SRTP KDF (RFC 3711 §4.3.1)
    // for the key_derivation benchmark. Uses libsrtp2's internal cipher
    // abstraction (copy-pasted from srtp.c).

    // libsrtp2 headers from the vendored srtp2-sys copy
    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let libsrtp_dir = manifest_dir.join("../../vendor/srtp2-sys/libsrtp");

    // generated config.h location, exported by the srtp2-sys build script
    let srtp2_include = std::env::var("DEP_SRTP2_INCLUDE")
        .expect("DEP_SRTP2_INCLUDE not set; srtp2-sys build script should export it");

    let openssl = pkg_config::probe_library("openssl")
        .expect("failed to find OpenSSL via pkg-config");

    let mut build = cc::Build::new();
    build.file("benches/c/srtp_kdf.c");

    // libsrtp2 internal headers
    build.include(libsrtp_dir.join("crypto/include"));
    build.include(libsrtp_dir.join("include"));

    // generated config.h
    build.include(&srtp2_include);

    // OpenSSL headers (needed by libsrtp2's cipher backends)
    for path in &openssl.include_paths {
        build.include(path);
    }

    // OPENSSL is defined when libsrtp2 is built with --enable-openssl
    build.define("HAVE_CONFIG_H", None);
    build.define("OPENSSL", None);

    build.compile("srtp_kdf");
}
