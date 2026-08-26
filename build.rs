fn main() {
    // Compile the C implementation of the SRTP KDF (RFC 3711 §4.3.1)
    // for the key_derivation benchmark. Uses libsrtp2's internal cipher
    // abstraction (copy-pasted from srtp.c).

    // libsrtp2 headers from the vendored srtp2-sys copy
    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let libsrtp_dir = manifest_dir.join("third_party/srtp2-sys/libsrtp");

    // generated config.h location, exported by the srtp2-sys build script
    let srtp2_include = std::env::var("DEP_SRTP2_INCLUDE")
        .expect("DEP_SRTP2_INCLUDE not set; srtp2-sys build script should export it");

    // OpenSSL include dir
    let openssl_include = std::env::var("DEP_OPENSSL_INCLUDE")
        .expect("DEP_OPENSSL_INCLUDE not set; openssl-sys build script should export it");

    let mut build = cc::Build::new();
    build.file("benches/c/srtp_kdf.c");

    // libsrtp2 internal headers
    build.include(libsrtp_dir.join("crypto/include"));
    build.include(libsrtp_dir.join("include"));

    // generated config.h
    build.include(&srtp2_include);

    // OpenSSL headers (needed by libsrtp2's cipher backends)
    build.include(&openssl_include);

    // OPENSSL is defined when libsrtp2 is built with --enable-openssl
    build.define("HAVE_CONFIG_H", None);
    build.define("OPENSSL", None);

    build.compile("srtp_kdf");
}
