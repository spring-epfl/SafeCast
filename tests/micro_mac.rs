//! TESLA's per-packet cost is one MAC over the packet. This measures our
//! two MAC implementations: HMAC-SHA256 (hardware SHA via the sha2 crate)
//! and GMAC (AES-GCM's authentication part, via OpenSSL). GMAC wins,
//! ~250 ns vs ~650 ns per packet-sized message.
//!
//! Run: cargo test --release --test micro_mac -- --ignored --nocapture

use std::hint::black_box;
use std::time::Instant;

use mls_srtp_core::tesla::chain::TESLA_KEY_LEN;
use mls_srtp_core::tesla::mac::TeslaMacAlg;

#[test]
#[ignore]
fn mac_cost() {
    // tags computed per algorithm, enough that the mean is stable
    const N: u64 = 200_000;
    // the TESLA MAC input at the standard payload: header + 1390 B + tag
    // (the content does not matter, only the length)
    let msg = vec![0xABu8; 1418];
    let chain_key = [7u8; TESLA_KEY_LEN];

    for alg in [TeslaMacAlg::HmacSha256, TeslaMacAlg::GmacAes128] {
        // the key setup once
        let mut p = alg.prepare(&chain_key);
        // timing N tag computations in one block
        let t0 = Instant::now();
        for _ in 0..N {
            // black_box keeps the compiler from optimizing the calls away
            black_box(p.tag(7, black_box(&msg)));
        }
        let ns = t0.elapsed().as_nanos() as f64 / N as f64;
        // mean cost of one tag, and the per-byte speed it implies
        println!("{alg:?}  {ns:6.1} ns per tag  ({:.2} GB/s)", msg.len() as f64 / ns);
    }
}
