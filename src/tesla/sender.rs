//! The TESLA sender: authenticates each outgoing packet.
//!
//! Per packet this means three things, all appended as the extension:
//! which interval the packet belongs to (from its send time), a MAC under
//! that interval's still-secret key, and the disclosure of an old key
//! whose secrecy has expired (the one from `d`` intervals ago).
//!
//! The sender owns the whole key chain, built here from its own private
//! randomness. Only the starting point K_0 ever leaves it directly (in
//! the signed commitment). Every other key leaves through the scheduled
//! disclosures.

use crate::tesla::chain::{ChainKey, TeslaChain};
use crate::tesla::mac::{PreparedMac, TeslaMacAlg};
use crate::tesla::schedule::TeslaSchedule;
use crate::tesla::append_extension;

/// The sender's TESLA state for one stream.
pub struct TeslaSender {
    /// The schedule (intervals, disclosure delay).
    params: TeslaSchedule,
    /// The full key chain, K_0..=K_n_chain.
    chain: TeslaChain,
    /// Which MAC algorithm tags the packets.
    alg: TeslaMacAlg,
    /// The interval whose MAC state is currently prepared.
    current_interval: u32,
    /// That interval's ready-to-use MAC state (key setup already done).
    prepared: PreparedMac,
}

impl TeslaSender {
    /// Creates the sender: builds a fresh private chain sized to the
    /// schedule and prepares interval 1's MAC state.
    pub fn new(params: TeslaSchedule, alg: TeslaMacAlg) -> Self {
        // the chain is generated here from a random value
        let chain = TeslaChain::generate(params.n_chain);
        // the stream starts in interval 1, so its MAC state is set up first
        let prepared = alg.prepare(chain.key(1));
        TeslaSender {
            params,
            chain,
            alg,
            current_interval: 1,
            prepared,
        }
    }

    /// The public starting point K_0, for the receiver's commitment.
    pub fn anchor(&self) -> &ChainKey {
        self.chain.anchor()
    }

    /// Authenticates one protected packet in place: appends the 34-byte
    /// extension (interval number, disclosed old key, MAC over the whole
    /// packet). `ext_index` is the packet's full index, `send_ns` its send
    /// time.
    pub fn authenticate(&mut self, buf: &mut Vec<u8>, ext_index: u64, send_ns: u64) {
        // the interval this packet belongs to, from its send time
        let interval = self.params.interval_of(send_ns);
        // on entering a new interval, we set up its MAC state once (the
        // sender emits in send order, so intervals only move forward)
        if interval != self.current_interval {
            self.prepared = self.alg.prepare(self.chain.key(interval));
            self.current_interval = interval;
        }
        // the MAC over the packet, under the interval's still-secret key
        let mac = self.prepared.tag(ext_index, buf);
        // the key due for disclosure: the one from d intervals ago!
        let disclosed = self.chain.key(self.params.disclosed_index(interval));
        // appending interval || disclosed key || MAC
        append_extension(buf, interval, disclosed, &mac);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tesla::chain::{ChainVerifier, Disclosure};
    use crate::tesla::split_extension;

    /// The sender-to-receiver story, in order (d = 2 throughout). The
    /// receiver role is played inline by this test, using the
    /// receiver-side primitives.
    ///
    /// 1. The sender emits a packet in interval 1. Its MAC key (key 1) is
    ///    still secret, so the receiver can only hold on to the packet.
    /// 2. The sender emits a packet in interval 3, which by schedule
    ///    discloses key 1 (= 3 - d).
    /// 3. The receiver, knowing only the anchor K_0, proves the disclosed
    ///    key genuine by hashing it down to K_0.
    /// 4. With key 1 now proven, the receiver verifies the MAC of the
    ///    interval-1 packet it had been holding since step 1.
    #[test]
    fn receiver_can_verify_sender_output() {
        // 1 ms intervals, d = 2, a 10-interval chain
        let params = TeslaSchedule::new(0, 1_000_000, 2, 10, 0, 16);
        let mut sender = TeslaSender::new(params, TeslaMacAlg::HmacSha256);
        // the receiver's side of the chain, started from the anchor
        let mut verifier = ChainVerifier::new(*sender.anchor(), 10, 16);

        // packet 0, sent at 0.5 ms: belongs to interval 1
        let mut p0: Vec<u8> = (0u8..60).collect();
        sender.authenticate(&mut p0, 0, 500_000);
        let (i0, k0, mac0) = split_extension(&mut p0).expect("extension present");
        assert_eq!(i0, 1);
        // intervals 1 and 2 disclose only the already-public anchor:
        // nothing new for the receiver
        assert_eq!(verifier.check(&k0, params.disclosed_index(i0)), Disclosure::NotNew);
        // the receiver cannot verify mac0 yet (key 1 still secret): it
        // holds on to the packet and its MAC

        // packet 1, sent at 2.5 ms: belongs to interval 3, and discloses
        // key 1 (= 3 - d), the first real key to go public
        let mut p1: Vec<u8> = (100u8..160).collect();
        sender.authenticate(&mut p1, 1, 2_500_000);
        let (i1, k1, _mac1) = split_extension(&mut p1).expect("extension present");
        assert_eq!(i1, 3);
        // the disclosed key must prove genuine against the anchor
        let recovered = match verifier.check(&k1, params.disclosed_index(i1)) {
            Disclosure::New(keys) => keys,
            other => panic!("key 1 should verify, got {other:?}"),
        };
        assert_eq!(recovered.len(), 1);
        let (idx, key1) = recovered[0];
        assert_eq!(idx, 1);

        // with key 1 in hand, the held-back interval-1 packet verifies:
        // recomputing its MAC gives exactly what the sender wrote
        let recomputed = TeslaMacAlg::HmacSha256.prepare(&key1).tag(0, &p0);
        assert_eq!(recomputed, mac0);
    }
}
