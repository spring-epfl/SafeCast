//! The TESLA receiver: decides per packet whether it can still be
//! trusted, and verifies it once its key goes public.
//!
//! For each arriving packet, in order:
//!
//! 1. Strip the TESLA extension off the datagram.
//! 2. The accept test: could this packet's key already be public? If yes,
//!    the packet proves nothing anymore and is dropped unverified.
//! 3. Copy the packet bytes. The MAC must be checked against them later,
//!    but the SRTP decrypt otherwise overwrites them.
//! 4. SRTP unprotect. The plaintext is handed out
//!    immediately ("optimistic playout") -> its per-sender verdict follows
//!    once the key arrives.
//! 5. Process the disclosed key the packet carried: check it is genuine
//!    (it must hash down to a chain key we already trust), then verify
//!    the MAC of every packet that was waiting for it.
//!
//! A delivered packet waits in a "drawer": the per-interval list of
//! (packet copy, MAC) pairs whose key is still secret. When the interval's
//! key finally arrives and checks out, d intervals later, the drawer's
//! packets are "settled": each MAC is recomputed with that key and the packet is
//! declared verified or forged.

use std::collections::BTreeMap;

use crate::receiver::index_recovery::IndexRecovery;
use crate::receiver::{ReceiverKeyManager, RecvDrop};
use crate::tesla::chain::{ChainKey, ChainVerifier, Disclosure};
use crate::tesla::mac::{TeslaMacAlg, TESLA_MAC_LEN};
use crate::tesla::schedule::{IntervalCheck, TeslaSchedule};
use crate::tesla::split_extension;
use crate::transport::rtp::RTP_HEADER_LEN;

/// Why a packet was dropped instead of delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeslaDrop {
    /// Too short to even carry a TESLA extension or an RTP header.
    Malformed,
    /// Failed the accept test: its key may already be public.
    UnsafeLate,
    /// Carried a disclosed key that does not check out against the chain.
    BadDisclosure,
    /// Rejected by the SRTP layer (outer tag, replay, keying).
    Srtp(RecvDrop),
}

/// Counters and measurements of one receiver run.
#[derive(Debug, Default)]
pub struct TeslaStats {
    /// Packets decrypted and handed out (their verdict pending at first).
    pub delivered: u64,
    /// Delivered packets whose MAC later verified: really from the sender.
    pub verified: u64,
    /// Delivered packets whose MAC later failed: not from the sender.
    pub forged: u64,
    /// Drops per cause.
    pub drops_malformed: u64,
    pub drops_unsafe: u64,
    pub drops_bad_disclosure: u64,
    pub drops_srtp: u64,
    /// Most packets that ever waited in the drawers at once.
    pub peak_pending: u64,
    /// Per verified packet: stream time from its arrival to its verdict.
    pub latencies_ns: Vec<u64>,
}

/// One waiting packet: everything needed to verify it once its key
/// arrives.
struct DrawerEntry {
    /// The packet's full index (for the MAC's position binding).
    ext_index: u64,
    /// When it arrived, to measure how long the verdict took.
    arrival_ns: u64,
    /// The MAC the sender wrote.
    mac: [u8; TESLA_MAC_LEN],
    /// The bytes that MAC covers (copied before decryption destroyed them).
    covered: Vec<u8>,
}

/// The TESLA receiver for one stream, wrapped around the SRTP receiver.
pub struct TeslaReceiver {
    /// The schedule and the accept test.
    params: TeslaSchedule,
    /// The chain state: checks disclosed keys against the chain.
    verifier: ChainVerifier,
    /// Which MAC algorithm to use.
    alg: TeslaMacAlg,
    /// The SRTP layer: outer authentication, replay protection, decryption.
    inner: ReceiverKeyManager,
    /// Recovers each packet's full index from its 16-bit header seq. 
    recovery: IndexRecovery,
    /// The waiting packets, grouped by their interval.
    drawers: BTreeMap<u32, Vec<DrawerEntry>>,
    /// Packets currently waiting (drawer entries), for peak tracking.
    pending: u64,
    /// Statistics about the receiver's operation.
    stats: TeslaStats,
}

impl TeslaReceiver {
    /// Creates the receiver. `anchor` is the sender's K_0 (from the signed
    /// commitment), `inner` is the SRTP receiver.
    pub fn new(
        params: TeslaSchedule,
        anchor: ChainKey,
        alg: TeslaMacAlg,
        inner: ReceiverKeyManager,
    ) -> Self {
        TeslaReceiver {
            params,
            verifier: ChainVerifier::new(anchor, params.n_chain, params.g_max),
            alg,
            inner,
            recovery: IndexRecovery::default(),
            drawers: BTreeMap::new(),
            pending: 0,
            stats: TeslaStats::default(),
        }
    }

    /// Everything the receiver did so far.
    pub fn stats(&self) -> &TeslaStats {
        &self.stats
    }

    /// The SRTP layer's own counters.
    pub fn inner_stats(&self) -> &crate::receiver::RecvStats {
        self.inner.stats()
    }

    /// Packets still waiting for their key. At the end of a run these are
    /// the packets of the last d intervals, whose keys are never disclosed
    /// because the stream stopped.
    pub fn unsettled(&self) -> u64 {
        self.pending
    }

    /// Processes one arriving datagram. On success the packet was
    /// decrypted in place and delivered. The returned number says how many
    /// waiting packets its disclosed key settled (usually 0, more when it
    /// carried a new key).
    pub fn process_arrival(
        &mut self,
        buf: &mut Vec<u8>,
        arrival_ns: u64,
    ) -> Result<usize, TeslaDrop> {
        // stripping the extension: interval number, disclosed key, MAC
        let Some((interval, disclosed, mac)) = split_extension(buf) else {
            self.stats.drops_malformed += 1;
            return Err(TeslaDrop::Malformed);
        };
        // what is left must at least be an RTP header
        if buf.len() < RTP_HEADER_LEN {
            self.stats.drops_malformed += 1;
            return Err(TeslaDrop::Malformed);
        }

        // the accept test: is this packet's key still secret?
        if self.params.accepts(arrival_ns, interval) == IntervalCheck::UnsafeLate {
            self.stats.drops_unsafe += 1;
            return Err(TeslaDrop::UnsafeLate);
        }

        // the packet's full index, recovered from the header's 16-bit seq
        let seq = u16::from_be_bytes([buf[2], buf[3]]);
        let ext_index = self.recovery.recover(seq);

        // copying the MAC-covered bytes now: the decrypt below overwrites
        // them with plaintext
        let covered = buf.clone();

        // the SRTP decryption
        if let Err(drop) = self.inner.unprotect(buf) {
            self.stats.drops_srtp += 1;
            return Err(TeslaDrop::Srtp(drop));
        }

        // the packet authenticated as group traffic: its index is now the
        // recovery's reference point
        self.recovery.update(ext_index);

        // processing the disclosed key the packet carried
        let settled = match self
            .verifier
            .check(&disclosed, self.params.disclosed_index(interval))
        {
            // a new genuine key:
            // settling every packet that was waiting for one of them
            Disclosure::New(keys) => self.settle(&keys, arrival_ns),
            // the same key again (d consecutive intervals disclose the
            // same one) or the public anchor: nothing to do
            Disclosure::NotNew => 0,
            // the key does not check out against the chain: rejecting the
            // whole packet
            Disclosure::Invalid | Disclosure::TooFarAhead | Disclosure::BeyondChain => {
                self.stats.drops_bad_disclosure += 1;
                return Err(TeslaDrop::BadDisclosure);
            }
        };

        // the packet joins its interval's drawer to await its own verdict
        self.drawers.entry(interval).or_default().push(DrawerEntry {
            ext_index,
            arrival_ns,
            mac,
            covered,
        });
        self.pending += 1;
        self.stats.peak_pending = self.stats.peak_pending.max(self.pending);
        self.stats.delivered += 1;
        Ok(settled)
    }

    /// Verifies every waiting packet whose key just arrived: recomputes
    /// each packet's MAC with the now-known key and compares it against
    /// the one the sender wrote. Returns how many packets got a verdict.
    fn settle(&mut self, keys: &[(u32, ChainKey)], now_ns: u64) -> usize {
        let mut settled = 0;
        for (interval, key) in keys {
            // the packets that were waiting for this interval's key
            // (none if they were all lost)
            let Some(entries) = self.drawers.remove(interval) else {
                continue;
            };
            // the key setup once per interval, then one MAC per packet
            let prepared = self.alg.prepare(key);
            for entry in entries {
                if prepared.tag(entry.ext_index, &entry.covered) == entry.mac {
                    // the MAC matches: only the sender could have written
                    // it while the key was still secret
                    self.stats.verified += 1;
                    self.stats.latencies_ns.push(now_ns - entry.arrival_ns);
                } else {
                    // the MAC does not match: this packet was not from the
                    // sender
                    self.stats.forged += 1;
                }
                self.pending -= 1;
                settled += 1;
            }
        }
        settled
    }
}
