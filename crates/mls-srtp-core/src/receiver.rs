//! Receiver-side key management for fine-grained keying under real network
//! conditions (reordering, loss, gaps).
//!
//! A receiver in reality computes each packet's generation `g` statelessly from the packet itself,
//! and keeps a bounded window of the last K generation keys so that reordered
//! packets still decrypt:
//!   - in window  -> cache hit, install if needed, decrypt;
//!   - ahead      -> catch-up: ratchet forward to `g` (capped by `seek_cap`);
//!   - behind the window -> the key was already deleted: keying-loss drop
//!     (deleting old keys is exactly the forward secrecy);
//!   - too far ahead -> seek-cap drop (an unauthenticated packet must not be
//!     able to demand unbounded work).
//!
//! The catch-up runs on a clone of the ratchet, and
//! the real ratchet/window only adopts the clone's result after the packet
//! authenticates.
//!
//! Inherited from the `srtp` crate: on a failed `unprotect` the buffer
//! is emptied (length set to 0), so a packet cannot be retried after a failed
//! attempt. Callers that ever want to try a second key (the epoch-boundary
//! trial) must clone the buffer first.

use std::collections::VecDeque;

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use srtp::{CryptoPolicy, Error, Session, StreamPolicy};

/// Mapping from a packet's header to its generation index `g`.
pub mod generation;
/// RFC 3711 sequence-number unwrapping (16-bit seq -> extended index).
pub mod index_recovery;

use self::generation::{frame_generation, GenerationScheme};
use self::index_recovery::IndexRecovery;
use crate::ratchet::{split_key_salt, KeySalt, StreamRatchet};
use crate::rtp::RTP_HEADER_LEN;

/// Why a packet was not delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvDrop {
    /// The packet's generation is older than the K-window: its key was
    /// already deleted. This is keying-loss.
    BehindWindow,
    /// The packet claims a generation further ahead than `seek_cap` allows.
    SeekCapExceeded,
    /// libsrtp's replay protection rejected the packet (duplicate or older
    /// than the replay window).
    SrtpReplay,
    /// AEAD authentication failed (corrupt packet or wrong key), or the
    /// packet was malformed (shorter than an RTP header).
    AuthFail,
}

/// Counters describing everything the receiver did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecvStats {
    /// Packets that authenticated and decrypted.
    pub decrypted: u64,
    /// In-window cache hits (key found without any derivation).
    pub cache_hits: u64,
    /// Total ratchet steps derived during catch-ups (counted even
    /// if the triggering packet later failed to authenticate).
    pub catchup_steps: u64,
    /// The subset of `catchup_steps` whose result was discarded because the
    /// triggering packet did not authenticate (the rolled-back work an
    /// attacker can force, bounded per packet by `seek_cap`).
    pub catchup_steps_wasted: u64,
    /// Largest single catch-up (steps triggered by one packet).
    pub max_catchup: u64,
    /// `inplace_rekey` calls (key installs into the cipher).
    pub installs: u64,
    /// Keying-loss drops (generation older than the K-window).
    pub drops_behind: u64,
    /// Seek-cap drops (claimed generation too far ahead).
    pub drops_seek_cap: u64,
    /// libsrtp replay rejections (duplicates/below the replay-window).
    pub drops_replay: u64,
    /// AEAD authentication failures and malformed packets.
    pub drops_auth: u64,
}

/// A receiver-side SRTP stream with a bounded window of generation keys.
/// One instance handles one inbound SSRC.
pub struct ReceiverKeyManager {
    session: Session,
    ssrc: u32,
    scheme: GenerationScheme,
    recovery: IndexRecovery,
    ratchet: StreamRatchet,
    provider: OpenMlsRustCrypto,
    /// Ring of the last K derived generation keys. Slot `g % K` holds
    /// `(g, key||salt)` and older entries are overwritten (= deleted).
    ring: Vec<Option<(u64, KeySalt)>>,
    /// Highest extended generation derived so far (None before the first packet).
    frontier: Option<u64>,
    /// Generation whose key is currently loaded in the cipher.
    installed: Option<u64>,
    /// Most ratchet steps one packet may demand.
    seek_cap: u64,
    stats: RecvStats,
}

/// Where a packet's generation `g` falls relative to what we have derived,
/// once it has passed the too-old and too-far-ahead checks.
enum Placement {
    /// `g` is within the window of kept keys: here is its key+salt, ready to use.
    InWindow(KeySalt),
    /// `g` is ahead of the frontier: the ratchet must advance this many steps
    /// (the forward jump) to reach it.
    Ahead(u64),
}

/// The result of ratcheting forward to reach an `Ahead` packet's generation,
/// held aside until that packet authenticates. As an unauthenticated
/// (possibly forged) packet must not touch the real ratchet or key ring,
/// the forward steps are computed on throwaway copies here first. Only if
/// the packet decrypts do these replace the receiver's real state.
struct PendingCatchup {
    /// The ratchet after advancing to the new generation (would become the
    /// receiver's ratchet on success).
    ratchet: StreamRatchet,
    /// The newly derived `(generation, key||salt)` pairs to fold into the
    /// key ring on success.
    derived: VecDeque<(u64, KeySalt)>,
    /// How many forward steps this catch-up took (for the stats counters).
    jump: u64,
}

impl ReceiverKeyManager {
    /// Creates a receiver for `ssrc` with a window of `k` generation keys, a
    /// forward-jump cap of `seek_cap` generations, and the given libsrtp
    /// replay window (`0` = libsrtp default of 128).
    ///
    /// Size of the three parameters:
    /// - `k`: how far BEHIND a packet may arrive and still decrypt (its key
    ///   must still be in the ring), so it must cover the worst lateness.
    ///   Every kept key is also forward-secrecy exposure, so k
    ///   is a tradeoff, not "the bigger the better".
    /// - `seek_cap`: how far AHEAD a packet may jump: the most ratchet steps
    ///   one packet can demand. These steps happen before authentication, so seek_cap
    ///   bounds the work a forged DoS packet can force. A real packet arrival
    ///   demands a jump of "packets sent before it that are still
    ///   missing" + 1, and big jumps come from loss, so we size it by the longest outage.
    ///   Reordering keeps jumps tiny, because the only sent-before-it packets that can still be
    ///   missing are due to small jitter.
    ///   Sample calculation (packet-level keying, 1424 B packets leaving
    ///   every ~4.6 us, jitter up to 100 us): a jump of at most 100/4.6 = ~21 -> ~22 steps. 
    ///   A 100 ms outage instead leaves 100_000/4.6 = ~21,700 packets missing.
    /// - `replay_window`: libsrtp remembers the highest packet index it has
    ///   accepted so far, and rejects every packet arriving more than
    ///   replay_window positions behind that index, replay or not. At
    ///   packet-level keying it must be set to `k`, as with a smaller value
    ///   we reject packets whose key we still hold. Beyond `k` it does not
    ///   buy anything, as a packet older than `k` is dropped due to its
    ///   deleted key. At frame level `k` counts frames, not packets, so no
    ///   comparison there: the window just needs to cover the worst
    ///   lateness in packets. libsrtp accepts 64..=32767.
    pub fn new(
        scheme: GenerationScheme,
        ssrc: u32,
        ratchet: StreamRatchet,
        k: usize,
        seek_cap: u64,
        replay_window: u64,
    ) -> Self {
        assert!(k >= 1, "window must hold at least one generation key");
        srtp::ensure_init();

        // One libsrtp session holding a single specific-SSRC AES-GCM stream.
        // We reuse it for every packet and just swap its key via inplace_rekey.
        let mut session = Session::new().expect("srtp_create failed");


        let throwaway = [0u8; 28];
        let policy = StreamPolicy {
            rtp: CryptoPolicy::aes_gcm_128_16_auth(),
            rtcp: CryptoPolicy::aes_gcm_128_16_auth(),
            key: &throwaway,
            window_size: replay_window,
            ..Default::default()
        };
        session.add_stream(ssrc, policy).expect("add_stream failed");

        ReceiverKeyManager {
            session,
            ssrc,
            scheme,
            recovery: IndexRecovery::default(),
            ratchet,
            provider: OpenMlsRustCrypto::default(),
            ring: vec![None; k],
            frontier: None,
            installed: None,
            seek_cap,
            stats: RecvStats::default(),
        }
    }

    /// Generation whose key is currently installed in the cipher.
    pub fn installed_generation(&self) -> Option<u64> {
        self.installed
    }

    /// Highest generation derived so far.
    pub fn frontier(&self) -> Option<u64> {
        self.frontier
    }

    /// Everything the receiver did so far.
    pub fn stats(&self) -> &RecvStats {
        &self.stats
    }

    /// Decrypts an SRTP packet in place (header || ciphertext || tag ->
    /// header || payload). On success returns the generation the packet
    /// decrypted under, so a caller that knows the packet's true position
    /// can verify the mapping-to-generation worked.
    /// The flow is four phases: (1) map the packet to a generation `g`,
    /// (2) classify `g` against the key window, (3) fetch or derive its
    /// key, (4) decrypt and only then finalize any state change.
    pub fn unprotect(&mut self, buf: &mut Vec<u8>) -> Result<u64, RecvDrop> {

        // reject a truncated datagram before touching its seq/ts fields below
        if buf.len() < RTP_HEADER_LEN {
            self.stats.drops_auth += 1;
            return Err(RecvDrop::AuthFail);
        }

        // reading seq (bytes 2-3) and timestamp (bytes 4-7) from the RTP
        // header, which is in the clear for AES-GCM SRTP
        let seq = u16::from_be_bytes([buf[2], buf[3]]);
        let ts = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

        // --- phase 1: map the packet to its generation `g` ---
        // (est_index carries the packet's extended index for the packet-level
        // scheme, so we can update the recovery later if it authenticates)
        let (g, est_index) = match self.scheme {
            // epoch-only: one key for the whole epoch, so every packet is g = 0
            GenerationScheme::EpochOnly => (0, None),
            // frame-level: g counts frames from the epoch's first frame, read
            // straight from the timestamp (no recovery needed, hence None)
            GenerationScheme::Frame {
                epoch_start_ts,
                frame_period,
            } => (frame_generation(ts, epoch_start_ts, frame_period), None),
            // packet-level: g counts packets, so first we recover the packet's
            // true position (unwrapping the 16-bit seq), then we subtract the base
            GenerationScheme::Packet { base } => {
                let index = self.recovery.recover(seq);
                // a packet from before the epoch's first packet (index < base)
                // has no generation in this epoch: its key does not exist
                let Some(g) = index.checked_sub(base) else {
                    self.stats.drops_behind += 1;
                    return Err(RecvDrop::BehindWindow);
                };
                (g, Some(index))
            }
            // every-n: like packet-level, except n consecutive indexes share
            // one generation, so the recovered offset is divided by n
            GenerationScheme::EveryN { base, n } => {
                let index = self.recovery.recover(seq);
                let Some(offset) = index.checked_sub(base) else {
                    self.stats.drops_behind += 1;
                    return Err(RecvDrop::BehindWindow);
                };
                (offset / n as u64, Some(index))
            }
        };

        // --- phase 2: classify g against the window [frontier-K+1, frontier] ---
        let k = self.ring.len() as u64;
        let placement = match self.frontier {
            // g is at or behind the frontier
            Some(f) if g <= f => {

                // too old (its key was already overwritten = keying-loss)
                if f - g >= k {
                    self.stats.drops_behind += 1;
                    return Err(RecvDrop::BehindWindow);
                }

                // still within the window:
                // ring maps generation -> slot by remainder: slot g % k
                // holds this generation's key
                let slot = &self.ring[(g % k) as usize];
                match slot {
                    // found
                    Some((tag, ks)) if *tag == g => Placement::InWindow(*ks),
                    _ => unreachable!("in-window generation {g} missing from ring"),
                }
            }
            
            // g is ahead of the frontier (or nothing derived yet): we must
            // ratchet forward to reach it. `jump` = how many generations to
            // advance = how many keys to derive.
            frontier => {
                let jump = match frontier {
                    // derive the g - f new generations past the frontier f
                    Some(f) => g - f,
                    // nothing derived yet: reaching g means deriving
                    // generations 0..=g, i.e. g + 1 of them
                    None => g + 1,
                };
                if jump > self.seek_cap {
                    self.stats.drops_seek_cap += 1;
                    return Err(RecvDrop::SeekCapExceeded);
                }
                Placement::Ahead(jump)
            }
        };

        // --- phase 3: get the key for g (cache hit or catch-up) ---
        // A catch-up advances the ratchet, which is one-way and irreversible.
        // Since this packet is not yet authenticated (it could be forged), we
        // do that advance on a clone of the ratchet and stash the result in
        // `pending_clone`; the real ratchet only takes it over in phase 4 if the
        // packet decrypts. So an unauthenticated packet can never move real
        // state.
        let mut pending_clone: Option<PendingCatchup> = None;
        let key_salt = match placement {
            // key already derived and still in the window: just read it out
            Placement::InWindow(ks) => {
                self.stats.cache_hits += 1;
                ks
            }
            // key not derived yet: ratchet forward to reach generation g,
            // working on a clone so nothing durable moves until auth (phase 4)
            Placement::Ahead(jump) => {
                let mut ratchet = self.ratchet.clone();
                // The newly derived (generation, key||salt) pairs. We keep at
                // most K of them (the ring's size), since anything older will
                // already be evicted once the frontier lands on g
                let mut derived: VecDeque<(u64, KeySalt)> = VecDeque::new();

                // advancing one generation at a time up to and including g
                // (next_key_salt derives the current generation's key, then
                // steps the ratchet forward)
                while ratchet.generation() <= g {
                    let (gg, ks) = ratchet.next_key_salt(self.provider.crypto());
                    // bounded ring: drop the oldest once we already hold K
                    if derived.len() == self.ring.len() {
                        derived.pop_front();
                    }
                    derived.push_back((gg, ks));
                }

                // count the work and track the worst single burst
                self.stats.catchup_steps += jump;
                self.stats.max_catchup = self.stats.max_catchup.max(jump);

                // the key we actually need is g's, i.e. the last one derived
                let ks = derived.back().expect("catch-up derived at least one key").1;

                // stashing the advanced clone + its keys, to be adopted in phase 4
                // only if the packet decrypts
                pending_clone = Some(PendingCatchup {
                    ratchet,
                    derived,
                    jump,
                });
                ks
            }
        };

        // --- phase 4: decrypt, then finalize state only on success ---
        // the cipher holds one key at a time, so load g's key only if it is
        // not already the installed one. This is usually skipped (consecutive
        // packets share a generation), but reordering can force it back and
        // forth: e.g. a late packet from frame N arriving after frame N+1
        // makes us install N's key, then N+1's again for the next packet - a
        // "flip-flop" of two extra installs per late packet.
        if self.installed != Some(g) {
            let (key, salt) = split_key_salt(&key_salt);
            self.session
                .inplace_rekey(self.ssrc, key, salt)
                .expect("inplace_rekey failed");
            self.installed = Some(g);
            self.stats.installs += 1;
        }

        // decrypting (this is where the packet is finally authenticated)
        match self.session.unprotect(buf) {
            Ok(()) => {
                // authenticated -> now safe to finalize any state changes
                if let Some(pending) = pending_clone {
                    // adopting the advanced ratchet as the real one
                    self.ratchet = pending.ratchet;
                    // folding the newly derived keys into the ring 
                    // (deleting old keys = FS)
                    let k = self.ring.len() as u64;
                    for (gg, ks) in pending.derived {
                        self.ring[(gg % k) as usize] = Some((gg, ks));
                    }
                    // the window now ends at g
                    self.frontier = Some(g);
                }

                // packet-level only: recording this genuine packet's position as
                // IndexRecovery's "highest index seen"
                if let Some(index) = est_index {
                    self.recovery.update(index);
                }
                self.stats.decrypted += 1;
                Ok(g)
            }

            // authentication failed or replay protection rejected the packet
            Err(e) => {
                // rolling back: the clone (if any) is dropped, so the
                // ratchet, ring and frontier stay untouched, only the wasted
                // work is recorded
                if let Some(pending) = pending_clone {
                    self.stats.catchup_steps_wasted += pending.jump;
                }
                match e {
                    Error::REPLAY_FAIL | Error::REPLAY_OLD => {
                        self.stats.drops_replay += 1;
                        Err(RecvDrop::SrtpReplay)
                    }
                    Error::AUTH_FAIL => {
                        self.stats.drops_auth += 1;
                        Err(RecvDrop::AuthFail)
                    }
                    e => panic!("unexpected libsrtp error: {e:?}"),
                }
            }
        }
    }
}
