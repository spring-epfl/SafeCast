//! Minimal RTP packet construction and parsing (RFC 3550).
//!
//! Only supports the fixed 12-byte header with no optional fields.
//! The 12 bytes are: version/flags (1) + payload type (1) + sequence number (2)
//! + timestamp (4) + SSRC (4). The version/flags byte is hardcoded to 0x80,
//! which means:
//!   - Version = 2 (the only version of RTP in use)
//!   - Padding = off (no extra padding bytes at the end of the payload)
//!   - Extension = off (no application-specific header extension present)
//!   - CSRC count = 0 (no CSRCs)
//!
//!
//! This is sufficient for feeding RTP packets into libsrtp's protect/unprotect.
//!
//! (The packet -> generation mapping for the keying schemes lives in
//! [`crate::generation`], not here.)

/// Fixed RTP header size in bytes: version/flags (1) + payload type (1)
/// + sequence number (2) + timestamp (4) + SSRC (4) = 12 bytes (RFC 3550 §5.1).
pub const RTP_HEADER_LEN: usize = 12;

/// A minimal RTP packet: fixed 12-byte header + payload.
pub struct RtpPacket {
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub payload: Vec<u8>,
}

impl RtpPacket {
    /// Serializes into the wire format: 12-byte header || payload.
    ///
    /// libsrtp's `protect` API operates on raw RTP
    /// bytes, not on a Rust struct
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(RTP_HEADER_LEN + self.payload.len());
        buf.push(0x80); 
        buf.push(self.payload_type & 0x7F);
        buf.extend_from_slice(&self.sequence_number.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.ssrc.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Parses from wire bytes (assumes no CSRC and no extensions).
    ///
    /// After libsrtp `unprotect` returns decrypted bytes,
    /// we need to reconstruct `RtpPacket`.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < RTP_HEADER_LEN {
            return None;
        }
        Some(Self {
            payload_type: data[1] & 0x7F,
            sequence_number: u16::from_be_bytes([data[2], data[3]]),
            timestamp: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            ssrc: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            payload: data[RTP_HEADER_LEN..].to_vec(),
        })
    }
}

