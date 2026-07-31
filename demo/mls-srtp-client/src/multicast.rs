//! IP multicast UDP helpers for SRTP media transport.
//! 
//! In normal unicast, a packet goes from one sender to one
//! receiver. With multicast, a packet is sent to a special group
//! address (here `239.0.0.1`) and the network delivers a copy to
//! every host that has joined that group. The protocol that manages
//! group membership is IGMP:
//! when a host joins a multicast group, the OS sends an IGMP membership 
//! report so routers know to forward traffic for that group
//! address to that host.
//!
//! Sender side: Opens a UDP socket bound to `0.0.0.0:0`. 
//! It then sends SRTP packets to `239.0.0.1:5004`.
//! The multicast TTL (Time To Live) is set to 1, meaning packets
//! are not forwarded beyond the local subnet (each router that
//! forwards a packet decrements the TTL; at 0 the packet is dropped).
//!
//! Receiver side: Uses the `socket2` crate instead of Tokio's
//! built-in socket API because two low-level options are needed:
//!   1. `SO_REUSEADDR`: lets multiple receiver processes on the same
//!      machine bind to the same port simultaneously (normally the OS
//!      rejects a second bind to an already-used port).
//!   2. `join_multicast_v4`: tells the OS to join the multicast
//!      group, triggering an IGMP report so routers deliver
//!      `239.0.0.1` traffic to this host.
//! The receiver binds to `0.0.0.0:5004` and joins the group.

use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::net::UdpSocket;

/// Multicast group address for SRTP media (administratively-scoped range
/// 239.0.0.0/8, RFC 2365).
pub const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(239, 0, 0, 1);

/// RTP port
pub const MULTICAST_PORT: u16 = 5004;

/// Creates a UDP socket for sending to the multicast group.
pub async fn create_multicast_sender() -> std::io::Result<UdpSocket> {
    // binding to 0.0.0.0:0 lets the OS pick an available ephemeral port
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    // TTL=1 restricts multicast to the local subnet
    socket.set_multicast_ttl_v4(1)?;
    Ok(socket)
}

/// Creates a UDP socket for receiving from the multicast group.
pub fn create_multicast_receiver() -> std::io::Result<UdpSocket> {
    
    // using socket2 for SO_REUSEADDR and IGMP membership control
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    // allowing multiple receivers to bind to the same port on one host
    socket.set_reuse_address(true)?;
    // on Unix, SO_REUSEPORT is also required for multiple processes to
    // bind to the same port simultaneously
    #[cfg(unix)]
    socket.set_reuse_port(true)?;

    // required before handing off to Tokio's async reactor
    socket.set_nonblocking(true)?;

    // binding to INADDR_ANY:5004 to receive multicast traffic on all interfaces
    socket.bind(&socket2::SockAddr::from(SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        MULTICAST_PORT,
    )))?;

    // joining the multicast group on all interfaces (INADDR_ANY);
    // this triggers an IGMP membership report so routers forward
    // traffic for 239.0.0.1 to this host
    socket.join_multicast_v4(&MULTICAST_ADDR, &Ipv4Addr::UNSPECIFIED)?;

    // converting the raw socket2 socket into a Tokio async UdpSocket
    UdpSocket::from_std(socket.into())
}

/// Returns the full multicast destination as a `"host:port"` string
/// suitable for `UdpSocket::send_to`.
pub fn multicast_dest() -> String {
    format!("{}:{}", MULTICAST_ADDR, MULTICAST_PORT)
}
