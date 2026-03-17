/// The ALPN for dumbvpn.
///
/// It is basically just passing data through 1:1, except that the connecting
/// side will send an HMAC-based auth proof before data transfer begins.
pub const ALPN: &[u8] = b"DUMBPIPEV0";

pub use iroh::{EndpointAddr, SecretKey};
pub use iroh_tickets::endpoint::EndpointTicket;
