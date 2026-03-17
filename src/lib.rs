pub mod gossip;
pub mod node_map;
pub mod rpc;

/// The ALPN for dumbvpn.
///
/// It is basically just passing data through 1:1, except that the connecting
/// side will send an HMAC-based auth proof before data transfer begins.
pub const ALPN: &[u8] = b"DUMBPIPEV0";

use std::fmt;
use std::str::FromStr;

pub use iroh::{EndpointAddr, PublicKey, SecretKey};
pub use iroh_tickets::endpoint::EndpointTicket;
pub use node_map::{NodeInfo, NodeMap};
pub use rpc::NetworkKey;

/// A node address that can be parsed from either a full endpoint ticket
/// or a bare public key (node ID).
#[derive(Debug, Clone)]
pub struct NodeAddr(EndpointAddr);

impl NodeAddr {
    pub fn endpoint_addr(&self) -> EndpointAddr {
        self.0.clone()
    }
}

impl fmt::Display for NodeAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.id)
    }
}

impl FromStr for NodeAddr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try parsing as a full endpoint ticket first.
        if let Ok(ticket) = EndpointTicket::from_str(s) {
            return Ok(Self(ticket.endpoint_addr().clone()));
        }
        // Fall back to parsing as a bare public key.
        let pk = PublicKey::from_str(s).map_err(|e| format!("invalid node address: {e}"))?;
        Ok(Self(EndpointAddr::new(pk)))
    }
}
