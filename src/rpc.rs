use argon2::Argon2;
use hmac::{Hmac, Mac};
use n0_error::{bail_any, AnyError, Result, StdResultExt};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::node_map::{NodeInfo, NodeMap};

/// Fixed salt for argon2id key derivation.
///
/// Both sides derive the same key from the same passphrase using this salt.
/// A random salt isn't possible since both sides must independently arrive
/// at the same key.
pub const AUTH_SALT: &[u8] = b"dumbvpn-network-secret-v1";

/// A symmetric key derived from a network secret passphrase via argon2id.
#[derive(Clone, Copy)]
pub struct NetworkKey([u8; 32]);

impl NetworkKey {
    /// Derive a network key from a passphrase using argon2id.
    pub fn from_passphrase(passphrase: &str) -> Self {
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(passphrase.as_bytes(), AUTH_SALT, &mut key)
            .expect("argon2 key derivation");
        Self(key)
    }

    /// Compute HMAC-SHA256(self, data).
    pub fn hmac(&self, data: &[u8]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC accepts any key size");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }
}

pub const CHALLENGE_LEN: usize = 32;

/// RPC call IDs.
pub const RPC_DATA: u8 = 0;
pub const RPC_GOSSIP: u8 = 1;
pub const RPC_LIST_NODES: u8 = 2;

/// Listener-side authentication (challenge-response).
///
/// 1. Connector sends a 1-byte RPC ID (stream opener)
/// 2. Listener sends a 32-byte random challenge
/// 3. Connector sends HMAC-SHA256(key, challenge)
/// 4. Listener verifies
///
/// Returns the RPC ID byte sent by the connector.
pub async fn auth_accept(
    send: &mut noq::SendStream,
    recv: &mut noq::RecvStream,
    key: &NetworkKey,
) -> Result<u8> {
    // Read the RPC ID byte from the connector.
    let mut opener = [0u8; 1];
    recv.read_exact(&mut opener).await.anyerr()?;

    // Send a random challenge.
    let challenge: [u8; CHALLENGE_LEN] = rand::rng().random();
    send.write_all(&challenge).await.anyerr()?;

    // Read and verify the HMAC response.
    let mut response = [0u8; 32];
    recv.read_exact(&mut response).await.anyerr()?;
    if response != key.hmac(&challenge) {
        bail_any!("authentication failed: invalid network secret");
    }
    Ok(opener[0])
}

/// Connector-side authentication (challenge-response).
///
/// Sends the given `rpc_id` byte, reads the challenge from the listener, then
/// responds with HMAC-SHA256(key, challenge).
pub async fn auth_connect(
    send: &mut noq::SendStream,
    recv: &mut noq::RecvStream,
    key: &NetworkKey,
    rpc_id: u8,
) -> Result<()> {
    // Send the RPC ID byte.
    send.write_all(&[rpc_id]).await.anyerr()?;

    // Read the challenge from the listener.
    let mut challenge = [0u8; CHALLENGE_LEN];
    recv.read_exact(&mut challenge).await.anyerr()?;

    // Send the HMAC response.
    let response = key.hmac(&challenge);
    send.write_all(&response).await.anyerr()?;
    Ok(())
}

/// Maximum frame size (1 MiB).
const MAX_FRAME_LEN: usize = 1024 * 1024;

/// Write a length-prefixed frame (4-byte LE length + data).
pub async fn write_frame(send: &mut noq::SendStream, data: &[u8]) -> Result<()> {
    let len = u32::try_from(data.len()).std_context("frame too large")?;
    send.write_all(&len.to_le_bytes()).await.anyerr()?;
    send.write_all(data).await.anyerr()?;
    Ok(())
}

/// Read a length-prefixed frame (4-byte LE length + data).
pub async fn read_frame(recv: &mut noq::RecvStream, max_len: usize) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await.anyerr()?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if max_len < len {
        bail_any!("frame too large: {len} bytes (max {max_len})");
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.anyerr()?;
    Ok(buf)
}

#[derive(Serialize, Deserialize)]
pub struct GossipRequest {
    pub node: NodeInfo,
}

#[derive(Serialize, Deserialize)]
pub struct GossipResponse {
    pub node: Option<NodeInfo>,
}

#[derive(Serialize, Deserialize)]
pub struct ListNodesResponse {
    pub nodes: Vec<NodeInfo>,
}

/// Result of dispatching an RPC call.
pub enum RpcOutcome {
    /// RPC 0: caller should proceed with bidirectional data forwarding.
    DataForward,
    /// RPC was handled (gossip, list-nodes, etc.) — continue accept loop.
    Handled,
}

/// Dispatch an RPC call based on the RPC ID returned by `auth_accept`.
pub async fn dispatch_rpc(
    rpc_id: u8,
    send: &mut noq::SendStream,
    recv: &mut noq::RecvStream,
    node_map: &NodeMap,
) -> Result<RpcOutcome> {
    match rpc_id {
        RPC_DATA => Ok(RpcOutcome::DataForward),
        RPC_GOSSIP => {
            handle_gossip(send, recv, node_map).await?;
            send.finish().anyerr()?;
            send.stopped().await.anyerr()?;
            Ok(RpcOutcome::Handled)
        }
        RPC_LIST_NODES => {
            handle_list_nodes(send, node_map).await?;
            send.finish().anyerr()?;
            send.stopped().await.anyerr()?;
            Ok(RpcOutcome::Handled)
        }
        other => bail_any!("unknown RPC ID: {other}"),
    }
}

/// Handle an incoming gossip RPC (responder side).
///
/// Reads a `GossipRequest`, updates the node map, picks a random other node
/// to share back, and sends a `GossipResponse`.
async fn handle_gossip(
    send: &mut noq::SendStream,
    recv: &mut noq::RecvStream,
    node_map: &NodeMap,
) -> Result<()> {
    let frame = read_frame(recv, MAX_FRAME_LEN).await?;
    let req: GossipRequest =
        postcard::from_bytes(&frame).map_err(|e| AnyError::from(e.to_string()))?;

    tracing::info!("gossip: received node info for '{}'", req.node.name);

    let exclude_key = req.node.id;
    node_map.insert(req.node).await;
    let response_node = node_map.pick_random(Some(&exclude_key)).await;

    let resp = GossipResponse {
        node: response_node,
    };
    let data = postcard::to_allocvec(&resp).map_err(|e| AnyError::from(e.to_string()))?;
    write_frame(send, &data).await?;
    Ok(())
}

/// Handle a list-nodes RPC.
///
/// Reads the current node map and sends all known nodes back.
async fn handle_list_nodes(send: &mut noq::SendStream, node_map: &NodeMap) -> Result<()> {
    let nodes = node_map.list().await;

    tracing::info!("list-nodes: returning {} nodes", nodes.len());

    let resp = ListNodesResponse { nodes };
    let data = postcard::to_allocvec(&resp).map_err(|e| AnyError::from(e.to_string()))?;
    write_frame(send, &data).await?;
    Ok(())
}
