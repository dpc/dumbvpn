use iroh::{Endpoint, PublicKey};
use n0_error::{AnyError, Result, StdResultExt};
use rand::Rng;
use tokio_util::sync::CancellationToken;

use crate::node_map::NodeMap;
use crate::rpc::{self, GossipRequest, GossipResponse, NetworkKey, RPC_GOSSIP};

/// Default gossip interval center (10 minutes).
const GOSSIP_INTERVAL_SECS: u64 = 600;
/// Jitter range: +/- 2 minutes.
const GOSSIP_JITTER_SECS: u64 = 120;

/// Background gossip loop.
///
/// Periodically connects to a random known peer and exchanges node info.
/// Runs immediately on start, then every ~10min (8-12min with jitter).
pub async fn gossip_loop(
    endpoint: Endpoint,
    key: NetworkKey,
    node_map: NodeMap,
    own_name: String,
    initial_peers: Vec<PublicKey>,
    cancel: CancellationToken,
) {
    let mut first = true;
    loop {
        if first {
            first = false;
        } else {
            let jitter = rand::rng().random_range(0..=(2 * GOSSIP_JITTER_SECS));
            let delay = GOSSIP_INTERVAL_SECS - GOSSIP_JITTER_SECS + jitter;
            tokio::select! {
                () = tokio::time::sleep(std::time::Duration::from_secs(delay)) => {}
                () = cancel.cancelled() => return,
            }
        }

        if let Err(e) = gossip_once(&endpoint, &key, &node_map, &own_name, &initial_peers).await {
            tracing::warn!("gossip round failed: {e}");
        }
    }
}

/// Perform a single gossip round: pick a random peer, exchange node info.
async fn gossip_once(
    endpoint: &Endpoint,
    key: &NetworkKey,
    node_map: &NodeMap,
    own_name: &str,
    initial_peers: &[PublicKey],
) -> Result<()> {
    let candidates = node_map.gossip_candidates(own_name, initial_peers).await;

    if candidates.is_empty() {
        tracing::debug!("gossip: no candidates to gossip with");
        return Ok(());
    }

    let idx = rand::rng().random_range(0..candidates.len());
    let target = &candidates[idx];
    tracing::info!("gossip: connecting to {}", target.id);

    let connection = endpoint
        .connect(target.clone(), crate::ALPN)
        .await
        .std_context("gossip: failed to connect")?;

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .std_context("gossip: failed to open bidi stream")?;

    rpc::auth_connect(&mut send, &mut recv, key, RPC_GOSSIP).await?;

    // Pick a random node to share (excluding the target, since it already
    // knows about itself).
    let to_share = node_map.pick_random(Some(&target.id)).await;
    let Some(node) = to_share else {
        tracing::debug!("gossip: nothing to share with {}", target.id);
        return Ok(());
    };

    let req = GossipRequest { node };
    let data = postcard::to_allocvec(&req).map_err(|e| AnyError::from(e.to_string()))?;
    rpc::write_frame(&mut send, &data).await?;

    // Read response.
    let resp_data = rpc::read_frame(&mut recv, 1024 * 1024).await?;
    let resp: GossipResponse =
        postcard::from_bytes(&resp_data).map_err(|e| AnyError::from(e.to_string()))?;

    if let Some(node) = resp.node {
        tracing::info!("gossip: learned about node '{}'", node.name);
        node_map.insert(node).await;
    }

    Ok(())
}
