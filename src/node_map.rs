use std::collections::HashMap;
use std::sync::Arc;

use iroh::{EndpointAddr, PublicKey};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub name: String,
    pub addr: EndpointAddr,
}

#[derive(Clone)]
pub struct NodeMap {
    inner: Arc<RwLock<HashMap<String, NodeInfo>>>,
}

impl NodeMap {
    /// Create a new node map containing only our own entry.
    pub fn new(name: String, addr: EndpointAddr) -> Self {
        let mut map = HashMap::new();
        map.insert(name.clone(), NodeInfo { name, addr });
        Self {
            inner: Arc::new(RwLock::new(map)),
        }
    }

    /// Insert or update a node.
    pub async fn insert(&self, node: NodeInfo) {
        self.inner.write().await.insert(node.name.clone(), node);
    }

    /// Pick a random node, optionally excluding one by public key.
    pub async fn pick_random(&self, exclude: Option<&PublicKey>) -> Option<NodeInfo> {
        let map = self.inner.read().await;
        let candidates: Vec<_> = map
            .values()
            .filter(|n| exclude.is_none_or(|pk| n.addr.id != *pk))
            .collect();
        if candidates.is_empty() {
            None
        } else {
            let idx = rand::rng().random_range(0..candidates.len());
            Some(candidates[idx].clone())
        }
    }

    /// Get a node by name.
    pub async fn get(&self, name: &str) -> Option<NodeInfo> {
        self.inner.read().await.get(name).cloned()
    }

    /// Return all known nodes.
    pub async fn list(&self) -> Vec<NodeInfo> {
        self.inner.read().await.values().cloned().collect()
    }

    /// Collect gossip candidates: addresses from `initial_peers` (preferring
    /// richer info from the map) plus all other known nodes, excluding
    /// `own_name`.
    pub async fn gossip_candidates(
        &self,
        own_name: &str,
        initial_peers: &[PublicKey],
    ) -> Vec<EndpointAddr> {
        let map = self.inner.read().await;
        let mut addrs: Vec<EndpointAddr> = Vec::new();

        // Add initial peers, preferring their address from the map if available.
        for pk in initial_peers {
            let from_map = map.values().find(|n| n.addr.id == *pk);
            if let Some(node) = from_map {
                addrs.push(node.addr.clone());
            } else {
                addrs.push(EndpointAddr::new(*pk));
            }
        }

        // Add all other known nodes not already in the list.
        for node in map.values() {
            if node.name == own_name {
                continue;
            }
            if addrs.iter().any(|a| a.id == node.addr.id) {
                continue;
            }
            addrs.push(node.addr.clone());
        }

        addrs
    }
}
