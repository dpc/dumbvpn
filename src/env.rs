/// Hex-encoded Ed25519 secret key for persistent endpoint identity.
pub const IROH_SECRET: &str = "DUMBVPN_IROH_SECRET";

/// Shared network secret for authentication (stretched with argon2id).
pub const NETWORK_SECRET: &str = "DUMBVPN_NETWORK_SECRET";

/// When set, enables direct IP connections (exposes your IP address).
pub const PUBLIC: &str = "DUMBVPN_PUBLIC";

/// When set, disables relay and address lookup (for sandboxed testing).
pub const LOCAL_ONLY: &str = "DUMBVPN_LOCAL_ONLY";
