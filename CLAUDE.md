# Dumbvpn

A CLI tool to create a dumb VPN over the network using iroh for NAT hole punching and end-to-end encryption. Think netcat but with QUIC, 256-bit endpoint IDs instead of IP addresses, and automatic relay fallback.

## Build & Dev

```bash
nix develop          # Enter dev shell (provides cargo, just, treefmt, etc.)
just build           # cargo build
just check           # cargo check
just test            # cargo test
just format          # treefmt (rustfmt + nixfmt)
just clippy          # cargo clippy --deny warnings
just clippy-fix      # auto-fix clippy issues
just final-check     # lint + clippy + test (PR readiness)
just typos           # spell check
```

## Project Structure

Single-crate Rust project (not a workspace):

- `src/main.rs` — CLI entry point, all subcommand handlers (~900 lines)
- `src/lib.rs` — Public exports: `ALPN`, `HANDSHAKE`, `EndpointTicket`
- `tests/cli.rs` — Integration tests that spawn actual dumbvpn binaries
- `flake.nix` — Nix flake with flakebox, crane builds, selfci integration
- `.config/selfci/` — Self-CI config and script
- `misc/git-hooks/` — Pre-commit (formatting, typos, semgrep) and commit-msg (conventional commits via convco)

## Architecture

- **Binary:** `dumbvpn` with subcommands: `listen`, `connect`, `listen-tcp`, `connect-tcp`, `listen-unix`, `connect-unix`, `generate-ticket`
- **Networking:** Uses `iroh::Endpoint` with N0 preset for QUIC connections, hole punching, relay fallback
- **Protocol:** Default ALPN `DUMBPIPEV0` with 5-byte `b"hello"` handshake; custom ALPNs skip handshake
- **I/O:** Bidirectional forwarding via `forward_bidi()` helper between noq streams and local I/O (stdin/stdout, TCP, Unix sockets)
- **Shutdown:** `CancellationToken` + `tokio::signal::ctrl_c()` for graceful cleanup

## Key Patterns

- `clap` derive macros for CLI parsing with `CommonArgs` shared across subcommands
- `n0_error::Result<T>` with `.anyerr()?` and `.std_context()` for error handling
- `tokio::select!` for concurrent async branches
- Environment variable `IROH_SECRET` for persistent endpoint identity (hex-encoded Ed25519 key)
- Environment variable `DUMBVPN_LOCAL_ONLY` disables relay and address lookup for sandboxed/offline testing
- Unix socket support is `#[cfg(unix)]`-gated

## Testing

Integration tests in `tests/cli.rs` use `duct` to spawn dumbvpn processes and verify data roundtrips through various forwarding modes. Tests set `DUMBVPN_LOCAL_ONLY=1` to avoid external network access (relay, DNS discovery), relying on localhost direct addresses in the ticket. Some tests are `#[ignore = "flaky"]` due to network timing. Tests use `nix::signal` for Ctrl-C simulation on Unix.

## CI

Selfci runs two parallel jobs: `lint` (treefmt check) and `cargo` (lock check, nix build, clippy, nextest).

## Formatting

Enforced via treefmt: `rustfmt` (edition 2024, grouped imports, wrapped comments) for Rust, `nixfmt` for Nix. See `.rustfmt.toml` and `.treefmt.toml`.
