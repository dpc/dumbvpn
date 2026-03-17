//! Command line arguments.
use std::io;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use clap::{Parser, Subcommand};
use dumbvpn::node_map::NodeMap;
use dumbvpn::rpc::{self, NetworkKey, RpcOutcome};
use iroh::endpoint::{presets, Accepting};
use iroh::{Endpoint, EndpointAddr, PublicKey, RelayMode, SecretKey};
use n0_error::{bail_any, AnyError, Result, StdResultExt};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::select;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

const ONLINE_TIMEOUT: Duration = Duration::from_secs(5);

/// Create a dumb pipe between two machines, using an iroh endpoint.
///
/// One side listens, the other side connects. Both sides are identified by a
/// 32 byte endpoint id.
///
/// Connecting to a endpoint id is independent of its IP address. Dumbvpn will
/// try to establish a direct connection even through NATs and firewalls. If
/// that fails, it will fall back to using a relay server.
///
/// For all subcommands, you can specify a secret key using the IROH_SECRET
/// environment variable. If you don't, a random one will be generated.
///
/// You can also specify a port for the endpoint. If you don't, a random one
/// will be chosen.
#[derive(Parser, Debug)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Listen on an endpoint and forward stdin/stdout to the first incoming
    /// bidi stream.
    ///
    /// Will print a endpoint ticket on stderr that can be used to connect.
    Listen(ListenArgs),

    /// Listen on an endpoint and forward incoming connections to the specified
    /// host and port. Every incoming bidi stream is forwarded to a new
    /// connection.
    ///
    /// Will print a endpoint ticket on stderr that can be used to connect.
    ///
    /// As far as the endpoint is concerned, this is listening. But it is
    /// connecting to a TCP socket for which you have to specify the host and
    /// port.
    ListenTcp(ListenTcpArgs),

    /// Connect to an endpoint, open a bidi stream, and forward stdin/stdout.
    ///
    /// A endpoint ticket is required to connect.
    Connect(ConnectArgs),

    /// Connect to an endpoint, open a bidi stream, and forward stdin/stdout
    /// to it.
    ///
    /// A endpoint ticket is required to connect.
    ///
    /// As far as the endpoint is concerned, this is connecting. But it is
    /// listening on a TCP socket for which you have to specify the interface
    /// and port.
    ConnectTcp(ConnectTcpArgs),

    #[cfg(unix)]
    /// Listen on an endpoint and forward incoming connections to the specified
    /// Unix socket path. Every incoming bidi stream is forwarded to a new
    /// connection.
    ///
    /// Will print a endpoint ticket on stderr that can be used to connect.
    ///
    /// As far as the endpoint is concerned, this is listening. But it is
    /// connecting to a Unix socket for which you have to specify the path.
    ListenUnix(ListenUnixArgs),

    #[cfg(unix)]
    /// Connect to an endpoint, open a bidi stream, and forward connections
    /// from the specified Unix socket path.
    ///
    /// A endpoint ticket is required to connect.
    ///
    /// As far as the endpoint is concerned, this is connecting. But it is
    /// listening on a Unix socket for which you have to specify the path.
    ConnectUnix(ConnectUnixArgs),

    /// Query a listening node for all known nodes in the network.
    ListNodes(ListNodesArgs),
}

#[derive(Parser, Debug)]
pub struct CommonArgs {
    /// The IPv4 address that the endpoint will listen on.
    ///
    /// If None, defaults to a random free port, but it can be useful to specify
    /// a fixed port, e.g. to configure a firewall rule.
    #[clap(long, default_value = None)]
    pub ipv4_addr: Option<SocketAddrV4>,

    /// The IPv6 address that the endpoint will listen on.
    ///
    /// If None, defaults to a random free port, but it can be useful to specify
    /// a fixed port, e.g. to configure a firewall rule.
    #[clap(long, default_value = None)]
    pub ipv6_addr: Option<SocketAddrV6>,

    /// The shared network secret for authentication.
    ///
    /// Both sides of a connection must use the same network secret.
    /// The secret is stretched using argon2id before use.
    #[clap(long, env = "DUMBVPN_NETWORK_SECRET")]
    pub network_secret: String,

    /// Write the bound port number to a file.
    ///
    /// Useful for scripting and testing where the port is assigned by the OS.
    #[clap(long)]
    pub port_path: Option<PathBuf>,

    /// Enable direct IP connections (exposes your IP address).
    /// By default, only relay connections are used for privacy.
    #[clap(long, env = "DUMBVPN_PUBLIC")]
    pub public: bool,

    /// The verbosity level. Repeat to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

/// Gossip-related arguments shared by all listen subcommands.
#[derive(Parser, Debug)]
pub struct GossipArgs {
    /// Name of this node. Defaults to hostname.
    #[clap(long)]
    pub node_name: Option<String>,

    /// Public key of a gossip peer. Repeatable.
    #[clap(long)]
    pub gossip_node: Vec<PublicKey>,
}

#[derive(Parser, Debug)]
pub struct ListenArgs {
    /// Immediately close our sending side, indicating that we will not transmit
    /// any data
    #[clap(long)]
    pub recv_only: bool,

    /// Exit after handling a single data connection.
    #[clap(long)]
    pub one_shot: bool,

    #[clap(flatten)]
    pub gossip: GossipArgs,

    #[clap(flatten)]
    pub common: CommonArgs,
}

#[derive(Parser, Debug)]
pub struct ListenTcpArgs {
    #[clap(long)]
    pub host: String,

    #[clap(flatten)]
    pub gossip: GossipArgs,

    #[clap(flatten)]
    pub common: CommonArgs,
}

#[derive(Parser, Debug)]
pub struct ConnectTcpArgs {
    /// The addresses to listen on for incoming tcp connections.
    ///
    /// To listen on all network interfaces, use 0.0.0.0:12345
    #[clap(long)]
    pub addr: String,

    /// The endpoint ID to connect to
    pub node_id: PublicKey,

    /// Direct IP address hint for the remote node. Repeatable.
    #[clap(long)]
    pub direct_addr: Vec<SocketAddr>,

    #[clap(flatten)]
    pub common: CommonArgs,
}

#[derive(Parser, Debug)]
pub struct ConnectArgs {
    /// The endpoint ID to connect to
    pub node_id: PublicKey,

    /// Direct IP address hint for the remote node. Repeatable.
    #[clap(long)]
    pub direct_addr: Vec<SocketAddr>,

    /// Immediately close our sending side, indicating that we will not transmit
    /// any data
    #[clap(long)]
    pub recv_only: bool,

    #[clap(flatten)]
    pub common: CommonArgs,
}

#[cfg(unix)]
#[derive(Parser, Debug)]
pub struct ListenUnixArgs {
    /// Path to the Unix socket to connect to
    #[clap(long)]
    pub socket_path: PathBuf,

    #[clap(flatten)]
    pub gossip: GossipArgs,

    #[clap(flatten)]
    pub common: CommonArgs,
}

#[cfg(unix)]
#[derive(Parser, Debug)]
pub struct ConnectUnixArgs {
    /// Path to the Unix socket to listen on
    #[clap(long)]
    pub socket_path: PathBuf,

    /// The endpoint ID to connect to
    pub node_id: PublicKey,

    /// Direct IP address hint for the remote node. Repeatable.
    #[clap(long)]
    pub direct_addr: Vec<SocketAddr>,

    #[clap(flatten)]
    pub common: CommonArgs,
}

#[derive(Parser, Debug)]
pub struct ListNodesArgs {
    /// The endpoint ID to query
    pub node_id: PublicKey,

    /// Direct IP address hint for the remote node. Repeatable.
    #[clap(long)]
    pub direct_addr: Vec<SocketAddr>,

    #[clap(flatten)]
    pub common: CommonArgs,
}

/// Build an `EndpointAddr` from a public key and optional direct address hints.
fn build_endpoint_addr(node_id: PublicKey, direct_addrs: &[SocketAddr]) -> EndpointAddr {
    let mut addr = EndpointAddr::new(node_id);
    for a in direct_addrs {
        addr = addr.with_ip_addr(*a);
    }
    addr
}

/// Copy from a reader to a noq stream.
///
/// Will send a reset to the other side if the operation is cancelled, and fail
/// with an error.
///
/// Returns the number of bytes copied in case of success.
async fn copy_to_noq(
    mut from: impl AsyncRead + Unpin,
    mut send: noq::SendStream,
    token: CancellationToken,
) -> io::Result<u64> {
    tracing::trace!("copying to noq");
    tokio::select! {
        res = tokio::io::copy(&mut from, &mut send) => {
            let size = res?;
            send.finish()?;
            Ok(size)
        }
        _ = token.cancelled() => {
            // send a reset to the other side immediately
            send.reset(0u8.into()).ok();
            Err(io::Error::other("cancelled"))
        }
    }
}

/// Copy from a noq stream to a writer.
///
/// Will send stop to the other side if the operation is cancelled, and fail
/// with an error.
///
/// Returns the number of bytes copied in case of success.
async fn copy_from_noq(
    mut recv: noq::RecvStream,
    mut to: impl AsyncWrite + Unpin,
    token: CancellationToken,
) -> io::Result<u64> {
    tokio::select! {
        res = tokio::io::copy(&mut recv, &mut to) => {
            Ok(res?)
        },
        _ = token.cancelled() => {
            recv.stop(0u8.into()).ok();
            Err(io::Error::other("cancelled"))
        }
    }
}

/// Get the secret key or generate a new one.
fn get_or_create_secret() -> Result<SecretKey> {
    match std::env::var("IROH_SECRET") {
        Ok(secret) => SecretKey::from_str(&secret).std_context("invalid secret"),
        Err(_) => Ok(SecretKey::generate(&mut rand::rng())),
    }
}

/// Whether to run in local-only mode, without relay or address lookup services.
///
/// This is useful for testing in sandboxed environments where no outgoing
/// network connections are allowed.
fn is_local_only() -> bool {
    std::env::var("DUMBVPN_LOCAL_ONLY").is_ok()
}

/// Create a new iroh endpoint.
async fn create_endpoint(
    secret_key: SecretKey,
    common: &CommonArgs,
    alpns: Vec<Vec<u8>>,
) -> Result<Endpoint> {
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(alpns);
    if is_local_only() {
        builder = builder
            .relay_mode(RelayMode::Disabled)
            .clear_address_lookup();
    }
    if !common.public {
        builder = builder.clear_ip_transports();
    }
    if let Some(addr) = common.ipv4_addr {
        builder = builder.bind_addr(addr)?;
    }
    if let Some(addr) = common.ipv6_addr {
        builder = builder.bind_addr(addr)?;
    }
    let endpoint = builder.bind().await.anyerr()?;
    if let Some(path) = &common.port_path {
        // Write the first bound port so tests/scripts can discover it.
        if let Some(addr) = endpoint.bound_sockets().first() {
            std::fs::write(path, addr.port().to_string()).std_context("writing port file")?;
        }
    }
    Ok(endpoint)
}

fn cancel_token<T>(token: CancellationToken) -> impl Fn(T) -> T {
    move |x| {
        token.cancel();
        x
    }
}

/// Bidirectionally forward data from a noq stream and an arbitrary tokio
/// reader/writer pair, aborting both sides when either one forwarder is done,
/// or when control-c is pressed.
async fn forward_bidi(
    from1: impl AsyncRead + Send + Sync + Unpin + 'static,
    to1: impl AsyncWrite + Send + Sync + Unpin + 'static,
    from2: noq::RecvStream,
    to2: noq::SendStream,
) -> Result<()> {
    let token1 = CancellationToken::new();
    let token2 = token1.clone();
    let token3 = token1.clone();
    let forward_from_stdin = tokio::spawn(async move {
        copy_to_noq(from1, to2, token1.clone())
            .await
            .map_err(cancel_token(token1))
    });
    let forward_to_stdout = tokio::spawn(async move {
        copy_from_noq(from2, to1, token2.clone())
            .await
            .map_err(cancel_token(token2))
    });
    let _control_c = tokio::spawn(async move {
        tokio::signal::ctrl_c().await?;
        token3.cancel();
        io::Result::Ok(())
    });
    forward_to_stdout.await.anyerr()?.anyerr()?;
    forward_from_stdin.await.anyerr()?.anyerr()?;
    Ok(())
}

/// Resolve the node name from args or hostname.
fn resolve_node_name(gossip: &GossipArgs) -> String {
    gossip.node_name.clone().unwrap_or_else(|| {
        hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string())
    })
}

async fn listen_stdio(args: ListenArgs) -> Result<()> {
    let secret_key = get_or_create_secret()?;
    let key = NetworkKey::from_passphrase(&args.common.network_secret);
    let endpoint = create_endpoint(secret_key, &args.common, vec![dumbvpn::ALPN.to_vec()]).await?;
    // wait for the endpoint to figure out its home relay and addresses before
    // making a ticket
    if !is_local_only() && (timeout(ONLINE_TIMEOUT, endpoint.online()).await).is_err() {
        eprintln!("Warning: Failed to connect to the home relay");
    }
    let addr = endpoint.addr();
    tracing::info!("node addr: {}", addr.id);

    let node_name = resolve_node_name(&args.gossip);
    let node_map = NodeMap::new(node_name.clone(), addr.id);
    let cancel = CancellationToken::new();

    // Spawn gossip loop.
    let _gossip_handle = tokio::spawn(dumbvpn::gossip::gossip_loop(
        endpoint.clone(),
        key,
        node_map.clone(),
        node_name,
        args.gossip.gossip_node.clone(),
        cancel.clone(),
    ));

    loop {
        let connecting = select! {
            connecting = endpoint.accept() => {
                let Some(connecting) = connecting else { break };
                connecting
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("got ctrl-c, exiting");
                break;
            }
        };
        let connection = match connecting.await {
            Ok(connection) => connection,
            Err(cause) => {
                tracing::warn!("error accepting connection: {}", cause);
                continue;
            }
        };
        let remote_endpoint_id = connection.remote_id();
        tracing::info!("got connection from {}", remote_endpoint_id);
        let (mut s, mut r) = match connection.accept_bi().await {
            Ok(x) => x,
            Err(cause) => {
                tracing::warn!("error accepting stream: {}", cause);
                continue;
            }
        };
        tracing::info!("accepted bidi stream from {}", remote_endpoint_id);
        let rpc_id = match rpc::auth_accept(&mut s, &mut r, &key).await {
            Ok(id) => id,
            Err(cause) => {
                tracing::warn!("auth failed from {}: {}", remote_endpoint_id, cause);
                continue;
            }
        };
        match rpc::dispatch_rpc(rpc_id, &mut s, &mut r, &node_map).await {
            Ok(RpcOutcome::Handled) => continue,
            Ok(RpcOutcome::DataForward) => {}
            Err(cause) => {
                tracing::warn!("RPC error from {}: {}", remote_endpoint_id, cause);
                continue;
            }
        }
        if args.recv_only {
            tracing::info!(
                "forwarding stdout to {} (ignoring stdin)",
                remote_endpoint_id
            );
            if let Err(e) = forward_bidi(tokio::io::empty(), tokio::io::stdout(), r, s).await {
                tracing::warn!("data forwarding error: {e}");
            }
        } else {
            tracing::info!("forwarding stdin/stdout to {}", remote_endpoint_id);
            if let Err(e) = forward_bidi(tokio::io::stdin(), tokio::io::stdout(), r, s).await {
                tracing::warn!("data forwarding error: {e}");
            }
        }
        if args.one_shot {
            break;
        }
    }
    cancel.cancel();
    Ok(())
}

async fn connect_stdio(args: ConnectArgs) -> Result<()> {
    let secret_key = get_or_create_secret()?;
    let key = NetworkKey::from_passphrase(&args.common.network_secret);
    let endpoint = create_endpoint(secret_key, &args.common, vec![]).await?;
    let addr = build_endpoint_addr(args.node_id, &args.direct_addr);
    let remote_endpoint_id = addr.id;
    // connect to the remote, try only once
    let connection = endpoint
        .connect(addr.clone(), dumbvpn::ALPN)
        .await
        .anyerr()?;
    tracing::info!("connected to {}", remote_endpoint_id);
    // open a bidi stream, try only once
    let (mut s, mut r) = connection.open_bi().await.anyerr()?;
    tracing::info!("opened bidi stream to {}", remote_endpoint_id);
    rpc::auth_connect(&mut s, &mut r, &key, rpc::RPC_DATA).await?;
    if args.recv_only {
        tracing::info!(
            "forwarding stdout to {} (ignoring stdin)",
            remote_endpoint_id
        );
        forward_bidi(tokio::io::empty(), tokio::io::stdout(), r, s).await?;
    } else {
        tracing::info!("forwarding stdin/stdout to {}", remote_endpoint_id);
        forward_bidi(tokio::io::stdin(), tokio::io::stdout(), r, s).await?;
    }
    tokio::io::stdout().flush().await.anyerr()?;
    Ok(())
}

/// Listen on a tcp port and forward incoming connections to an endpoint.
async fn connect_tcp(args: ConnectTcpArgs) -> Result<()> {
    let addrs = args
        .addr
        .to_socket_addrs()
        .std_context(format!("invalid host string {}", args.addr))?;
    let secret_key = get_or_create_secret()?;
    let endpoint = create_endpoint(secret_key, &args.common, vec![])
        .await
        .std_context("unable to bind endpoint")?;
    tracing::info!("tcp listening on {:?}", addrs);

    // Wait for our own endpoint to be ready before trying to connect.
    if !is_local_only() && (timeout(ONLINE_TIMEOUT, endpoint.online()).await).is_err() {
        eprintln!("Warning: Failed to connect to the home relay");
    }

    let tcp_listener = match tokio::net::TcpListener::bind(addrs.as_slice()).await {
        Ok(tcp_listener) => tcp_listener,
        Err(cause) => {
            tracing::error!("error binding tcp socket to {:?}: {}", addrs, cause);
            return Ok(());
        }
    };
    let key = NetworkKey::from_passphrase(&args.common.network_secret);
    async fn handle_tcp_accept(
        next: io::Result<(tokio::net::TcpStream, SocketAddr)>,
        addr: EndpointAddr,
        endpoint: Endpoint,
        key: NetworkKey,
    ) -> Result<()> {
        let (tcp_stream, tcp_addr) = next.std_context("error accepting tcp connection")?;
        let (tcp_recv, tcp_send) = tcp_stream.into_split();
        tracing::info!("got tcp connection from {}", tcp_addr);
        let remote_endpoint_id = addr.id;
        let connection = endpoint
            .connect(addr, dumbvpn::ALPN)
            .await
            .std_context(format!("error connecting to {remote_endpoint_id}"))?;
        let (mut endpoint_send, mut endpoint_recv) = connection
            .open_bi()
            .await
            .std_context(format!("error opening bidi stream to {remote_endpoint_id}"))?;
        rpc::auth_connect(&mut endpoint_send, &mut endpoint_recv, &key, rpc::RPC_DATA).await?;
        forward_bidi(tcp_recv, tcp_send, endpoint_recv, endpoint_send).await?;
        Ok::<_, AnyError>(())
    }
    let addr = build_endpoint_addr(args.node_id, &args.direct_addr);
    loop {
        // also wait for ctrl-c here so we can use it before accepting a connection
        let next = tokio::select! {
            stream = tcp_listener.accept() => stream,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("got ctrl-c, exiting");
                break;
            }
        };
        let endpoint = endpoint.clone();
        let addr = addr.clone();
        tokio::spawn(async move {
            if let Err(cause) = handle_tcp_accept(next, addr, endpoint, key).await {
                // log error at warn level
                //
                // we should know about it, but it's not fatal
                tracing::warn!("error handling connection: {}", cause);
            }
        });
    }
    Ok(())
}

/// Listen on an endpoint and forward incoming connections to a tcp socket.
async fn listen_tcp(args: ListenTcpArgs) -> Result<()> {
    let addrs = match args.host.to_socket_addrs() {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(e) => bail_any!("invalid host string {}: {}", args.host, e),
    };
    let secret_key = get_or_create_secret()?;
    let key = NetworkKey::from_passphrase(&args.common.network_secret);
    let endpoint = create_endpoint(secret_key, &args.common, vec![dumbvpn::ALPN.to_vec()]).await?;
    // wait for the endpoint to figure out its address before making a ticket
    if !is_local_only() && (timeout(ONLINE_TIMEOUT, endpoint.online()).await).is_err() {
        eprintln!("Warning: Failed to connect to the home relay");
    }
    let addr = endpoint.addr();
    tracing::info!("node addr: {}", addr.id);

    let node_name = resolve_node_name(&args.gossip);
    let node_map = NodeMap::new(node_name.clone(), addr.id);
    let cancel = CancellationToken::new();

    // Spawn gossip loop.
    let _gossip_handle = tokio::spawn(dumbvpn::gossip::gossip_loop(
        endpoint.clone(),
        key,
        node_map.clone(),
        node_name,
        args.gossip.gossip_node.clone(),
        cancel.clone(),
    ));

    // handle a new incoming connection on the endpoint
    async fn handle_endpoint_accept(
        accepting: Accepting,
        addrs: Vec<std::net::SocketAddr>,
        key: NetworkKey,
        node_map: NodeMap,
    ) -> Result<()> {
        let connection = accepting.await.std_context("error accepting connection")?;
        let remote_endpoint_id = &connection.remote_id();
        tracing::info!("got connection from {}", remote_endpoint_id);
        let (mut s, mut r) = connection
            .accept_bi()
            .await
            .std_context("error accepting stream")?;
        tracing::info!("accepted bidi stream from {}", remote_endpoint_id);
        let rpc_id = rpc::auth_accept(&mut s, &mut r, &key).await?;
        match rpc::dispatch_rpc(rpc_id, &mut s, &mut r, &node_map).await? {
            RpcOutcome::Handled => return Ok(()),
            RpcOutcome::DataForward => {}
        }
        let connection = tokio::net::TcpStream::connect(addrs.as_slice())
            .await
            .std_context(format!("error connecting to {addrs:?}"))?;
        let (read, write) = connection.into_split();
        forward_bidi(read, write, r, s).await?;
        Ok(())
    }

    loop {
        let incoming = select! {
            incoming = endpoint.accept() => incoming,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("got ctrl-c, exiting");
                break;
            }
        };
        let Some(incoming) = incoming else {
            break;
        };
        let Ok(connecting) = incoming.accept() else {
            break;
        };
        let addrs = addrs.clone();
        let node_map = node_map.clone();
        tokio::spawn(async move {
            if let Err(cause) = handle_endpoint_accept(connecting, addrs, key, node_map).await {
                // log error at warn level
                //
                // we should know about it, but it's not fatal
                tracing::warn!("error handling connection: {}", cause);
            }
        });
    }
    cancel.cancel();
    Ok(())
}

#[cfg(unix)]
/// Listen on an endpoint and forward incoming connections to a Unix socket.
async fn listen_unix(args: ListenUnixArgs) -> Result<()> {
    let socket_path = args.socket_path.clone();
    let secret_key = get_or_create_secret()?;
    let key = NetworkKey::from_passphrase(&args.common.network_secret);
    let endpoint = create_endpoint(secret_key, &args.common, vec![dumbvpn::ALPN.to_vec()]).await?;
    // wait for the endpoint to figure out its address before making a ticket
    if !is_local_only() && (timeout(ONLINE_TIMEOUT, endpoint.online()).await).is_err() {
        eprintln!("Warning: Failed to connect to the home relay");
    }
    let addr = endpoint.addr();
    tracing::info!("node addr: {}", addr.id);

    let node_name = resolve_node_name(&args.gossip);
    let node_map = NodeMap::new(node_name.clone(), addr.id);
    let cancel = CancellationToken::new();

    // Spawn gossip loop.
    let _gossip_handle = tokio::spawn(dumbvpn::gossip::gossip_loop(
        endpoint.clone(),
        key,
        node_map.clone(),
        node_name,
        args.gossip.gossip_node.clone(),
        cancel.clone(),
    ));

    // handle a new incoming connection on the endpoint
    async fn handle_endpoint_accept(
        accepting: Accepting,
        socket_path: PathBuf,
        key: NetworkKey,
        node_map: NodeMap,
    ) -> Result<()> {
        tracing::trace!("accepting connection");
        let connection = accepting.await.std_context("error accepting connection")?;
        let remote_endpoint_id = &connection.remote_id();
        tracing::info!("got connection from {}", remote_endpoint_id);
        let (mut s, mut r) = connection
            .accept_bi()
            .await
            .std_context("error accepting stream")?;
        tracing::info!("accepted bidi stream from {}", remote_endpoint_id);
        let rpc_id = rpc::auth_accept(&mut s, &mut r, &key).await?;
        match rpc::dispatch_rpc(rpc_id, &mut s, &mut r, &node_map).await? {
            RpcOutcome::Handled => return Ok(()),
            RpcOutcome::DataForward => {}
        }
        tracing::trace!("connecting to backend socket {:?}", socket_path);
        let connection = UnixStream::connect(&socket_path)
            .await
            .std_context(format!("error connecting to {socket_path:?}"))?;
        tracing::trace!("connected to backend socket");
        let (read, write) = connection.into_split();
        tracing::trace!("starting forward_bidi");
        forward_bidi(read, write, r, s).await?;
        tracing::trace!("forward_bidi finished");
        Ok(())
    }

    loop {
        let incoming = select! {
            incoming = endpoint.accept() => incoming,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("got ctrl-c, exiting");
                break;
            }
        };
        let Some(incoming) = incoming else {
            break;
        };
        let Ok(connecting) = incoming.accept() else {
            break;
        };
        let socket_path = socket_path.clone();
        let node_map = node_map.clone();
        tokio::spawn(async move {
            if let Err(cause) = handle_endpoint_accept(connecting, socket_path, key, node_map).await
            {
                // log error at warn level
                //
                // we should know about it, but it's not fatal
                tracing::warn!("error handling connection: {}", cause);
            }
        });
    }
    cancel.cancel();
    Ok(())
}

#[cfg(unix)]
/// A RAII guard to clean up a Unix socket file.
struct UnixSocketGuard {
    path: PathBuf,
}

#[cfg(unix)]
impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::error!("failed to remove socket file {:?}: {}", self.path, e);
            }
        }
    }
}

#[cfg(unix)]
/// Listen on a Unix socket and forward connections to an endpoint.
async fn connect_unix(args: ConnectUnixArgs) -> Result<()> {
    let socket_path = args.socket_path.clone();
    let secret_key = get_or_create_secret()?;
    let key = NetworkKey::from_passphrase(&args.common.network_secret);
    let endpoint = create_endpoint(secret_key, &args.common, vec![])
        .await
        .std_context("unable to bind endpoint")?;
    tracing::info!("unix listening on {:?}", socket_path);

    // Wait for our own endpoint to be ready before trying to connect.
    if !is_local_only() && (timeout(ONLINE_TIMEOUT, endpoint.online()).await).is_err() {
        eprintln!("Warning: Failed to connect to the home relay");
    }

    // Remove existing socket file if it exists
    if let Err(e) = tokio::fs::remove_file(&socket_path).await {
        if e.kind() != io::ErrorKind::NotFound {
            bail_any!("failed to remove existing socket file: {}", e);
        }
    }

    let addr = build_endpoint_addr(args.node_id, &args.direct_addr);
    tracing::info!("connecting to remote endpoint: {:?}", addr);
    let connection = endpoint
        .connect(addr.clone(), dumbvpn::ALPN)
        .await
        .std_context("failed to connect to remote endpoint")?;
    tracing::info!("connected to remote endpoint successfully");

    let unix_listener = UnixListener::bind(&socket_path)
        .with_std_context(|_| format!("failed to bind Unix socket at {socket_path:?}"))?;
    tracing::info!("bound local unix socket: {:?}", socket_path);

    let _guard = UnixSocketGuard {
        path: socket_path.clone(),
    };

    async fn handle_unix_accept(
        next: io::Result<(UnixStream, tokio::net::unix::SocketAddr)>,
        connection: iroh::endpoint::Connection,
        key: NetworkKey,
    ) -> Result<()> {
        tracing::trace!("handling new local connection");
        let (unix_stream, unix_addr) = next.std_context("error accepting unix connection")?;
        let (unix_recv, unix_send) = unix_stream.into_split();
        tracing::trace!("got unix connection from {:?}", unix_addr);

        tracing::trace!("opening bidi stream");
        let (mut endpoint_send, mut endpoint_recv) = connection
            .open_bi()
            .await
            .std_context("error opening bidi stream")?;
        tracing::trace!("bidi stream opened");
        rpc::auth_connect(&mut endpoint_send, &mut endpoint_recv, &key, rpc::RPC_DATA).await?;

        tracing::trace!("starting forward_bidi");
        forward_bidi(unix_recv, unix_send, endpoint_recv, endpoint_send).await?;
        tracing::trace!("forward_bidi finished");
        Ok(())
    }

    tracing::info!("entering accept loop");
    loop {
        // also wait for ctrl-c here so we can use it before accepting a connection
        let next = tokio::select! {
            stream = unix_listener.accept() => stream,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("got ctrl-c, exiting");
                break;
            }
        };
        tracing::trace!("accepted a local connection");
        let connection = connection.clone();
        tokio::spawn(async move {
            tracing::trace!("spawning handler task");
            if let Err(cause) = handle_unix_accept(next, connection, key).await {
                // log error at warn level
                //
                // we should know about it, but it's not fatal
                tracing::warn!("error handling connection: {}", cause);
            }
            tracing::trace!("handler task finished");
        });
    }

    Ok(())
}

async fn list_nodes(args: ListNodesArgs) -> Result<()> {
    let secret_key = get_or_create_secret()?;
    let key = NetworkKey::from_passphrase(&args.common.network_secret);
    let endpoint = create_endpoint(secret_key, &args.common, vec![]).await?;
    let addr = build_endpoint_addr(args.node_id, &args.direct_addr);

    let connection = endpoint.connect(addr, dumbvpn::ALPN).await.anyerr()?;
    tracing::info!("connected to {}", args.node_id);

    let (mut s, mut r) = connection.open_bi().await.anyerr()?;
    rpc::auth_connect(&mut s, &mut r, &key, rpc::RPC_LIST_NODES).await?;

    let resp_data = rpc::read_frame(&mut r, 1024 * 1024).await?;
    let resp: rpc::ListNodesResponse =
        postcard::from_bytes(&resp_data).map_err(|e| AnyError::from(e.to_string()))?;

    for node in &resp.nodes {
        println!("{}\t{}", node.name, node.id);
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    let res = match args.command {
        Commands::Listen(args) => listen_stdio(args).await,
        Commands::ListenTcp(args) => listen_tcp(args).await,
        Commands::Connect(args) => connect_stdio(args).await,
        Commands::ConnectTcp(args) => connect_tcp(args).await,

        #[cfg(unix)]
        Commands::ListenUnix(args) => listen_unix(args).await,

        #[cfg(unix)]
        Commands::ConnectUnix(args) => connect_unix(args).await,

        Commands::ListNodes(args) => list_nodes(args).await,
    };
    match res {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1)
        }
    }
}
