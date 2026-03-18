# Dumb VPN


[Iroh](https://crates.io/crates/iroh) based simple VPN system.

Allows exposing tcp/unix sockets as Iroh endpoints, and connect
to them p2p.

Features:

* p2p (hole punching & NAT traversal or relay-based connectivity)
* shared secret based network security
* persistent or ephemeral identities
* simple gossip-based host discoverability
* public (direct IP) vs private (Iroh relays only) connectivity mode

# Example

Expose ssh port on a server machine:

```
> dumbvpn listen tcp --network-secret xyzlongsecret --host localhost:22
# will print:
2026-03-18T03:16:54.996877Z  INFO dumbvpn: node addr: 8d3d8f2fe27fa9cb5e197b9cd3705013ffd75f9d21f2d88fcf48b8b6b87d4cf8
```

Node addr is ephemeral, unless you use `--iroh-secret`.

Connect and bind locally on a different system:

```
> dumbvpn connect tcp --network-secret xyzlongsecret --bind localhost:2346 8d3d8f2fe27fa9cb5e197b9cd3705013ffd75f9d21f2d88fcf48b8b6b87d4cf8
```

Advertise current node addr via gossip to another instance:

```
> dumbvpn listen tcp --network-secret xyzlongsecret --host localhost:22 --gossip-node 8d3d8f2fe27fa9cb5e197b9cd3705013ffd75f9d21f2d88fcf48b8b6b87d4cf8 --node-name somename
```

Ask given node for known instances:

```
> dumbvpn list nodes --network-secret xyzlongsecret 8d3d8f2fe27fa9cb5e197b9cd3705013ffd75f9d21f2d88fcf48b8b6b87d4cf8
# will print:
foo      8d3d8f2fe27fa9cb5e197b9cd3705013ffd75f9d21f2d88fcf48b8b6b87d4cf8
somename 9cb5e197b9cd3f9d21f2d88fcf48b8b6b87d4cfa705013ffd758d3d8f2fe27fa
```

## AI usage disclosure

[I use LLMs when working on my projects.](https://dpc.pw/posts/personal-ai-usage-disclosure/)
