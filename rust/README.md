# StalkNet — Rust + Tauri rewrite

A faithful rewrite of StalkNet (originally C# / .NET Framework 4.8 / WPF, in
`../src`) to Rust with a Tauri window. It lives beside the original; the C#
tree is left untouched. The goal is wire compatibility: a Rust node and a C#
node speak the same network, so every byte format, order and cryptographic
construction is kept identical and checked against the standards' test vectors.

The network is cross-platform — it builds and runs on **Windows, Linux and
macOS**. The core depends only on portable crates and `std`; the few
Windows-only conveniences from the C# version sit behind `cfg(windows)` with a
portable fallback or a graceful no-op elsewhere.

## Layout

```
rust/
  Cargo.toml        workspace; pins the crate versions, vendored for offline builds
  core/             stalknet-core — the library (a port of src/StalkNet.Core)
  src-tauri/        the window (a port of src/StalkNet.Client) — not yet scaffolded
  ui/               static HTML/JS/CSS front end (no Node/npm) — not yet scaffolded
```

Crypto is not hand-rolled (the C# version had to be, as .NET 4.8 ships none of
these). The rewrite uses the reviewed RustCrypto crates — `blake2`, `sha2`,
`hmac`, `hkdf`, `aes`, `argon2`, `p256` — each RFC-compliant, so the bytes on
the wire match the C# node.

## core — what is ported so far

Ported bottom-up; every module below compiles and is covered by unit tests
(RFC / known-answer vectors where they exist). `cargo test -p stalknet-core`.

- `util/base32` — RFC 4648 lower-case, unpadded Base32 (addresses).
- `crypto/` — the whole cryptographic base:
  - `blake2b` (RFC 7693), `hkdf` (HKDF-SHA256, RFC 5869), `rand` (the one source
    of OS randomness, unbiased range, weighted pick, constant-time compare),
  - `ctr_stream` (AES-256-CTR keystream), `chaining_mac` (chained HMAC-SHA256
    integrity), `aead_aes_ctr_hmac` (encrypt-then-MAC AEAD),
  - `argon2id` (RFC 9106, memory-hard KDF / proof of work),
  - `ecc_p256` (ECDSA + ECDH over P-256; keys travel raw as `X‖Y` / `X‖Y‖d`; the
    ECDH secret is `SHA-256(x)`, matching the C# CNG agreement).
- `identity/` — `onion_address` (`…​.stalknet` address from the signing key),
  `sybil_proof` (Argon2id proof of work), `node_identity` (the signing + onion
  keys; reads and writes `node.id` in the same sealed format, passphrase via
  Argon2id or — on Windows — the account via DPAPI, tags `ONID`/`ONIW`).
- `directory/` — `relay_descriptor` (the signed relay card with its pass, same
  wire format), `relay_list`, `relay_reputation` (a private, machine-local tally
  with decay and a blackout), `path_selector` (guard + middle + exit, distinct
  /16 subnets, weighted by reputation).
- `protocol/` — `cell` (the fixed 514-byte cell), `relay_cell` (the 509-byte
  payload layout), `relay_digest` (in-cell integrity tag), `hop_keys`,
  `ntor` (the ntor handshake on P-256), `extend_payload`, `relay_hop` (a relay's
  single layer), `client_circuit` (the client's onion: wrap/unwrap across hops).
- `transport/` — `link_crypto` (per-link encryption, the 530-byte frame),
  `service_context`, `cell_channel` (the TCP link and its handshake), `circuit`
  (the client's circuit builder), `relay_node` (a node others' circuits pass
  through: accept threads, circuit tables, Create/Extend/Relay/Destroy).
- `streams/` — `stream_payloads` (the reserved virtual ports), `channel_limits`,
  `exit_policy` (own-network rule + destination rules), `multiplexed_circuit`,
  `exit_tunnel` (self-rebuilding), `socks_proxy` (SOCKS5 at 127.0.0.1),
  `local_port_forwarder`, `port_stack`, `tcp_port_service`.
- `nat/` — NAT-PMP then UPnP port forwarding; cross-platform (gateway via the OS
  routing table). One live-network test is `#[ignore]`d.
- `discovery/` — `bencode`, `mainline_dht` (BitTorrent DHT), `peer_finder`. The
  network is an internet one only: there is no home-network discovery.
- `peers/` — the master-less network: `peer_view` (`node.peers`), `placement`
  (XOR-closest keepers), `peer_protocol`, `peer_service` (the desk), `peer_client`,
  `relay_pass` (`node.pass`), `holder_proof` (a holder's signed word).
- `hidden/` — hidden services end to end: `service_descriptor`, `hidden_protocol`,
  `e2e_session`/`e2e_channel`, `circuit_factory`, `intro_point_service`,
  `rendezvous_service`, `hidden_mux`, `hidden_connection`, `hidden_service`,
  `hidden_service_client`.
- `sharing/` — shared folders: `folder_protocol`, `shared_folder`, `share_catalog`,
  `folder_service`, `folder_client`, `login_proof`, `account_authenticator` (the
  owner's guest accounts, kept as salted Argon2id hashes; a Windows account
  backend behind `windows_logon`), `account_store` (`node.accounts`),
  `windows_share_reader` / `explorer_integration` (Windows-only, feature-gated).
- `swarm/` — encrypted torrents and sites: `bundle_*`, `swarm_store`,
  `swarm_protocol`/`swarm_service`/`swarm_download`, `site_record`,
  `local_site_server`, `exit_service` (the anonymous exit).
- `text/` — the window's English strings (`loc`, `strings_en`), key for key.
- `runtime/` — `node`: the whole node assembled (a port of `NodeController`) —
  identity, the relay, the role choice, joining by discovery and gossip,
  records with their keepers, the folders' hidden service, the SOCKS way out,
  guest accounts. `node_swarm`: torrents, sites and the anonymous exit, each
  under a hidden address of its own.

## The window

`src-tauri/` is the Tauri app (`stalknet` binary) over `stalknet_core::runtime`;
`ui/` is the static front end (no Node/npm). Commands: open/create identity,
start/stop the node, reconnect, start a hidden service, open the SOCKS way out,
folders, ports, torrents, read the status and the log. Every command is
`#[tauri::command(async)]`: a plain one runs on the window's own thread, and any
wait in it freezes the window.

## Status

The whole of `StalkNet.Core` is ported. `cargo test -p stalknet-core` is green
(220+ tests, RFC/known-answer vectors for every primitive); the window builds.
The Windows-only conveniences (identity sealed by the account, SMB share
reading, the Explorer menu) are behind cargo features that are off by default,
so the build and the network are cross-platform.

`runtime::Node` covers the whole C# `NodeController`, `Auto` and `Swarm` parts
included: the role choice (a node nobody outside can reach uses the network as
a client), the folders' hidden address raised by itself, torrents and sites
handed out under an address of their own, the anonymous exit, guest accounts.

### Anonymity

- Folders and offered ports sit on a private port stack reachable only through
  the folders' hidden address — never through the relay, whose card carries
  its IP.
- Keepers (announcements, holders, sites) are reached only over circuits of at
  least two hops; a direct link is used for trading relay cards only.
- Every circuit starts at one long-lived guard (`node.guard`); relays of one
  /16 never share a circuit (except on one machine, for tests).
- The way out moves new connections to a fresh tunnel every ten minutes; old
  tunnels live on for the connections still on them.
- Bundles, the anonymous exit and sites are handed out under addresses made for
  them, never under the relay or the folders' address.

### Floods

- `peers/store_pass`: a place at the keepers costs a proof of work over the key's
  fingerprint (10 bits, seconds, once per key; a keeper checks it once per key).
  Required for service announcements, site records and holders.
- A full keeper drops the record renewed longest ago instead of refusing new ones.
- An introduction point passes at most 30 invitations a minute per service; a
  service sets up at most 8 meetings at once.

### Forgeries

Cards, announcements, site records and holders are all signed; nothing is taken
on a bare fingerprint. Bundles are checked piece by piece against their hashes.

### Wire changes from the C# node (Rust and C# nodes no longer agree on these)

- Establish at an introduction point: signed over the key, that point's
  fingerprint and the time (`stalknet-establish-intro-v2`, ±10 minutes) — a
  point that saw it cannot register the service elsewhere.
- Site records carry the owner's key and an outer signature
  (`stalknet-site-record-v2`): nobody can file a record under another's address,
  not even first.
- A holder's announcement is its signed word (`holder_proof`, with its paid
  place), not a bare fingerprint; service announcements and site records carry
  a paid place too (`store_pass`).
- A relay's pass is 14 bits (C#: 10): minutes once per key, and the same for
  every fake relay somebody would raise.

### What no network of this kind removes

Whoever watches both ends of a circuit at once can match them by timing; an
exit sees what is not encrypted end to end (use HTTPS); a new node's first
relays come from the torrent network, where somebody with many relays (each
paying its pass) could be most of what it finds; the identity file is kept
without a passphrase, as asked.

## Build

```
cd rust
cargo test -p stalknet-core     # the core library and its tests
cargo build                     # the whole workspace, incl. the window
cargo run -p stalknet-app       # open the window

# two nodes on this machine trade cards (~10 s)
cargo test --release -p stalknet-core -- --ignored two_nodes_find_each_other
# three nodes: a bundle, a site and a folder by account, all for real (~90 s)
cargo test --release -p stalknet-core -- --ignored network_end_to_end
```

With `STALKNET_TEST_AUTOSTART=1` set, the window signs in and joins the network
by itself 1.5 s after it opens — for checking that it stays responsive while
joining, without anyone pressing START.

Run only one `cargo` build at a time against this workspace — two at once collide
on the Windows linker's output file.
