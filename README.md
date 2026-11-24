# StalkNet

An anonymous network with onion routing of its own. Traffic goes through a circuit of relays, each of which knows
only its neighbours; inside the network live hidden services, shared folders, torrents and sites at addresses that
cannot be forged. Written in Rust with a Tauri window; runs on Windows, Linux and macOS.

The network has no master: no directory, no voting, no invitations. Every relay signs its own card and attaches a
proof of work to it. Nodes find each other in the BitTorrent DHT and from the cards kept since the last start, then
trade cards. Records somebody has to keep — hidden service announcements, who seeds what, site records — are kept
by the three relays closest to the record's key.

## Download and run

Take the file for your system from the [latest release](https://github.com/AkaTorich/StalkNet/releases/latest):

| System  | File                                | How to start                                                        |
|---------|-------------------------------------|---------------------------------------------------------------------|
| Windows | `StalkNet-windows-x64.exe`          | Run it. Windows 10/11 have the WebView2 runtime it needs.           |
| Linux   | `StalkNet-linux-x64.AppImage`       | `chmod +x StalkNet-linux-x64.AppImage` and run it.                  |
| Linux   | `StalkNet-linux-x64.deb`            | `sudo apt install ./StalkNet-linux-x64.deb`, then `stalknet`.       |
| macOS   | `StalkNet-macos-universal.dmg`      | Open, drag StalkNet to Applications. Intel and Apple silicon.       |
| macOS   | `StalkNet-macos-universal.app.zip`  | The same application, unzipped in place.                            |

The builds are not signed. Windows may show SmartScreen ("More info" → "Run anyway"); macOS may refuse the first
start — right-click the app → Open, or `xattr -dr com.apple.quarantine /Applications/StalkNet.app`.

On the first start the node makes its identity by itself — nothing to type — and a relay counts its proof of work
once (about two minutes, in the background).

## The window

**IDENTITY** — the identity file and your folders' address (`….stalknet`). NODE: the public address and port
others reach the node at, port forwarding on the router (UPnP / NAT-PMP), whether to relay traffic for others,
whether to let traffic out to the internet. START joins the network; STOP leaves it. A node nobody outside can
reach does not relay: it uses the network as a client.

**NETWORK** — the network's name (nodes under one name find each other) and RECONNECT. HIDDEN SERVICE: the folders'
address (it comes up by itself once there are other relays). WAY OUT: a SOCKS5 proxy on 127.0.0.1 (9150 by default)
for a browser or any program — traffic leaves through three relays; the circuit changes every ten minutes. Only
nodes that let others out get a way out: tick "Allow exit traffic". ANONYMOUS EXIT: let others out from this machine
behind an address made for it.

**RELAYS** — the relays the node knows. Tick one to trust it as an exit: then the way out leaves only through the
ticked ones.

**FOLDERS** — folders you share. A public folder is read-only and open to anyone with your address; any other needs
a sign-in. GUEST ACCOUNTS: the names and passwords guests sign in with (kept only as salted hashes).

**REMOTE** — someone else's folders by their address: OPEN, LOGIN if needed, list the files, download.

**PORTS** — offer a local port (a web server, a game, SSH) under your address, or bring a port behind someone's
address to this machine.

**TORRENT** — SHARE a file or folder: you get a link; whoever has it can download. DOWNLOAD by a link into a folder.
BUNDLES: what was shared and fetched. MY SITE: publish a folder (with an `index.html`) as the site at your address.
OPEN A SITE: by its address; BROWSER shows it.

**LOG** — what the node is doing.

## Files

Everything lives in one folder: `%APPDATA%\StalkNet` on Windows, `~/.stalknet` on Linux and macOS.

| File           | What it holds                                                    |
|----------------|------------------------------------------------------------------|
| `node.id`      | the node's keys                                                  |
| `node.folder`  | the key of your folders' address                                 |
| `node.pass`    | the relay's proof of work, counted once                          |
| `node.peers`   | the relays' cards kept between starts                            |
| `node.guard`   | the relay every circuit starts at                                |
| `node.accounts`| guest accounts: names and salted Argon2id hashes, no passwords   |
| `node.swarm/`  | torrents, sites                                                  |

## What is protected

- Your folders and offered ports are reachable only through your hidden address, never through your relay (a
  relay's card carries its IP).
- Torrents, sites and the anonymous exit are handed out under addresses made for them.
- Nobody learns what you look up: requests to the record keepers always go through a circuit.
- Every circuit starts at one long-lived guard; two relays of one /16 network never share a circuit.
- Cards, announcements, site records and torrent holders are signed; nobody can take your site's address or set
  you down as the holder of something. Torrents are checked piece by piece against their hashes.
- A place at the record keepers is paid for once per key with a proof of work (seconds); a thousand rubbish keys
  cost a thousand times that. When a keeper is full, the record renewed longest ago goes — live ones renew all the
  time. An introduction point passes at most 30 invitations a minute to one service, and a service sets up at most
  8 meetings at once, so a flood of invitations cannot bring it down.

What no network of this kind removes (Tor included): somebody watching both ends of a circuit at once can match
them by timing; an exit sees what is not encrypted end to end — open sites over HTTPS; a new node's first relays come
from the torrent network. The identity file is kept without a passphrase, guarded by the folder's permissions — as
in Tor.

## Build from source

The code is in `rust/` (details in `rust/README.md`). With Rust installed (and on Linux
`libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev`):

```
cd rust
cargo test --release -p stalknet-core     # the core and its tests
cargo build --release                     # the window: target/release/stalknet
```

A tag `v*` builds the release on all three systems (`.github/workflows/release.yml`), each after the core's tests
and two network tests pass on it.

## License

GNU General Public License v3.0 — see `LICENSE`.
