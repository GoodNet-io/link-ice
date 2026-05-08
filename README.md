# goodnet-link-ice

ICE NAT-traversal link for GoodNet. Implements the controlled /
controlling agent state machine from RFC 8445, the STUN binding /
integrity attributes from RFC 5389, and the TURN allocation slice
from RFC 5766. Maps `ice://<peer-pk-hex>` URIs to per-peer ICE
sessions, gathers host / server-reflexive / relay candidates, runs
prioritised connectivity checks, and surfaces post-nomination
bytes through `host_api->notify_inbound_bytes`.

ICE has no listening port — candidates ride out-of-band through the
peer-to-peer `gn.link.ice.signal` extension. A signaling handler
(heartbeat, a future signaling channel, or a bridge) calls
`offer(peer_pk, blob)` / `answer(peer_pk, blob)` to deliver
serialized candidate sets; the link maps `peer_pk` onto an
`IceSession` and feeds the FSM.

**Kind**: link · **Artefact**: dynamic plugin (`.so` via dlopen)
· **License**: GPL-2.0 with Linking Exception (see `LICENSE`)

## Build

This plugin lives in its own git with a flake that pulls the
kernel SDK as a Nix input. From this checkout:

```sh
nix run .#build         # release build of libgoodnet_link_ice.so
nix run .#test          # vanilla ctest (FSM, STUN, TURN parsing)
nix run .#test-asan     # AddressSanitizer + UBSan
nix run .#test-tsan     # ThreadSanitizer
```

The kernel monorepo also builds this plugin in-tree through its
own `nix run .#build -- release` — operator install consumes
every bundled `.so` from there.

## Configuration

| Key | Type | Default | Notes |
|---|---|---|---|
| `ice.stun_servers` | array of string | `["stun.l.google.com:19302"]` | `host:port` entries; reload-friendly |
| `ice.turn_servers` | string | `""` | single `host:port`; multi-server fallback is v1.1 |
| `ice.turn_username` | string | `""` | TURN long-term credential |
| `ice.turn_password` | string | `""` | TURN long-term credential |
| `ice.session_timeout_s` | int64 | `10` | gather + checks deadline |
| `ice.keepalive_interval_s` | int64 | `20` | consent-freshness probe period |
| `ice.consent_max_failures` | int64 | `3` | missed probes before recovery |
| `ice.check_interval_ms` | int64 | `50` | per-pair check pacing |

## Contract

- Kernel-side link contract: `docs/contracts/link.en.md`
- ICE wire candidates: `candidate.hpp::CandidateWire` (24 bytes)
  and `IceSignalData` (44 bytes). Stable for interop with bridges.
