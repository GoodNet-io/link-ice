# Changelog — goodnet-link-ice

All notable changes to this plugin are listed here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions track the kernel ABI through `gn_link_vtable_t` /
`gn.link.ice.signal` / `gn.link.ice.path_mtu`.

## [Unreleased]

### `dns_ext_client`: drop duplicate URI parser

`parse_service_uri` now thin-wraps `gn::parse_uri` from
`sdk/cpp/uri.hpp`. The `//` + userinfo bug found earlier is no
longer reachable from ICE; future URI parsing fixes land once in
the SDK and propagate to every transport plugin at once. The
wrapper still owns the RFC 7064 `stun:host` no-slash shape, the
RFC 7065 `user[:pass]@` userinfo strip, and the SRV-expansion
"no port" branch — everything else (control-byte gate, host:port
split, port-range and trailing-garbage rejection) defers to the
SDK parser.

### `stun://` / `turn://` URI form accepted in `ice.stun_servers` / `ice.turn_servers`

`parse_service_uri` rejected the colloquial `stun://host:port` and
`turn://user:pass@host:port` URI shapes — the parser pinned the
RFC 7064 canonical `stun:host[:port]` form, treating the optional
`//` authority delimiter as part of the hostname. Every operator
config that emitted the WebRTC `RTCIceServer.urls`-style URI fed
the `gather` path a malformed hostname (`//10.10.0.10`) on which
`ensure_remote_cid` returned 0; `start_multi_stun_probes` saw an
empty pending-probe set and fast-completed the gather without an
`srflx` candidate. The session then advertised host-only
candidates, the responder's check ladder saw exactly one
host-to-host pair across NAT'd subnets, and `run_next_check`
transitioned to `Failed` after `max_check_retries × check_interval_ms`
(~200ms) with no nomination.

The parser now strips the optional `//` authority delimiter AND
the optional `user[:pass]@` userinfo segment per RFC 7065 §3,
producing a clean `(host, port)` tuple regardless of which URI
spelling the operator emitted. Both legacy `stun:host:port` and
modern `stun://host:port` round-trip identically through `gather`
now.

### `add_remote_candidates` dedup keys on transport

The candidate-merge dedup walked `(ip, port, type)` and dropped a
TCP-active candidate at the same `(ip, port)` as a UDP host
candidate as a duplicate. RFC 6544 emits one TCP candidate per
interface IP per active/passive/SO variant alongside the UDP
candidate at the matching `local_port`; without the transport
key in the dedup, the responder's `remote_candidates_` collapsed
the TCP fallback set into a single UDP entry and the check ladder
never tried the TCP pairs. The dedup now keys on
`(ip, port, type, transport)` so every transport variant rides as
a first-class entry in the merged set.

### `gn.link.ice.signal` outbound poll surface

`gn_link_ice_signal_api_t` gains a `poll_local` slot so out-of-process
hosts (signalling bridges, the docker test harness, third-party
glue) can drain serialised local-side candidate blobs without
reaching into `IceLink::sessions_` C++. The slot returns one queued
blob per call keyed by the peer pubkey, tagged with the matching
`ICE_SIGNAL_*` kind (OFFER_EOC when this side is controlling,
ANSWER_EOC when responding). `on_gathered` in `make_callbacks` /
`make_composer_callbacks` was a no-op stub previously — it now
serialises the full local candidate set, ufrag/pwd, and signal
flags via the existing `serialize_signal` helper into a per-peer
outbound queue.

`OUT_OF_RANGE` returns leave the queue entry in place and surface
the required buffer size in `*blob_len_out` so callers can retry
with a sized buffer instead of dropping the blob. `NOT_FOUND` is
the steady-state response once a peer's queue is drained — callers
poll on whatever cadence their signalling channel demands.

The shape change forces a version bump of `kIceSignalVersion` to
`0x00020000`. Older consumers that pin `0x00010000` fail the
`register_extension` version check at load time so the breaking
ABI change cannot bind silently.

### TURN TCP allocations (RFC 6062)

The TURN allocation flow learns the TCP-relay variant from RFC
6062. `ice.turn_requested_transport` defaults to `"udp"` (the
RFC 5766 shape) and accepts `"tcp"` / `6` to request a TCP-
allocated relay. The ALLOCATE request carries
`REQUESTED-TRANSPORT = 6`; the data path swaps CHANNEL-BIND /
ChannelData for CONNECT / CONNECTIONBIND with one TCP connection
to the TURN server per peer. ConnectionAttempt indications
trigger the same data-connection handshake when a remote peer
connects to the relay first.

### Auto-restart on consent loss

When RFC 7675 consent recovery is exhausted the session no longer
transitions straight to `Failed`. With `ice.auto_restart_on_consent_loss`
on (the default) the FSM regenerates ufrag / pwd, drops pending
state, and re-enters Gathering — giving the peer a chance to
re-signal and recover without an app-level reconnect. The transient
network outage that motivated the change is the typical wifi flap
or cellular handoff: keepalive responses stall past
`consent_max_recovery`, the link comes back a few hundred
milliseconds later, and the session resumes against a fresh
candidate set rather than being torn down.

`ice.auto_restart_max_attempts` caps the consecutive restart count
so an unreachable peer cannot hold the session in a restart loop
forever; the counter resets on successful nomination. A short
`ice.auto_restart_backoff_ms` window coalesces a burst of
consent-loss events into a single restart so one network blip does
not chew through the attempt budget.

The session surfaces the decision through a new `on_auto_restart`
callback carrying a `"consent-loss"` reason token; the link side
logs it at INFO so strategy plugins parsing the log stream can
deprioritise the conn or trigger an upper-layer reconnect. A
richer kernel-side `GN_PATH_EVENT_AUTO_RESTART` enum is on the
roadmap.

### DPLPMTUD path-MTU discovery

Active path-MTU discovery per RFC 8899 runs on every nominated
pair. A probe state machine in the session FSM emits padded
STUN binding requests at the candidate MTU step (1200 → 1280 →
1380 → 1492 → 1500); responses are correlated by transaction
id and feed the binary search up to the wire ceiling.

The discovered MTU is published through the new
`gn.link.ice.path_mtu` extension so upper layers (notably the
QUIC link consuming an ICE carrier) size their datagrams to the
actual path rather than the static `ice.path_mtu` fallback. The
fallback config knob still applies when discovery is disabled
or before the first successful probe.

### mDNS host-candidate obfuscation

Host candidates can be replaced with `<uuid>.local` names per
draft-ietf-mmusic-mdns-ice-candidates so that raw RFC 1918
addresses do not leak across the signaling channel. The mDNS
responder binds dual-stack 224.0.0.251 / FF02::FB, registers
the local UUID on inbound queries, and answers per qtype. Peer
candidates carrying `.local` names are resolved through the
same responder; pairs that fail to resolve within
`ice.mdns_resolve_timeout_ms` are dropped before connectivity
checks.

### Multi-TURN fallback

`gather_relay` walks `IceConfig::turn_servers` sequentially and
keeps the unused entries as backups. A background timer probes
one backup every `ice.turn_backup_interval_s`; when the primary
relay degrades (per `TurnClient::is_healthy()`) and a backup
ALLOCATE has succeeded recently, the link swaps the relay
candidate. Rate-limited to one swap per
`ice.turn_failover_min_interval_s` to avoid oscillation under
flapping conditions.

## [1.0.2-rc1] — 2026-05-13

Operator-facing knobs for production deployments. The
`ice.consent_recovery_cap_s` knob bounds the consent-freshness
recovery window — peers that drop probes for longer than the cap
are abandoned rather than churning through indefinite recovery.
`ice.candidate_filters` lets the operator strip whole candidate
families (`host`, `srflx`, `relay`) before gathering — useful for
NAT-only fleets or relay-only deployments.

`ice.turn_servers` is accepted as either a single `host:port`
string or an array of strings; the array form feeds the
multi-TURN fallback machinery introduced under Unreleased.

## [1.0.1-rc1] — 2026-05-13

STUN / TURN configuration entries learn to talk to `gn.dns`:
operators can configure `stun:host` / `turn:host` URIs and the
link expands them via the SRV record for the configured `_stun.
_udp` / `_turn._udp` services before gathering. Falls back to
the literal `host:port` parse when the extension is not loaded
or the SRV record is absent. Closes the C.1 cross-plugin
integration with `goodnet-handler-dns`.

## [1.0.0-rc1] — 2026-05-12

Initial release. Brings the legacy in-tree `links/ice` link
forward as a v1 GoodNet link plugin.

### Added

- Full controlled / controlling FSM per RFC 8445, with
  triggered checks (§7.3.1.4), regular nomination by default
  and aggressive nomination (§8.1.1) opt-in via
  `ice.aggressive_nomination`.
- STUN binding + integrity attributes per RFC 5389; long-term
  credential mechanism for TURN.
- TURN allocation slice per RFC 5766 over UDP, TCP (§7.2.2)
  and TLS (`turns://`). TCP path layered on the `gn.link.tcp`
  carrier; TLS path on `gn.link.tls`. Stream framing is
  extracted to a standalone helper with unit tests covering
  reassembly under partial reads.
- Candidate gathering across host, server-reflexive and relay
  families. Server-reflexive uses the configured STUN list;
  relay walks the TURN list (multi-TURN fallback added later).
- `gn.link.ice.signal` extension for the offer / answer
  side-channel. The link has no listening port; a signaling
  handler (heartbeat, a future signaling channel, or a bridge)
  hands serialized candidate sets to the link, which maps
  `peer_pk` onto an `IceSession`.
- Kernel-facing adapter wired through the SDK link teardown
  conformance plus the smoke-test suite.
- Composer surface for cross-link nesting — ICE can run as a
  carrier under a higher-level link (notably QUIC) by handing
  its post-nomination socket back through
  `host_api->notify_inbound_bytes`.
- Operator knobs for the timeouts that matter:
  `ice.session_timeout_s`, `ice.keepalive_interval_s`,
  `ice.consent_max_failures`, `ice.check_interval_ms`,
  `ice.path_mtu`.
- RFC coverage table in `README.md`, listing each RFC slice
  and whether it lands in the v1.0.0-rc1 surface or a later
  cut.

### Removed

- The in-tree copy under `links/ice` in the kernel monorepo.
  Source-of-truth moved to this sub-repo; the kernel consumes
  the built `.so` via the plugin loader.
