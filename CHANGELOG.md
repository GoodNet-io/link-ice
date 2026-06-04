# Changelog — goodnet-link-ice

All notable changes to this plugin are listed here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions track the kernel ABI through `gn_link_vtable_t` /
`gn.link.ice.signal` / `gn.link.ice.path_mtu`.

## [Unreleased]

### P2300 timer migration, nomination logic, topology-aware config

`asio::steady_timer` replaced throughout the session FSM with a
generation-counter cancellation scheme backed by
`exec::timed_thread_context` (P2300 / stdexec). Each timer
arm increments an `uint64_t` generation; expired callbacks
compare against the current generation and no-op if stale.
The `asio::io_context` dependency is removed from the timer
path; the session compiles and runs without Asio on platforms
that provide only the stdexec runtime.

New config knobs:

- `ice.max_check_retries` — maximum per-pair retransmission
  count before the pair is marked Failed (was hard-coded).
- `ice.nomination_wait_ms` — time the controlling agent waits
  after the first valid pair before sending a USE-CANDIDATE
  nomination; allows lower-priority pairs to complete and
  avoids nominating a relay pair when a direct path arrives
  slightly later.

New session methods wired from `on_topology_sealed`:

- `set_prefer_turn_tcp(bool)` — prefer TCP-relay candidates
  when the topology layer reports a TCP-friendly path.
- `set_security_overhead(size_t)` — subtracts a cipher-overhead
  budget from the discovered path MTU before publishing via
  `gn.link.ice.path_mtu`.
- `set_ordered_delivery(bool)` — hints the check ladder to
  deprioritise UDP host pairs when the upper layer requires
  ordered delivery (QUIC over ICE-TCP scenario).

Log format: all `gn_log_info(…, "%.*s", …)` printf-style calls
converted to `gn::log::info("{}", …)` format-style. Format-string
type-safety is now enforced at compile time.

New test: `tests/test_ice_nomination.cpp` — covers
`nomination_wait_ms` window, early-nomination suppression, and
the generation-counter cancellation path under timer-storm
conditions.

### Known implementation mistake — multi-connect signal routing broken

**Architecture**: `IceLink` correctly implements the kernel's N-conn-per-peer
model.  `sessions_` maps `conn_id → PeerEntry`; `peer_to_ids_` maps
`peer_pk → [conn_id, ...]`.  Each `IceSession` internally holds
composer-mode carrier handles (high-bit-tagged L1 ids, bypassing
`notify_connect`) obtained via the composer `connect()` slot of
`link-udp` / `link-tcp`.  These are private to the session and are
not registered in `ConnectionRegistry`.  The two-handle-space model
(kernel-registered ICE conn_id + composer-internal L1 handle) is
correct by design and mirrors the WSS/TLS composer pattern.

**What is broken — signal routing with `peer_to_ids_.size() > 1`**:
OFFER/ANSWER blobs arrive at `IceLink::handle_new_conn` keyed by
`peer_pk` (via the `gn.link.ice.signal` extension).  The signal
envelope carries no session-specific token.  Current fallback: fold
trickle candidates into the existing session only when exactly one
session for the peer exists (`size() == 1` guard); when `size() > 1`
allocate a new `IceSession` via `notify_connect`.  Each such
fallthrough spawns a fully independent check ladder; incoming signals
for the original sessions are lost and those ladders time out.
Multi-connect to the same peer via ICE is therefore broken beyond the
first session.

The single-connection path works correctly.

**Fix scope**:

1. Add a session token (local `ufrag` or an explicit nonce) to the
   OFFER/ANSWER signal envelope so `handle_new_conn` can route to the
   correct existing session without relying on `size() == 1`.
   The `AcceptFilterFn` on `LinkCarrier::on_accept` provides the
   equivalent demux for inbound carrier data.
2. Gate all `check_list_` / `local_candidates_` reads and writes behind
   the Asio strand; remove `local_state_mu_` from those paths.
3. Rewrite `check_list_states_for_test()` as a strand-dispatched future
   so tests do not race the I/O thread.

Until the fix lands, treat the plugin as single-path only: one
`gn_core_connect("ice://…")` per peer at a time.

### `gn.link.portmap` integration: explicit-port-mapped srflx candidates

`IceSession::gather()` now runs a new step `gather_portmap()` between
host gather and TURN allocation when the host exposes the
`gn.link.portmap` extension (UPnP IGD / PCP / NAT-PMP, version
`0x00010000`). The session asks the router for a `(ext_ip, ext_port)`
mapping bound to the local UDP port and emits the result as a
dedicated srflx candidate. The mapping is released best-effort on
session teardown via the matching `release()` slot. Peers consume
the candidate identically to a STUN-discovered srflx — same wire
shape, same priority structure — but the foundation hash uses the
synthetic server string `"portmap"` so pacing groups stay distinct
from STUN-allocated srflx entries.

The path is purely additive: a missing extension, a zero
`supported_protocols()` mask, or a router refusal all fall back to
the pre-existing STUN-srflx + TURN-relay gather flow without
behaviour change. TCP-side portmap candidates are not yet wired —
deferred to a future commit that mirrors the UDP request slot for
RFC 6544 TCP fallback.

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
