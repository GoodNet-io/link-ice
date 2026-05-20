# goodnet-link-ice

ICE NAT-traversal link for GoodNet. Implements the controlled /
controlling agent state machine from RFC 8445, the STUN binding /
integrity attributes from RFC 5389, and the TURN allocation slice
from RFC 5766. Maps `ice://<peer-pk-hex>` URIs to per-peer ICE
sessions, gathers host / server-reflexive / relay candidates, runs
prioritised connectivity checks, and surfaces post-nomination
bytes through `host_api->notify_inbound_bytes`.

ICE has no listening port — candidates ride out-of-band through the
peer-to-peer `gn.link.ice.signal` extension. The extension is
bidirectional:

- **Inbound** (peer → us): a signaling handler calls
  `offer(peer_pk, blob)` / `answer(peer_pk, blob)` (plus the
  RFC 8838 §10 end-of-candidates variants `offer_eoc` /
  `answer_eoc`) to deliver serialised candidate sets. The link maps
  `peer_pk` onto an `IceSession` and feeds the FSM.
- **Outbound** (us → peer): the signaling handler polls
  `poll_local(peer_pk, &kind, buf, cap, &len)` to drain the
  freshly serialised local-side candidate blob. `kind` is
  `ICE_SIGNAL_OFFER_EOC` when this side is controlling,
  `ICE_SIGNAL_ANSWER_EOC` when responding. Returns
  `GN_ERR_NOT_FOUND` when no signal is queued for that peer (gather
  still in progress or the queue was already drained); returns
  `GN_ERR_OUT_OF_RANGE` with the required size in `*len` if `cap`
  is too small (the queue entry stays in place for retry).

The extension version is `0x00020000` since the outbound `poll_local`
slot was added — older consumers that pin `0x00010000` fail the
extension version check at register time.

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
| `ice.turn_servers` | string OR array of string | `""` | TURN server entries; both forms accepted. Array form walks the list in order per RFC 8445 §6.1.4 fallback semantics. Single-string form populates one entry. Credentials (`turn_username` / `turn_password`) apply globally to every entry. |
| `ice.turn_username` | string | `""` | TURN long-term credential |
| `ice.turn_password` | string | `""` | TURN long-term credential |
| `ice.turn_tcp` | bool | `false` | RFC 5389 §7.2.2 TURN-over-TCP — fallback when UDP-blocked; needs `gn.link.tcp` carrier |
| `ice.turn_tls` | bool | `false` | RFC 5389 §7.2.2 TURN-over-TLS via `turns://` — needs `gn.link.tls` carrier; precedence over `turn_tcp` |
| `ice.turn_requested_transport` | string / int | `"udp"` | RFC 6062 relay-side transport: `"udp"` / `17` keeps the RFC 5766 UDP-allocation flow; `"tcp"` / `6` requests a TCP-allocated relay where peers connect over TCP and the client uses CONNECT / CONNECTIONBIND for each data connection |
| `ice.session_timeout_s` | int64 | `10` | gather + checks deadline |
| `ice.keepalive_interval_s` | int64 | `20` | consent-freshness probe period |
| `ice.consent_max_failures` | int64 | `3` | missed probes before recovery |
| `ice.check_interval_ms` | int64 | `50` | per-pair check pacing |
| `ice.aggressive_nomination` | bool | `false` | RFC 8445 §8.1.1 — fastest-possible nomination at the cost of pair churn |
| `ice.path_mtu` | int64 | `1200` | RFC 8085 datagram size budget; bypass discovery when set |
| `ice.mdns_obfuscate_host_candidates` | bool | `false` | draft-ietf-mmusic-mdns-ice-candidates — replace raw host IPs with `<uuid>.local` registered on multicast 224.0.0.251 / FF02::FB |
| `ice.mdns_resolve_timeout_ms` | int64 | `5000` | how long to wait for a peer's `.local` candidate to resolve before dropping the pair |
| `ice.lite_mode` | bool | `false` | RFC 8445 §2.7 ICE-lite — responds to checks only, never initiates |
| `ice.reactive_interface_change` | bool | `true` | Linux only: re-gather host candidates on `RTM_NEWLINK` / `RTM_NEWADDR` / `RTM_DELADDR` events |
| `ice.symmetric_port_prediction_enabled` | bool | `true` | Probe predicted ports past the peer's advertised srflx when symmetric NAT is detected |
| `ice.symmetric_port_prediction_attempts` | int64 | `8` | Max consecutive predicted ports to try (`peer.port + stride * k` for k in 1..N) |
| `ice.auto_restart_on_consent_loss` | bool | `true` | Re-enter Gathering with fresh ufrag / pwd when RFC 7675 consent recovery is exhausted instead of transitioning to `Failed`. Designed for transient outages (wifi flap, cellular handoff). |
| `ice.auto_restart_max_attempts` | int64 | `3` | Upper bound on consecutive auto-restarts before the session gives up and transitions to `Failed`. Counter resets on successful nomination. `0` disables auto-restart. |
| `ice.auto_restart_backoff_ms` | int64 | `500` | Minimum gap between two consecutive auto-restarts. A burst of consent-loss events landing inside this window coalesces into a single restart. |

Operator-facing recipes that map deployment shapes (home network,
UDP-blocked enterprise, multi-TURN HA, mDNS-only LAN, ICE-lite
gateway, symmetric-NAT punch, PMTU optimisation, mobile reconnect)
to specific `ice.*` knob combinations live in the kernel monorepo:
[`docs/operator/ice-recipes.en.md`](../../../docs/operator/ice-recipes.en.md).

## RFC coverage

- RFC 8445 (core ICE) — full controlled / controlling FSM,
  triggered checks (§7.3.1.4), regular nomination by default,
  aggressive nomination opt-in (§8.1.1)
- RFC 5389 / 5766 (STUN / TURN) — long-term credential auth,
  ChannelBind fast path (§11), Send-Indication fallback,
  TURN-over-TCP / TLS framing (§7.2.2)
- RFC 6062 (TURN TCP allocations) — REQUESTED-TRANSPORT=6 in the
  ALLOCATE request, ConnectionAttempt indication handling, Connect
  / ConnectionBind for per-peer data connections (no CHANNEL-BIND
  on TCP allocations)
- RFC 8838 (Trickle ICE) — incremental candidates with
  end-of-candidates marker (OFFER_EOC / ANSWER_EOC)
- RFC 8305 (Happy Eyeballs) — dual-family pre-fire in begin_checks
- RFC 8085 (UDP usage) — path-MTU floor knob; RFC 8899 active
  probe discovery is planned
- RFC 6762 (Multicast DNS) — minimal A/AAAA responder + resolver
  used by mDNS host-candidate obfuscation
- draft-ietf-mmusic-mdns-ice-candidates — `<uuid>.local` host
  candidate variant; gated on `ice.mdns_obfuscate_host_candidates`

## ICE-lite mode

`ice.lite_mode = true` switches the agent to the lightweight variant
defined in RFC 8445 §2.7. A lite agent only responds to incoming
connectivity checks — it never sends checks itself, never runs
consent freshness, and never drives nomination. Typical use-cases:
media gateways, SFUs, and IoT endpoints that already sit at a fixed
public address where running full ICE would be redundant. The peer
side must always be a full ICE agent; two lite agents cannot
complete the handshake because no one drives the checks.

## NAT port mapping (`gn.link.portmap`)

When the host exposes the `gn.link.portmap` extension (UPnP IGD / PCP
/ NAT-PMP, version `0x00010000`), `IceSession::gather()` runs an
additional step between the host and TURN gather phases: it asks the
router for an explicit `(ext_ip, ext_port)` mapping bound to the
session's local UDP port and emits the mapping as an extra srflx
candidate. The candidate is wire-identical to a STUN-discovered srflx
entry — peers consume it the same way (same `CandidateWire::type` low
nibble, same priority structure) — but its foundation hash uses the
synthetic server string `"portmap"` and its priority occupies a
distinct slot (`local_pref = 65534` vs. STUN srflx `65535`,
`component = 2`) so the two coexist in the check list without
collapsing into a single pacing group.

The path is purely additive:

- Missing extension → `gather_portmap` is a no-op, the session falls
  back to STUN srflx + TURN relay unchanged.
- Zero `supported_protocols()` mask (the extension is present but no
  protocol reached the local gateway) → same no-op.
- `request()` failure (router refused, transient probe loss) → no
  candidate emitted, the rest of gather completes.
- `host-only` / `relay-only` candidate filters drop the portmap
  candidate the same way they drop STUN srflx / TURN relay.

The mapping is released through `release(GN_PORTMAP_UDP, local_port)`
on session teardown (`IceSession::close()` and dtor). Failure to
release is non-fatal — the underlying plugin's renewal table clears
the entry once the router-granted `lifetime_s` expires without a
refresh.

TCP-side portmap candidates (`GN_PORTMAP_TCP` for the RFC 6544 TCP
host port) are deferred: the current gather flow emits the UDP
mapping only. Operators relying on TCP fallback continue to use the
STUN-over-TCP srflx path.

## Contract

- Kernel-side link contract: `docs/contracts/link.en.md`
- ICE wire candidates: `candidate.hpp::CandidateWire` (24 bytes)
  and `IceSignalData` (44 bytes). Stable for interop with bridges.
  Signals that include `HostMdns` candidates carry an optional
  trailer (`uint32` count + length-prefixed hostnames) after the
  fixed-size candidate array. Signals without any HostMdns
  candidate are byte-identical to the pre-mDNS form.
