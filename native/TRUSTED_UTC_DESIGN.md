# Trusted UTC source design

Status: **provider set, initial bounds and offline-refusal policy approved by
the owner on 2026-10-05; fixed local endpoints and confined keeper design approved
on 2026-10-08; implementation in progress, not activated**. Originally
proposed 2026-10-04. This supplements
ADR-0004, ADR-0007 and ADR-0010. [ADR-0011](../docs/adr/0011-local-utc-runtime-and-offline-admin-recovery.md)
records the narrow extension of the local transport and recovery design.
G2 remains open. The current Admin service still reports
`trusted_utc_available: false` and does not admit assignments or effect grants.

## Approved source policy

Use chrony with NTS-only upstreams and a separate, confined Luma UTC keeper.
The keeper supplies a fresh uncertainty interval to the protected authorization
composition root, rather than trusting the system wall clock or a caller's
timestamp. The owner approved these three separately operated sources:

| Policy identity | Candidate endpoint | Official service documentation |
| --- | --- | --- |
| Cloudflare | `time.cloudflare.com` | [Cloudflare NTS](https://developers.cloudflare.com/time-services/nts/) |
| Netnod | `nts.netnod.se` | [Netnod NTS](https://www.netnod.se/nts/network-time-security) |
| PTB | `ptbtime1.ptb.de` | [PTB time service](https://www.ptb.de/cms/en/ptb/fachabteilungen/abt9/gruppe-95/ref-952/time-synchronization-of-computers-using-the-network-time-protocol-ntp.html) |

Endpoint documentation was verified, but live handshakes and availability were
not tested. Multiple addresses or regional servers
from one operator count as one source. Public-provider and shared-network
dependencies remain; private authenticated enterprise sources can be a later,
separately governed policy, not a silent fallback.

The approval fixes the provider set, initial bounds below and refusal of
time-bound authorization during outages. It permits continuing implementation,
not altering this host's clock, firmware, TPM ownership or WSL settings.
The conditional one-fault guarantee remains an explicit assumption. Certificate
bootstrap and durable history/recovery remain proposed procedures requiring
implementation and qualification; no custodian clock seed has been supplied
and no ceremony or physical operation is authorized by this policy approval.

## Trust boundary

```text
Three NTS operators -> confined chrony -> protected Luma UTC keeper
                                         -> Admin / effect-time policy checks
```

NTS authenticates replies and detects replay, but cannot guarantee a server's
truthfulness or eliminate network-delay attacks. The design therefore depends
on at most one faulty operator, honest intervals covering actual UTC, and the
installed kernel/chrony/keeper remaining inside the platform trust boundary.
Two colluding operators or a compromised privileged platform are outside that
guarantee. [RFC 8915](https://www.rfc-editor.org/rfc/rfc8915.html)

Chrony handles protocol cryptography and clock discipline; the keeper handles
Luma's authorization eligibility, bounded estimates and clock generations.
Only chrony gets the required time-setting privilege and upstream network
access. The keeper gets protected read-only telemetry, no network or TPM-owner
credentials. Admin retains its local socket/PAM/TPM boundary and receives no
NTS secrets. A root-owned policy binds operator identities, TLS hostnames,
approved CA roots, endpoint/redirect rules and its digest.

Do not replace the current clock service or enable the new source until the
authenticated publisher and protected service are implemented. The eventual
image must have one clock
discipliner, no DHCP/pool/unauthenticated fallback, no local-clock authority and
no network command listener. Illustrative chrony settings are `nts` on each
source, `authselectmode require`, `minsources 2` and poll exponents 6 through 7
(64–128 seconds). Chrony's source count does not prove independent operators;
the keeper must enforce that mapping. Its root-distance limit should be no
looser than the reviewed uncertainty budget. [Chrony configuration](https://chrony-project.org/doc/4.5/chrony.conf.html)

## Estimates and conservative quorum

Owner-approved initial policy, subject to network/drift qualification:

| Quantity | Proposed limit |
| --- | --- |
| Independent available operators | At least two of the configured three |
| Age of each contributing authenticated measurement | At most 180 seconds |
| Width of the final possible-UTC interval | At most 500 ms, including drift and acquisition delay |
| Total elapsed-clock rate-error envelope | 100 ppm, expanded outward with rounding up |
| Leap or unclassified discontinuity | Fence authorization until requalified |

Represent UTC as integer milliseconds `[earliest, latest]`, with explicit
unsmeared leap handling; authorization is fenced across a leap ambiguity.
Bind every observation to boot identity, provider-process generation, clock
generation and policy digest. Project it using elapsed `CLOCK_BOOTTIME`, which
must be sampled by the protected adapter. Include acquisition timing, source
error bounds, asymmetry and drift; neither integer rounding nor selection may
artificially narrow uncertainty. The initial rate-error value is an assumption
to qualify, not a measured property of every target machine. `CLOCK_BOOTTIME`
includes suspend but is frequency-adjusted like `CLOCK_MONOTONIC`; it is not a
raw independent oscillator. The freshness deadline must use maximum possible
real elapsed age; a slow local clock cannot extend it. The adapter must bound
the combined oscillator error and clock discipline/slew, audit the pinned
kernel/chrony rate limits,
and fence if that envelope cannot be established. Do not assume chrony's
default slew limits fit 100 ppm. Suspend/resume still invalidates the epoch;
counting suspended time is not permission for offline authority. [Linux clock semantics](https://man7.org/linux/man-pages/man2/clock_gettime.2.html)

For measured elapsed age `a` and rate-error limit `d` ppm, the arithmetic uses
`e = ceil(a*d / (1000000-d))`. Project an input `[L,U]` to
`[L+a-e, U+a+e]` and reject if `a+e` exceeds the freshness limit. Acquisition
and clock-read quantization uncertainty must already be included by the live
adapter; integer arithmetic cannot establish those input bounds itself.

With three current independent inputs, retain the hull of **all** overlapping
pair intersections. Choosing the narrowest pair can let one faulty operator
exclude the true time. With only two inputs, require overlap but retain their
full union hull: either could be faulty. Reject disagreement or excessive
width. Include every current admissible operator; do not silently drop an
outlier to manufacture precision. Unavailable/stale sources and admission
decisions must be visible in audit/status.

## Protected live adapter requirements

The keeper's fixed local interface is restricted to approved service peers;
requests cannot supply estimates, provider identities, epochs or a `trusted`
flag. Observations are short-lived and bound to the active keeper instance.
The composition root retains the provider and calls it again before every
authorization-sensitive preparation and final effect dispatch. Audit interval
records are evidence, never reusable time capabilities.

An implementation must verify fixed configuration provenance, resolved source
mapping, successful NTS-protected measurements, selection state, error bounds,
measurement age and consistent report generations. `chronyc selectdata`'s
`Auth=Y` means authentication is enabled, not standalone proof that a particular
fresh packet authenticated. `authdata` key/cookie state or a synchronized flag
also cannot alone admit time. [Chrony reporting](https://chrony-project.org/doc/4.5/chronyc.html)

The [upstream chrony audit](evidence/G2_UTC_KEEPER_2026-10-05.md) confirms that
stock selection reports retain state from the last selection event and do not
provide the atomic measurement/generation provenance required here. Continue
with a bounded protected publisher at the authenticated good-sample boundary;
do not synthesize proof from report flags. Audit the eventual exact packaged
Ubuntu tuple and publisher changes as well. Bound parsing, report size,
duplicate/alias handling, finite numbers,
rounding, deadlines and before/after generation checks. A pinned good-sample
publisher source fixture and closed measurement decoder now exist; protected
production dependency qualification and installed confinement
are still missing. Source linkage and arithmetic are not substitutes.

The subsequent [receiver checkpoint](evidence/G2_UTC_RECEIVER_2026-10-05.md)
implements per-message kernel credential checks, observed process pinning,
bounded queue draining and replay/age/epoch checks in source. It has no product
bind path or authority interface. Capturing unchanged process fingerprints is
not approval of that executable, certificate configuration or confinement.
The protected supervisor and live keeper/history composition remain open.
The later JSON transport source adaptation removes the binary-serialization
mismatch with ADR-0002. ADR-0011 now approves the fixed peer-authenticated local
endpoint/confined-keeper design. Executable/configuration admission, the
measurement/deadline/socket implementation, protected provisioning and deployed
lifecycle qualification remain open; the approval enables that work, not a
working or qualified endpoint.

The [stream composition checkpoint](evidence/G2_UTC_STREAM_2026-10-05.md) joins
receiver-checked rounds to the keeper in queue order, with independent producer
and keeper generation mapping. Intermediate quorum loss/disagreement fences even
if a later round looks usable. Quiet polls reproject the current source inventory,
not a saved interval, with fresh local clocks and a conservative one-second
producer-heartbeat deadline. Source process/queue errors, observed discontinuities
and explicit invalidation keep the session fenced; there is no automatic recovery.
At that checkpoint the source module did not authenticate its supplied history
floor. The later binding below addresses that source input; code/confinement
approval, complete lifecycle delivery and time authority remain open.

The subsequent [step-watch checkpoint](evidence/G2_UTC_STEP_WATCH_2026-10-05.md)
adds a privately owned nonblocking `CLOCK_REALTIME` timer with absolute
cancel-on-set semantics. The stream checks it before and after candidate work;
cancellation, expiration and any unverifiable read fence without rearming or
automatic recovery. This supplements numeric comparisons rather than replacing
them. Linux reports discontinuous realtime changes through `ECANCELED` for such
timers. [Linux timerfd interface](https://man7.org/linux/man-pages/man2/timerfd_create.2.html).
Actual clock-step delivery, step-and-restore and suspend race behavior on the
supported kernel/image remain unqualified. The guard does not approve runtime
provenance, authenticate time history or establish the absolute rate envelope.

The [JSON transport checkpoint](evidence/G2_UTC_JSON_TRANSPORT_2026-10-05.md)
adapts the C publisher and runtime receiver to the accepted four-byte big-endian
length and strict UTF-8 JSON envelope, with a 2048-byte datagram bound. Asserted
PID/real UID must match kernel message credentials; boot-scoped deadlines,
request identity, epochs and the ordered source inventory are closed fields.
The receiver accepts no historical binary fallback. This is serialization of
measurements, never serialization of time authority, and activates no listener.

## Bootstrap and offline recovery

Certificate validity introduces a bootstrapping dependency when the clock is
unknown. Keep chain, hostname and validity checks enabled. An explicitly
authenticated local Admin/custodian may supply a reviewed approximately
correct clock seed from an independent trusted clock solely to permit initial
TLS verification. Record its provenance and uncertainty; it is not role time.
If no suitable seed exists, remain fenced. Reject a seed below the protected
history floor. A guessed RTC, Windows/WSL wall clock, image build date or TPM
powered-time is not a seed authority. Do not enable `nocerttimecheck` or accept
expired certificates as an automatic recovery path. This stricter choice
addresses the bootstrap issue described in [RFC 8915, section 8.5](https://www.rfc-editor.org/rfc/rfc8915.html#section-8.5).

Initial local PAM-authenticated enrollment/bootstrap and read-only catalog
inspection do not acquire UTC authority from this seed. A narrowly reviewed
seed/policy recovery path must remain usable without an existing time-bound
delegation, while never granting arbitrary effects or resetting trust history.

State progresses from `Uninitialized` through `Acquiring` to `Eligible` only
after authenticated quorum and all bounds hold. Restart, suspend/resume,
clock steps/regression, policy change, unknown leap state, lost quorum or
unverifiable provider state moves it to `Fenced`. Old observations and pending
authorizations invalidate; reacquisition is explicit, not replay of old time
tokens. No configured long offline holdover grants new authority. Ordinary
intervals between polls are bounded by the age limit; detected loss of quorum
fences immediately, not only at the eventual age deadline. Manual non-model
operation and diagnostic inspection remain available.

## Durable history and authorization integration

Store the last accepted lower UTC bound and clock/policy generation in protected,
TPM-bound semantic history. A persisted floor detects rollback but cannot prove
current UTC after reboot. It must be reconciled with fresh network evidence;
never reload a saved estimate as live time. Use governed security transactions
for persistence, not one TPM write per NTP packet. Define uncertain-write and
restart behavior before integration. Do not allocate another NV index, change
ownership, clear the TPM, or pretend its powered-time is UTC.

For a validity window `[notBefore, expires)`, require the whole fresh interval
inside it: `earliest >= notBefore` and `latest < expires`. Crossing either edge
denies. Issuance, extension, expiry, revocation and final effect checks must use
the same live provider plus fresh principal, catalog/assignment, resource and
lease-generation checks. UTC availability alone never creates a grant. Clock
recovery does not resurrect a revoked assignment or redispatch an uncertain
effect. History rollback/reconciliation and assignment semantics still require
implementation under ADR-0010.

The [UTC history source checkpoint](evidence/G2_UTC_HISTORY_2026-10-05.md)
adds canonical floor/context records to the existing native Admin checkpoint
domain, with mixed catalog/history replay and a private reviewed transaction
adapter. Floors and their independent versions advance only monotonically;
missing/substituted payloads and uncertain writes fence. Historical replay
acknowledges a past commit without reacquiring time or writing again. No new
NV index or clock seed is introduced. The live-observation/authentication seams
are tested with fakes here, not deployed as authenticators. Protected provider
composition, current floor revalidation in the keeper/effect path and the
installed recovery ceremony remain open; a stored floor cannot restore UTC.

The [current history binding checkpoint](evidence/G2_UTC_HISTORY_BINDING_2026-10-05.md)
adds a read-only semantic adapter borrowing the Admin owner's existing store.
It validates the explicit bootstrap and every mixed catalog/history payload,
bracketed by fresh shared checkpoint checks, then repeats replay before
returning a private binding. Deployment, enrollment, historical principal,
exact shared head, floor/version and TPM reset/restart epoch are pinned; TPM
powered-time is only a regression/epoch check, never UTC. An initial zero floor
is available only after verified bootstrap and does not create an estimate.

The non-authorizing bound stream checks the same binding before and after
candidate work. Any shared-head change, including a catalog-only mutation,
or failed/uncertain read fences the session with explicit reconstruction
required. After replay it checks the live peer/queue, samples fresh clocks,
reprojects and checks the step watch; slow history work cannot extend the
heartbeat deadline. It does not return the pre-replay candidate or silently
refresh the bound floor. No TPM credential, wire authority token, new endpoint
or write-per-poll is introduced. Installed protected composition and final
effect checks are still missing; historical writer identity is not current
human authentication and the source remains incapable of granting effects.

## Increment delivered and qualification still needed

`rust/luma-platform/src/utc_bounds.rs` implements inert checked interval math,
quorum envelopes, drift projection, epoch mismatch and finite-window checks.
Its inputs are not authenticated; it has no product entry point, serialization,
clock reader, service or authority token. No production policy is activated.
The original test checkpoint is [UTC bounds evidence](evidence/G2_UTC_BOUNDS_2026-10-04.md).

The later [policy and keeper checkpoint](evidence/G2_UTC_KEEPER_2026-10-05.md)
adds the fixed policy artifact and non-authorizing lifecycle reducer. The
policy digest is domain-separated; compiled bytes and semantics cannot be
replaced by a caller-selected provider or looser bounds. Complete observation
rounds retain all three operator states. Replay, re-aging, invalid epochs,
lost quorum, leap ambiguity, inconsistent clocks and acquisition failures
discard estimates and fence. Explicit reacquisition changes the clock
generation; a candidate wholly behind the supplied history floor requires
reconciliation with no reset path. These are data-level tests: neither the
clock observations nor the supplied floor are yet bound to an authenticated
publisher or TPM history. `Bounded` means an arithmetic candidate, not the
deployed service's `Eligible` state or permission to set trusted UTC available.

The [publisher checkpoint](evidence/G2_UTC_PUBLISHER_2026-10-05.md) adds the
authenticated good-sample source hook, complete fixed-format rounds and a
strict C/Rust codec. It does not turn serialized measurements into proof:
kernel peer/runtime identity, queue deadlines, live clock checks and protected
history still belong to the integrating service. Producer source-clock
generation and keeper reacquisition generation are distinct and must be
mapped explicitly at that boundary. No fixture daemon or time service is
installed or activated.

Next: complete/audit protected live reception and the production dependency,
confinement and bootstrap/history lifecycle; integrate finite assignments and
effect-time checks; package installer/boot/update/recovery paths. Add controlled
tests for forged/expired/wrong-host certificates, NTS stripping, replay, delayed
packets, bad operator clocks, duplicate aliases, inconsistent telemetry,
outages, suspend, steps, leap handling, seed abuse and TPM-history interruption.
Use isolated fixtures for those attacks. The consolidated image and separate
native Ubuntu machine must then qualify actual network service behavior,
hardware clock drift, installed confinement, boot and recovery. Source arithmetic
tests cannot close trusted-time or G2 production acceptance.
