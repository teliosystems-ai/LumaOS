# ADR-0011: Local UTC runtime and offline Admin recovery

- Status: Accepted design; implementation and qualification remain separate
- Date: 2026-10-08
- Decision owner: product owner
- Extends: ADR-0002, ADR-0007 and ADR-0010

## Decision

The owner approved both decisions on 2026-10-08. This approval permits their
software implementation. It does not authorize activating host services,
changing host time or accounts, changing TPM ownership, or performing a
physical enrollment or recovery ceremony.

### UTC runtime

Use fixed, filesystem-local, peer-authenticated UTC endpoints and a confined
keeper. There is no network-facing internal control endpoint. Producer
measurements, keeper queries and human acquisition/recovery control are separate
interfaces; a measurement frame is never a capability or a time-authority token.
The composition must authenticate the actual protected executable, original
connected process, credentials and confinement, not a PID or claimed identity
from a request. Disconnect, replacement, malformed input, missed heartbeat,
suspend, clock discontinuity, changed history and ambiguous recovery fence the
current generation. Reacquisition is explicit, not automatic revival.

Retain the UTC policy approved on 2026-10-05: Cloudflare, Netnod and PTB NTS;
at least two independent operators; contributing samples at most 180 seconds
old; final uncertainty width at most 500 milliseconds; and a 100 ppm elapsed-time
envelope. Offline operation, missing quorum and leap ambiguity refuse timed
authority. TLS certificate bootstrap needs an independently reviewed approximate
time seed; OS time, RTC, WSL time and TPM powered time are not implicit seeds.
Dependency selection, protected image provenance and validation of that envelope
still require evidence. Endpoint approval does not qualify the existing chrony
source fixture as a production dependency.

### Admin recovery

The installer generates a separate, high-entropy offline credential for the
original local Admin. It is not a password, LUKS recovery passphrase, TPM owner
credential, signing key or effect grant. The operator records and confirms it
through the local terminal. Persist only a domain-separated verifier bound to
the installation, original Admin principal and recovery credential generation.
Secrets do not enter arguments, environment, JSON, files, receipts or logs.

Explicit principal adoption binds the installed verifier into the existing
TPM-backed Admin history. Until that adoption commits, the installer record is
not recovery authority. Existing installations without an enrolled verifier
refuse recovery; missing records never trigger automatic enrollment.

Recovery requires possession of the current credential, fresh original registry
and TPM-history validation, and review of the exact proposed transaction. It
advances the Admin principal generation and replaces the recovery verifier in
one checkpointed mutation. A fresh generated replacement credential must be
recorded and confirmed before committing. The old credential cannot authorize
another recovery after commit. Recovery does not implicitly transfer Admin,
issue an effect grant, reset account passwords, or reconstruct damaged authority.
OS-account mutation needs its own governed transaction and recovery evidence.

Root privilege and TPM-owner access alone are not recovery authorization.
Recovery commands are separate from ordinary catalog/PAM commands and cannot
accept caller-supplied verifiers through the general Admin service. Damaged,
missing or uncertain checkpoint history remains fenced; preserve it for exact
reviewed reconciliation rather than resetting, retrying or clearing TPM state.

## Completion criteria

The design is accepted, not the implementation or G2 gate. Closure requires the
installer ceremony and retained verifier, shared-checkpoint adoption and
rotation, refusal and interrupted-commit tests, account-lifecycle integration,
the installed confined UTC runtime and consumer boundaries, and integrated
grant/admission qualification. Native-image and physical-machine evidence remain
separate from source and isolated software-TPM tests.

Changing credential custody, adding root/owner bypass, silently resetting history,
exporting authority in JSON, or widening the local transport requires a new ADR
and owner review.
