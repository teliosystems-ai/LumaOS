# G2 Explicit Product Admin Bootstrap

The native source now supports an explicit, principal-bound Admin bootstrap
receipt above the existing TPM checkpoint adapter. Enrollment alone still
confers no product role. This increment establishes the selected governance
principal; it does not implement the confined Admin service, finite delegation,
resource grants, signing custody or G2 acceptance.

## Implemented scope

`luma-platform admin-bootstrap LOGIN` authenticates the enrolled human through
the fixed local PAM interface and inspects the semantic state without writing.
An explicit `--activate REVIEW-SHA256` commits the reviewed bootstrap. Both
commands require an installed system, fixed credential paths and the fixed
local TPM backend. Root privilege, a caller-supplied role, an enrollment intent,
or a review digest alone is insufficient. The account must remain the original
installer-selected UID 1001 principal, including its installation ID, random
principal ID, generation and login.

The closed canonical payload binds the fixed `Admin` role, authenticated
checkpoint deployment, original enrollment digest, complete principal identity
and previous genesis head. It is retained privately in `bootstrap.json` before
the journal append. Its digest, exact activity/request, actor UID and TPM clock
are included in the TPM-anchored entry. Semantic replay verifies the complete
payload against that entry and the original deployment-bound enrollment.
An uncommitted payload does not establish Admin. Missing, altered, partial,
noncanonical, public or linked payloads refuse without overwriting them.

The review binds the payload, current checkpoint head, activation state and
TPM boot epoch. Authentication is independently revalidated before payload
preparation, at each journal writer boundary and before successful reporting.
Potentially blocking enrollment reads finish before the final authentication
check. PAM observation freshness is also checked after registry/account reads.
The backend retains its sole-writer lock. These controls do not protect against
hostile OS root or provide the still-missing anchored principal lifecycle.

Lost TPM replies retain the journal proposal and fence ordinary startup. Only
the existing explicit publication procedure can publish an exact successor
already proved committed by the TPM; it does not repeat the bootstrap write.
The committed semantic receipt was authorized before that write. After restart
or a lost successful reply, fresh inspection supplies the current review for
explicit replay without another TPM extension. No transfer, reset or automatic
recovery exists. Unknown or additional semantic history fails closed until its
owning service is implemented.

The CLI does not expose an authenticated session or capability token. It reports
delegation unavailable, no effect grant, production custody unverified and
`gate_closing: false`. Bootstrap uses the TPM clock as an audit/epoch observation,
not UTC or a trusted signing/assignment timestamp. Trusted time remains open.

## Verification

Targeted checks passed on 2026-10-04 from the frozen snapshot at
`D:\LumaOS-builds\g2-admin-bootstrap-targeted-20261004-03`.

- Build manifest SHA-256: `4991db9c5facf410c707c530e7026b5bce5c46384ef15659dad2765109a906ce`.
- Supplementary test-input manifest SHA-256: `e18a7d1db911f2db5644b7a11a4f822b4d935d7f638e184210f0deeaac074c4f`.
- Completed log SHA-256: `3f4e8e976839e8080368e6064b93a7668989e70fccd0c95ebb38cac6ae07d77d`.
- All 166 captured build inputs and four supplementary test inputs matched the
  current checkout after the final run.
- 58 ordinary Rust tests passed: 12 bootstrap, 16 journal, 20 enrollment,
  six principal and four authentication tests. The ordinary run explicitly
  skipped the fixtures that require separately initialized PAM/TPM environments.
- The separate disposable-TPM wrapper passed empty-owner sealing control,
  legacy systemd nonempty-owner refusal, native existing-owner enrollment, and
  bootstrap activation followed by credential reload and exact restart/replay.
  Its bootstrap identity is a test fixture, not real PAM-to-TPM acceptance.
- Four source-wiring checks, formatting, the offline locked native build with
  warnings denied and CI runner Bash syntax passed. The runner now invokes the
  new fixture; the complete runner and remote CI were not executed here.
- The failed `-01` compile and passing `-02` checks remain retained. The `-03`
  snapshot qualifies the final authentication-freshness ordering as well.

Containers used D-backed Docker/cache/evidence, at most one CPU and 768 MiB,
no network, host TPM devices, Docker socket or extra privileges. WSL memory,
unrelated workloads and the physical TPM were unchanged. No image, VM or model
sweep ran. Installed authentication, service confinement, production custody,
hardware qualification and the remaining implementation backlog are still open.
