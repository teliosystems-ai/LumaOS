# G2 Admin Publication Retry and Writer Authorization

The native checkpoint enrollment now supports exact replay after a lost
directory-publication acknowledgement. The inert journal also requires its
integrating service to authorize the exact entry at preparation and immediately
before TPM dispatch. These are Admin/trust implementation increments, not the
product Admin bootstrap/service, finite role grants or G2 completion.

## Enrollment publication retry

The existing `admin-checkpoint-enrollment-reconcile` command accepts exactly
one retained proposal location: the pending directory or the final directory.
Both present, neither present, partial contents and unsafe metadata refuse.
The final directory is a candidate for verification, not success evidence by
itself. Verification requires the original inert record and bound parent,
unchanged five-file proposal and boot inputs, successful sealed credential
delivery, and an authenticated fixed NV read matching the exact genesis head.

Pending inspection still reports `committed_pending_publication`; verified
final inspection reports `verified_published_enrollment`. The review remains
bound to the same proposal bytes, intent, parent, boot inputs, TPM genesis and
boot epoch, regardless of directory placement. The original review can
therefore be retried after rename while those inputs remain unchanged.
Published replay reports `replayed: true` and
`filesystem_publication_performed: false`; neither path writes the TPM.

Publication and replay both require fresh principal-bound PAM in the product
command. Account authority is rechecked after synchronizing all proposal files
and the directory, followed by another proof/clock check before publication.
An expired/revoked observation, changed epoch or changed file refuses without
reprovisioning, deletion or assumed rollback. Final replay synchronizes the
verified directory and parent again. The native sole-writer lock spans the
operation; it does not exclude hostile OS root.

No published journal history is reset to genesis. A journal that has advanced,
changed boot inputs, an unbound parent, vacant/wrong NV, or other conflicting
state does not qualify for this narrow exact enrollment replay. Product Admin
remains inactive and no role grant is issued. Existing-owner enrollment never
changes hierarchy authorization or clears/deletes another TPM allocation.

## Mandatory journal writer checks

The crate-private native journal append API now requires an authorizer supplied
by its trusted integrating service. It receives the exact immutable entry,
including request, actor UID, activity, payload digest and TPM clock, before
preparation, after the proposed journal is durably written and again after
proof readback directly before TPM dispatch. There is
no production append CLI or callback-free append method.

Before its final authority check and TPM advancement, the adapter also rechecks
the original journal head, exact canonical prepared bytes, authenticated TPM head and entry clock
epoch. Initial authorization denial leaves no preparation. Revocation or a
changed input after preparation leaves the proposal as a persistent fence and
does not dispatch a TPM write. Restart/retry never silently discards that fence
or replays an uncertain append. Existing reviewed committed-audit publication
remains separate.

The callback is a required integration boundary, not a complete authenticator
or role/policy implementation. A UID or audit record is still inert; the
future product service must authenticate its principal and enforce current
activity, grant, expiry and revocation semantics independently. Ordinary
effect authorization is not inferred from an audit append.

## Verification

Final targeted verification passed on 2026-10-04 against a frozen source snapshot at
`D:\LumaOS-builds\g2-enrollment-retry-targeted-20261004-03`.

- Build source manifest SHA-256: `ac52a0e2acc75db4d14b7cc1bed83769258365e2daac94a0bb0d5a11004d1072`.
- Supplementary test-input manifest SHA-256: `674db16861af8a039c4ed987bbd84bd29139a9f252dd9202253e9d1bc124ec29`.
- Completed test log SHA-256: `4b1ff73e4b6fb228ee1173503dd38b8b14a601e33fe5079cd9edd53bd41e50c8`.
- All 165 captured build inputs and eight separately hashed test inputs matched
  the current checkout after the run.
- All 47 selected ordinary Rust tests passed: 20 enrollment, 16 journal,
  five credential and six principal tests. This is a targeted regression, not
  a rerun of every Rust/hardware fixture.
- Existing-owner native enrollment, installed-format credential delivery under
  signed PCR11 renewal/fixed PCR7 refusal, and reviewed bound-parent continuation
  passed on disposable software TPMs. The legacy systemd 255 nonempty-owner
  refusal remains a compatibility result, not product enrollment acceptance.
- All five pending/publication TPM cases passed: committed, vacant, wrong head,
  process exit before rename and process exit immediately after successful
  rename but before parent-directory synchronization. The interrupted native
  test process owned the checkpoint lock; exit released it without destructors.
  Fresh reopen used the same review, published or replayed as appropriate, then
  repeated replay without another publication/TPM write. Final credential
  delivery recovered the original sealed secret.
- The real software-TPM committed-journal recovery regression passed after the
  mandatory writer API change. Unit tests also refused initial authorization,
  post-preparation revocation, changed original/prepared bytes and changed epoch
  without dispatch. A final authorization denial after proof readback also
  prevented dispatch; the read-only fixture panics if a TPM write is attempted.
- Formatting, the offline locked native build with warnings denied and two
  credential-delivery wiring checks passed.
- The CI TPM runner is wired to all four verified enrollment/
  continuation/publication/journal-recovery helpers and hashes the test-only
  C interposer. Its Bash syntax check passed; runner SHA-256 is
  `bf7405dc3687c791ee84efd5f13be755609d2390d9e02a7a22dedd2cebd9a70b`.
  It is included in the final supplementary test-input manifest. The full
  combined CI runner was not executed locally or remotely in this checkpoint.

The earlier `-01` checkpoint passed enrollment retry checks before the mandatory
writer API was added. The `-02` checkpoint passed that API before the final
post-readback authority check. Both remain retained; only the `-03` manifest
qualifies the final scope.

The run uses one CPU, 768 MiB memory with no extra swap, 128 PIDs, no network,
and no host TPM/device/socket. Docker storage, cache, snapshots and logs stay on
D:; source stays on C:. Only disposable software TPMs and test processes are
used. No image/VM/model sweep, WSL memory change or host TPM mutation occurs.

The abrupt-exit C interposer and callback stubs are test-only, not product
authentication or runtime fault switches. The software-TPM fixture does not
exercise the product terminal/PAM journey.

## Remaining production work

The [implementation-first backlog](../G2_IMPLEMENTATION_FIRST.md) remains open.
Complete the product Admin bootstrap/confined service, governed principal and
role lifecycle, production effect-time grants/receipts and wider enrollment,
journal-capacity, credential-loss and uncertain-write recovery. Trusted UTC,
signer lifecycle and actual custody remain separate. These increments do not
implement those services or independently recoverable credentials.

After the remaining implementation, freeze/build the integrated image and
perform the consolidated sweep and separate native Ubuntu qualification.
Process-exit fixtures do not establish physical power-loss durability, hardware
TPM behavior, installed PAM/service confinement or production signing custody.
