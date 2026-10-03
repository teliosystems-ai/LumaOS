# G2 retained enrollment record validation

Status: bounded source and disposable software-TPM checks passed on
2026-10-03. This increment makes checkpoint-enrollment inspection reject a
retained record that is not the canonical, inert existing-owner profile. It
does not activate product Admin or close G2.

The parent intent already binds its record by a deployment hash. Hash
agreement alone, however, does not establish that the record has the required
no-role-grant profile. The native path now validates that profile when creating
an intent and when reading a retained intent for inspection. A forged record
that claims `role_grant: true`, even with a correspondingly updated intent
hash, is rejected before TPM handle observation; the retained files are not
repaired or removed. Disposable fixtures now use the same inert record profile
as the product enrollment path.

## Bounded verification

Passing evidence: `D:\LumaOS-builds\g2-enrollment-record-targeted-20261003-02`.

- Source snapshot manifest SHA-256: `d8d4ed6ee473550c13f3a6ba416c3a2292d32fe2942859afbc1c1744d1695134`.
- Completed test log SHA-256: `83ffa337e618e2ac18264d47299a47f09b6200d609b8e2f6188a0430fb76d764`.
- Separately copied software-TPM fixture driver SHA-256: `c6191ed72e3ce2263d62ae68556b286da6da0e410a8d800e84ecb7d1c0fb7d39`.

The offline D-backed container passed formatting, 16 ordinary
`admin_enrollment` tests, isolated software-TPM positive enrollment and
delivery, reviewed bound-parent continuation, committed pending publication,
vacant NV and wrong-head refusal, and the native build with warnings denied.
It used one CPU, 768 MiB memory with no extra swap, 128 PIDs and no network.
The first snapshot at `D:\LumaOS-builds\g2-enrollment-record-targeted-20261003-01`
failed compilation because a test helper accepted JSON values but the existing
fixture supplies a serializable admission reference; the helper was corrected
and that failed snapshot retained.

These checks do not establish installed-image enrollment, actual custody,
hardware TPM behavior, product Admin roles, or a general
interrupted-enrollment recovery procedure. Unbound parent, vacant or mismatched
NV, and other uncertain states remain fenced rather than retried or reset. The
separate native Ubuntu image and physical qualification remain outstanding.
