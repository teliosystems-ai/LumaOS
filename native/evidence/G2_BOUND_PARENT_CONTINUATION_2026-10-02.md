# G2 bound parent enrollment continuation checkpoint

The source now permits one explicit continuation of checkpoint enrollment
after the persistent parent Name was durably recorded but before an NV proposal
or index exists. The operator must first inspect the fixed state and supply
its exact observation digest. Fresh account and existing-owner authorization,
the original principal and boot inputs, and the matching fixed parent profile
are checked before a newly sealed proposal and one-shot NV allocation. The
parent is not recreated. This enrolls an inert checkpoint, not product Admin.

A disposable software-TPM test passed parent allocation, review of the
bound-parent/no-NV state, native sealing, one NV provisioning transaction,
published credential delivery and refusal to resume again. Unit tests reject
stale review, occupied NV, a pending proposal, noncanonical or role-granting
retained records. The D-backed bounded run is
`D:\LumaOS-builds\g2-native-seal-targeted-20261002-10`; frozen source manifest
SHA-256 is `b2f1088eb5ea0d4e4d251bf8ea0c76311ba395f634691ab9488a57fae4110a40`
and completed log SHA-256 is
`0038d3b9479932832011e2f8bd9821f4ad7c984fed9dacbf6df7c4483c5120ec`.

This test exercised the transaction core with a fixture, not the installed
CLI's real PAM conversation or a physical interruption. An unbound parent,
pending proposal, uncertain NV write, occupied index, changed signer policy
or final-publication ambiguity still refuses this continuation. No TPM state
was changed outside a disposable software TPM. Full reviewed recovery,
installed-image qualification and G2 completion remain open.
