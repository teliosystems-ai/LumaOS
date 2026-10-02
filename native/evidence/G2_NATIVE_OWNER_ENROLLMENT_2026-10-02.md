# G2 native existing owner checkpoint enrollment checkpoint

The source now uses a fixed persistent TPM parent and a native sealed child for
the selected existing-owner installation variant. A positive checkpoint
enrollment and fixed-path credential delivery passed on an isolated disposable
software TPM. This is an inert checkpoint, not product Admin activation or G2
acceptance. No physical TPM, installed image, model or VM was used in this run.

The parent allocation at `0x81004c41` follows a synchronized private intent
containing the exact enrollment record and boot-input digests. Its Name is
retained and bound into the schema-v3 proposal and native credential envelope.
The independent NV index at `0x01804c41` is provisioned only after the sealed
secret has been recovered under the image-owned signer, signed current PCR 11
and fixed PCR 7. Both writes are one-shot and an interrupted attempt remains
fenced; there is no automatic delete, retry, owner change or TPM clear.

The D-backed targeted run is
`D:\LumaOS-builds\g2-native-seal-targeted-20261002-07`.
Its frozen source manifest SHA-256 is
`de6b734f4c6dbfee5a9f54191455e60c1bf2da2ee4faa1c7d8f56dbb898a8ade`;
the completed log SHA-256 is
`85211699ff2358462fe16703cd344251678390aed7ed6d8c31df131e523d3220`.
The separately copied native test scripts have SHA-256 values
`97b93232ca1279b09277bcd6e04a84c1077365fe7c332882d1300c2ec58e09d7`,
`4b5f9e98939344b7eec478abf708852ef6f93de0b037a8c7e17782fc8ef48364`,
`9bf5313e11eb1f698fe1bbf70d7fbbccd932ea8ab2b5c5550219035ab181b661`
and `ebbffdeb3389558bd1893442da0f6985f2872b2d30e4c2a507760ecd0343bded`.

Formatting, selected ordinary Rust suites and a warning-clean offline native
build passed. Explicit disposable-TPM modes covered owner-protected parent
creation, sealed-child/envelope allow and refusal cases, forged signed policy,
PCR 11 renewal, PCR 7 refusal, restart continuity, the legacy systemd 255
refusal, and positive native enrollment followed by repeated credential delivery
across unsigned and signed PCR 11 changes and PCR 7 denial. The
ordinary transaction tests covered durable parent intent and no retry after
uncertain writes. A targeted pass is not a full regression or a booted-image
qualification.

Reviewed interrupted-enrollment recovery, full product Admin service and
roles, signer/custody and trusted-time lifecycle, confined secret handling,
installed A/B boot policy evaluation, physical security and recovery tests
remain open. The earlier failed snapshots are retained and are not recast as
passing evidence. Build/cache/evidence stayed on D:; WSL memory and unrelated
workloads were unchanged.
