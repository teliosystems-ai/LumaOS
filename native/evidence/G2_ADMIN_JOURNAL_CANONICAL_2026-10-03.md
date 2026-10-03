# G2 Admin journal canonical byte validation

Status: targeted source and disposable software-TPM checks passed on 2026-10-03. This is a checkpoint-hardening increment, not product Admin activation or G2 acceptance. No OS image or physical TPM was tested.

The native journal writer emits compact JSON in a fixed field order. Previously, normal reads and recovery parsed the file and compared its event-derived head with the TPM, so an equivalent rewrite of the JSON bytes could pass that semantic check. `Store::open`, `Store::status` and pending-publication inspection now require the on-disk bytes to exactly equal the writer's serialized representation. A noncanonical current or pending file is refused and preserved; recovery does not rewrite it or advance the TPM.

The regression tests cover whitespace and field-order rewrites of semantically identical current journals, and whitespace rewrites of both recovery inputs. Two disposable software-TPM fixture writers were aligned with the compact production format. The first targeted run retained at `D:\LumaOS-builds\g2-admin-canonical-targeted-20261003-01` failed because one fixture still emitted spaced JSON; the corrected run is below.

## Bounded verification

Evidence: `D:\LumaOS-builds\g2-admin-canonical-targeted-20261003-02`.

- Source snapshot manifest SHA-256: `c437c93ba4fa9af75fd79fb42cae096fd93139d17f30eb6e214359575fabc443`.
- Completed test log SHA-256: `359a76b767713bf759531530701c29550962322e52abee6d381148a5056fbfa0`.
- Separately copied software-TPM recovery fixture SHA-256: `f03d0b2bb28461928b9db7092dc700b4abf6cbc8c9acb2452285d928962e0126`.
- Separately copied broader TPM fixture SHA-256: `fcfb59f10a532ed1db340ab07ae9bc2e18c5ed2e56935eacc2c424189e9194eb`; that broader fixture was not run in this bounded check.

The offline D-backed tools container passed formatting, 12 `admin_journal` unit tests, one isolated software-TPM lost-reply and reviewed-publication invocation, and the native build with warnings denied. It had one CPU, 768 MiB memory with no extra swap, 128 PIDs, no host TPM or Docker socket, and no network. WSL memory settings were not changed.

The journal remains inert audit data. This result does not establish authenticated product Admin assignment, governed effect authorization, interrupted enrollment recovery, installed-image operation, production custody, hostile-root resistance or physical power-loss recovery. Those remain in the G2 implementation and qualification backlog.
