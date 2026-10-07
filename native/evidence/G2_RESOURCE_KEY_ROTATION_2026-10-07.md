# Native reference credential rotation checkpoint

On 2026-10-07, Requirement #1 gained fenced runtime-key rotation and the
installed reference service's default migration to broker-mediated inference.
Selected source and protocol regressions pass. **Requirement #1 and G2 remain
open** for broader resource integrations, governance/recovery and installed
qualification. Requirement #2 has not been started.

## Implemented boundary

Activation now generates a fresh 256-bit runtime key, refuses unchanged-key
publication, writes a key-free native-broker environment and publishes the
canonical version-2 selection last. Final ownership/modes and affected
directories are synchronized before activation can clear. Errors retain the
existing pending records. Admission and ongoing supervision refuse older
version-1 selections; the installed reference unit defaults to native-broker.

Explicit legacy migration accepts either exact former environment layout,
verifies weights before stopping the model/reference services and verifies
again under runtime exclusion. It rotates rather than copies the exposed key.
Conflicting settings, unsafe files, pending lifecycle state and bad weights
refuse; restart requests do not claim readiness. Root maintenance is not
product Admin/session authorization or signed production custody.

Interrupted and completed restoration refuse exposed version-1 credentials
before writing. Reconciliation cannot publish an environment/selection-only
migration that retained the exposed key. Exact rollback between consistent
private version-2 configurations remains functional. Obsolete worker-writable
files and private recovery bytes remain for investigation, not as an older-image
fallback. Broader damaged/legacy lifecycle recovery remains open.

## Verification and limits

Evidence: `D:\LumaOS-builds\g2-resources-targeted-20261007-13`. The frozen runner
exited zero; all **208 source files and 88 test inputs** matched the checkout
after execution. Builds, cache, temporary state and evidence used D. The pinned
tool image used one CPU, CPU affinity, a 1-GiB container ceiling, no extra swap
or network, locked offline Cargo and warnings denied. No WSL configuration,
host service, installed credential or TPM ownership changed.

| Selected check | Actual result |
| --- | --- |
| Resource core | 18 passed |
| Native manager, requests, peer proof, history and recovery | 87 passed |
| Acquisition and storage | 6 passed |
| Broker transport | 25 passed |
| Model lifecycle, supervision, rotation and gateway | 135 passed |
| Python policy, native client and selected reference regressions | 155 passed; one existing Windows-junction-only check skipped on Linux |
| Native history CLI | 24 synthetic-authority cases passed |
| Native model-chat CLI | 16 cases passed, including five pre-IO selection refusals |
| Formatting, warnings-denied build, AppArmor syntax and 56 pinned runtime parser options | Passed; no model loaded |
| Actual systemd unit graph verifier | Exit 1: tool image lacks `apparmor.service`; not a passing installed graph |

Total: **426 passing selected tests plus 40 CLI protocol cases**. Two existing
owned-child entrypoints are ignored at top-level but exercised by parent
fixtures, not counted twice. No new Requirement #1 test is skipped. DAC fixtures
use real isolated model/reference UIDs; the broker/runtime CLI authorities are
synthetic. These results do not establish installed confinement, real-model
execution, old-key rejection by the actual serving binary or power-loss recovery.
The broader Windows suite was not rerun.

Earlier attempts remain retained: a test warning, two changed fixture
assumptions and an unversioned Python selection fixture were corrected. The
superseded sweep was explicitly stopped with exit 137 after the durability
barrier was added; its artifacts remain. This final sweep tested the complete
finalized source, without reusing those attempts as passing evidence.

## Evidence digests

These SHA-256 values identify unsigned laboratory evidence, not production
custody or reproducibility attestation.

| Artifact relative to the evidence directory | SHA-256 |
| --- | --- |
| `source/build-inputs.json` | `7421311596bfe3862041aa5abc123587ab29a25a8640eafaadc683f8973a9d29` |
| `test-inputs.sha256` | `0635eec5493e4d7437fb9ec6256718e7de4b28272ed751f99d190f2fd095941e` |
| `test.log` | `8ec1977a9a760827d5b4030bc60cace19e3808e0f18a85c0270490fb3b53d6b0` |
| `checks/targeted-runner.sh` | `428024adca5343348dd66217cf9bd1a6164e92224678db08d33d730360964f56` |
| `checks/sweep-exit.txt` | `9a271f2a916b0b6ee6cecb2426f0b3206ef074578be55d9bc94f6f3fe3ab86aa` |
| `checks/unit-verification.txt` | `cc6d6ba4f56881e50612c693db5577418157f96999327fbac956e538602db498` |
| `checks/resource-history-artifacts.sha256` | `41abd7c7a4fc77a6fd4797b14b5434fcb4912becc0a4a9301f0e8b48e2046281` |

The compiled native binary digest is
`c3e52c309c4e180bf7ddd3a7b8c355490bfd1b1d0c2a81114be2382a059552fd`.
The test-only preload remains outside the production installation.

## Remaining Requirement 1 work

Content/workflow worker leases, product principal/session grants, broader
inference consumers, tenant/device generation adapters, governed export/deletion
and retention/recovery remain open. The consolidated image still needs actual
model/tokenizer, confinement, descendant drainage, pressure/OOM, suspend,
storage/crash/restart and upgrade/rollback evaluation, followed by the separate
native Ubuntu qualification. See [the completion register](../G2_SOFTWARE_STATUS.md)
and [resource contract](../RESOURCE_LEASES.md). This checkpoint does not declare
production readiness or authorize proceeding to Requirement #2.
