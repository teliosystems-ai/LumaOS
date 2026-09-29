# Native sealed credential checkpoint — 2026-09-29

**Selected software-TPM boundaries passed. G2 remains open.** This adds a
credential primitive, not installer enrollment, a running product Admin service,
installed update acceptance or physical TPM qualification. The sequence-4 image
was not rebuilt or changed. External Admin remains a future installer variant.

## Implemented and exercised

The Rust boundary invokes packaged systemd 255 using the explicit TPM-only
signed-key mode, SHA-256 PCR7 plus signed PCR11, an independently expected public
key and deployment-bound name. It rejects weaker/unknown credential profiles
before decryption and bounds input, output, helper time and parent secret memory.
See [implementation limitations](../LOCAL_TPM2_ADMIN.md).

The disposable TPM/signing-key fixture exercised:

- Exact binary secret round-trip, including NUL/CR/LF bytes.
- Rejection of changed deployment identity, substituted public key, missing
  policy signature and altered ciphertext that still passes the header filter.
- Refusal after PCR11 changes without approval; the same sealed blob opens
  after that measurement is signed by the original signer, without resealing.
- Refusal of a wrong private-key signature even when JSON claims the expected
  public-key fingerprint; restoring the valid signature permits access again.
- Persistence across TPM restart; changed PCR7 refuses access.
- A replacement software TPM cannot open the blob despite matching startup
  PCRs and a valid signed policy.
- Product entrypoints cannot select the emulator or environment fallback.

The ordinary Rust suite also checks canonical/bounded base64, truncated headers,
unapproved modes/PCR fields/signer bytes, credential domain syntax and protected
memory descriptor flags. The existing authenticated NV, journal rollback,
installer admission and VM fixture tests were rerun, not replaced.

## Evidence and repeatability

Final successful execution:
`D:\LumaOS-builds\native-tests-20260929-tpm-sealing-08`.
The [machine-readable record](native_tpm_sealing_2026-09-29.json) pins the tool
image and hashes of the transcript, results, Python test log and source inventory.
Source baseline is `8735919aee3812a308a0b27124ac5d7f074dd1b3` plus the exact
subsequent source identified by that inventory. Documentation added afterwards
does not alter the evaluated binary.

- Rust: **39 ordinary passed**, five emulator functions intentionally ignored
  in the ordinary suite, then **14 explicit emulator invocations passed**.
- TPM runner: **32 boundary labels passed** (labels are not distinct test functions).
- Linux Python: **14 passed**. Windows Python: **10 passed, 4 Linux-only skipped**.
- Offline locked debug build, warnings denied, and `cargo fmt --check` passed.

Run `native/tests/run_tpm_boundaries.sh` in the existing isolated tools container
with a read-only repository mount, writable D: evidence mount, no network, no
host TPM or privileged device access, and a fresh output directory. The runner
copies a source snapshot before compiling. No production signing keys, secrets,
emulator state or credentials are exported as evidence.

Earlier diagnostic runs are **not acceptance evidence**. They caught the
packaged helper ignoring the public key under plain `--with-key=tpm2`, and
fixture trial sessions accumulating on direct swtpm transport. The final code
uses `tpm2-with-public-key`, validates its output profile and explicitly flushes
each fixture-owned policy session. Temporary helper diagnostic overrides were
removed before the successful run. No TPM-wide session flush or host cleanup
was used to mask these failures.

## Remaining software and qualification

Authenticated enrollment must bind the signer, deployment and human principal;
reserve/provision the approved NV allocation without collisions or hierarchy
takeover; and fence interrupted enrollment. The sealed credential must then be
integrated into the confined native service with finite role assignment,
revocation, grants and durable effect reconciliation. Full helper working-memory
and process isolation, trusted time, signer rotation/revocation and independently
authorized recovery remain open. Signed PCR policies alone do not prevent boot
rollback to a previously signed image.

Next image evaluation must cover actual measured UKIs, service boot phase,
installed credential delivery, reboot, A/B update/fallback and recovery. Container
PCR extension is not proof of that flow. Physical TPM/firmware/bus/power-loss
qualification and production custody approval remain separate requirements.
