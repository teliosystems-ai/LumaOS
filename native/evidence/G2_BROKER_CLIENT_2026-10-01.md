# Native broker client and desktop export checkpoint - 2026-10-01

G2 remains **incomplete**. This checkpoint distinguishes source repairs from
the already-frozen sequence-11 desktop image; the repair below is not in that
image and requires a later rebuild and image-level evaluation.

## Broker response handling

The native CLI previously printed any framed broker response and returned
success, including a denial or malformed response. It now deserializes a
closed response, requires the supported schema and implementation, correlates
the request ID and authenticated UID, and accepts only an explicit success.
Unexpected authority/generated-code claims, extra/duplicate fields, malformed
JSON and trailing data fail. Unvalidated peer payloads are never printed.
Request output and response input share one three-second monotonic budget
after connection and kernel peer authentication. This is not an execution
deadline or cancellation guarantee for a server-side effect.

Four Rust regression tests exercise response validation, real framed socket
exchange and refusal before sending with an expired budget. The separate
`native/tests/broker_client_integration.py` executes the compiled CLI against
a private root-owned fixture socket in a disposable container, checking actual
exit status and output for success and 13 negative cases. It is deliberately
not ordinary unittest discovery: it requires an isolated root container and
refuses an existing broker namespace or reused evidence directory.

The integration command inside that isolated container is:

```sh
python3 /repo/native/tests/broker_client_integration.py \
  --binary /tmp/luma-broker-target/debug/luma-platform --output /evidence/cli
```

Never mount a host broker socket or host `/run` into this fixture. It does not
test real broker authorization, product Admin enrollment or a booted image.
The server's finite laboratory policy is unchanged; root is not a substitute
for the required product Admin service. Durable effects, policy grants,
revocation, request fairness and the remaining G2 integration remain open.

## Verification

The D-backed frozen source run is recorded under
`D:\LumaOS-builds\g2-broker-client-tests-20261001-01`.
It passed formatting checks, offline locked Rust tests/build with warnings
denied, all **59 ordinary Rust tests**, all **14 real CLI cases**, and all
**112 native Linux Python tests** (Python warnings treated as errors).
Seven specialized Rust tests were ignored in this ordinary run; their earlier
separate emulator/PAM/disk-full results are not reruns of this source repair.
The container had no network, no host devices and a 768 MiB/one-CPU limit.
The complete verification process exited successfully. `git diff --check`
also passed.

Frozen input identities:

- `source/build-inputs.json` SHA-256:
  `fbdc54a0aad18597f7c57b64bd0a730577bdc1a43508ed11d9434428f6ea7b47`.
- `source/native/tests/broker_client_integration.py` SHA-256:
  `6c6c29784b0e220daec0e30355229364103333264f35319aa551d58fd6053191`.
- Completed `test.log` SHA-256:
  `e35b5670af70ac99d745d9470abcbb0ce85b61422a22924628d36808749b6f3d`.
- `cli/result.json` SHA-256:
  `d513ce76c53d925023e72e4980b556e9568524891a000b5ad65edbf2bb1918b9`.
- Executed debug binary SHA-256 (also recorded in the CLI result):
  `5314f057ff066306bab50f2b55d5ecaf7b2a44b375a3c369b92c86716bc07fc8`.

The image-source manifest includes the Rust repair. Native tests are copied
separately into the frozen tree; the fixture digest above identifies the
executed CLI harness. Later documentation edits do not modify those inputs.

## Sequence-11 desktop image

Build `20261001T090338Z-desktop` completed assembly and verified export to:

`D:\LumaOS-builds\native\20261001T090338Z-desktop`

- Media: `luma-native-lab-20260927-desktop-11.img.zst`.
- Compressed SHA-256:
  `26f82ffb3f3af2f88f8a6c4a9bfb14084732c6383c94b246a2b0e0c6d4147790`.
- Uncompressed image SHA-256:
  `96f0083cf64e7d968992256da96f3ed9f1a24d1696ed6c5d8be7a72ca66e264b`.
- Captured build-input SHA-256:
  `8596a569b0cb3be9ef065d90e816bf22ce783676ab8978cbc92828e6d8a6d85b`.

The export includes public release metadata/signature, Secure Boot certificate,
package locks, source archive and boot policy. Private signing keys remain in
their retained D-backed Docker volume and must not be published. The raw image
remains in the build's `work/.../artifacts` directory; public export is compressed.

This is a **laboratory-signed candidate**, not the final all-components G2 OS.
It contains the GNOME/Wayland profile, pinned CPU model installer/runtime,
earlier atomic recovery export and bounded frame I/O, plus the bounded model
request helper. It does not contain this later broker client repair.

The desktop acceptance queue has observed completed export and passed the
D-backed storage preflight; artifact verification precedes its fresh virtual
installation. The 4B installer/inference queue remains serialized behind a
passing desktop result. Neither pending evaluation counts as acceptance.
Full graphical authentication/locking/workflow, product Admin/policy/effects,
signed skills, complete model lifecycle, remaining fault matrices, production
custody and physical qualification are still open in the software register.
