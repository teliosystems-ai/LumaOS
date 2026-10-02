# Native model reply validation and WSL impact - 2026-10-01

G2 remains **incomplete**. Earlier uncommitted host-memory admission changes
were preserved. No WSL memory change, service restart, image build or large VM
launch was performed in this continuation.

## Host decision remains conditional

The owner approved a planned WSL increase only if other running processes
would not be affected. The read-only Windows observation reported 16,591,532
KiB visible physical RAM and 2,311,760 KiB free (about 2.2 GiB free). There is
no existing `C:\Users\hakim\.wslconfig`; this continuation did not create one.
Ubuntu reported 7,847 MiB total and 6,643 MiB available at its observation.
These are point-in-time, non-atomic observations and not resource reservations.

The default daemon listed six running workloads: `compose-tempo-1`,
`compose-grafana-1`, `compose-prometheus-1`, `compose-collector-1`,
`q-manager-control-plane` and `registry`. The dedicated Luma daemon listed no
running job at this check. No listed workload was stopped or reconfigured.

Raising a memory ceiling permits greater consumption; it cannot promise no
impact on Windows memory pressure. Applying WSL configuration requires the
WSL VM to stop/restart, and `wsl --shutdown` interrupts all running
distributions. See [Microsoft's configuration documentation](https://learn.microsoft.com/en-us/windows/wsl/wsl-config).
The owner was asked to choose a planned interruption or the separate native
Ubuntu test machine. Conditional no-impact approval was not treated as restart
authorization. A proposed 10 GiB ceiling still requires actual Windows and
Linux headroom review before another 6 GiB guest is admitted.

## Native inference repair

The existing helper bounded transport time/response bytes but labeled output
with the locally selected model without checking the response model, and
forwarded arbitrary `usage` metadata. A malformed completion could therefore
become a successful CLI result even though later VM acceptance might reject
it. Validation now happens at the actual CLI response boundary.

The response must identify the selected runtime alias and `chat.completion`,
contain exactly one index-zero completed assistant message with nonempty text,
and finish with `stop` or `length`. Nonempty tool calls, function calls,
refusals, malformed/duplicate-key JSON and nonfinite JSON constants are denied.
Prompt/completion/total counts must be integers (not booleans), positive where
required, internally consistent and within the caller's completion-token
budget. Only those three usage counters are returned. Arbitrary extra runtime
metadata is not forwarded as trusted evidence. Validation failure exits
nonzero with a generic diagnostic and no successful JSON result or raw runtime
error details. Existing fixed loopback authority, no-proxy/no-redirect behavior,
whole-request deadline and no OS-effect dispatch remain unchanged.

These checks validate a response contract, not an attested model identity or
independent tokenizer measurement. Runtime-reported alias/counts can still lie;
governed pack admission and full model lifecycle remain separate open work.
Model text is untrusted text, not executable instructions or policy authority.

## Executed checks and retained evidence

All **133 native Linux Python tests passed**, warnings treated as errors.
Six new parser/CLI-oracle tests cover success, metadata filtering, wrong model,
ambiguous choices, tool dispatch, invalid usage, duplicate/malformed JSON and
non-disclosing CLI failure. A separate isolated 128 MiB container ran six real
subprocess/HTTP cases: valid response, wrong model, over-budget completion,
tool-call output, duplicate model key and malformed JSON. Every request used
the fixed authenticated loopback endpoint; every rejection had nonzero exit
and no success output. No public fixture token appeared in CLI output.

The HTTP replies were **synthetic**, not model inference. This fixture is not
an image boot, production catalog or G2 acceptance pass. The full regression
container was capped at 512 MiB; neither test container exposed host devices,
host sockets or outbound networking. All bulk evidence stays on D:.

Evidence directory: `D:\LumaOS-builds\g2-model-reply-tests-20261001-01`.
Frozen build-input manifest SHA-256:
`89a05139976ae8a77b0fdff963e23b79ddd20ecbd35db1e68cd7af48bbb6fd6f`.
Completed test log SHA-256:
`6ff3795585b59b41741aa45d7036ffb0e80065fe0d3f2e6e1e645fc6920fb652`.
Native tests were copied separately into that frozen tree. Rust was unchanged
and was not retested. Source checks do not qualify existing image bytes.

The changed helper is **not in sequence 11**. It must be rebuilt together with
the pending broker and installer RAM fixes, then exercised against the pinned
real runtime/model. Admin enrollment/policy, signed skills/vertical workflow,
full model resources/lifecycle, generated-code isolation and the remaining
image/physical matrices still prevent G2 closure; increasing WSL memory does
not implement or waive any of them.
