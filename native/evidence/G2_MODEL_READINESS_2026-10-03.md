# G2 model reconfiguration readiness checkpoint

Date: 2026-10-03. This source increment changes installed `model-install`
reconfiguration so a successful systemd restart request is no longer its last
success condition. It calls a fixed local health helper and then verifies that
the selected model unit is loaded and running with consistent selection,
reference environment and credential; the reference unit must also be active.
The helper reads only `http://127.0.0.1:8081/health`, disables proxy use and
redirects, accepts only a bounded HTTP 200 JSON response with `status=ok`,
and enforces a 300-second whole-operation deadline. No model prompt, token or
OS effect is sent through this probe.

If health never succeeds, the command exits nonzero and manual OS operation
remains available. The candidate selection may already have been committed;
the command does not silently roll back or claim that a prior worker was
restored. A listening endpoint and active unit do not prove an inference
response, bind the TCP listener cryptographically to the unit, or qualify a
post-stop failure policy. Initial installation still checks inference after
boot rather than during media installation. Native Ubuntu and consolidated
image tests must exercise this transition with real weights.

The final bounded offline source snapshot is
`D:\LumaOS-builds\g2-model-readiness-targeted-20261003-02`. Its frozen
`source/build-inputs.json` SHA-256 is
`eed717ea3c14ed2b996882a1d0085a206cbc641717574ee8ab312c769d9dd3c7`;
`test.log` SHA-256 is
`8b95427aaae211fa057354281390a5f2697aabbf677402b9bf7ad9eda4ee38e9`.
The D-backed Docker run used no external network, VM, host TPM or real LLM
load, with one CPU/Cargo job, 768 MiB, no extra swap and 128 PIDs. It passed
31 Rust model tests, seven model-runtime policy tests, four health-helper
tests including a loopback HTTP fixture, fifteen VM-harness unit tests,
formatting, a warning-clean offline build and compiled CLI help. No new image
or installed-system readiness transition was executed; G2 remains open.
