# Security policy

Luma OS `0.1.x` is a developer MVP. It is not hardened for production, untrusted multi-user access, remote exposure, or safety-critical decisions.

## Supported versions

| Version | Security updates |
| --- | --- |
| `0.1.x` | Best-effort during active MVP development |
| Earlier or unreleased snapshots | Not supported |

Security support means triage and source-level fixes where feasible. It does not imply a service-level agreement, certification, or warranty.

## Report a vulnerability

Do **not** open a public issue for a suspected vulnerability or include secrets, personal data, exploit payloads, or model weights in a report.

Email [info@teliosystems.com](mailto:info@teliosystems.com) with:

- a concise description and affected version or commit;
- reproduction steps using non-sensitive test data;
- expected impact and relevant environment details;
- any suggested mitigation; and
- a safe way to contact you.

Use the subject `Luma OS security report`. We aim to acknowledge a report within five business days. Validation and remediation timing depend on severity and reproducibility. Please allow a reasonable remediation window before public disclosure.

## MVP security assumptions

- The operator controls the local machine and repository checkout.
- Services bind to loopback and are not reachable from untrusted networks.
- Inputs, model output, file metadata, and tool output are untrusted.
- Approval prompts are a usability control, not a security boundary by themselves.
- External model runtimes and weights are outside this project's trust and licensing boundary.
- A compromised host, Python interpreter, browser, WSL distribution, or model runtime is out of scope.

## Safe operating guidance

1. Use synthetic or non-sensitive data only.
2. Keep the runtime on loopback; do not port-forward it.
3. Never store API keys, access tokens, passwords, or private keys in project configuration or logs.
4. Review every capability grant and generated plan before execution.
5. Run as an unprivileged user. The supplied scripts neither need nor invoke `sudo`.
6. Treat optional models, plugins, and tool adapters as third-party code and isolate them accordingly.
7. Stop the process and delete local runtime state if unexpected actions or disclosures occur.

The detailed trust boundaries, abuse cases, and residual risks are documented in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
