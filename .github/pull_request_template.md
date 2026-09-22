## Outcome

Describe the user or engineering outcome and why this is the smallest useful change.

## Scope and risk

- Components/trust boundaries changed:
- Local data or durable effects changed:
- Unsupported-scope implications:

## Verification

- [ ] `make check` passes locally.
- [ ] Tests cover success and relevant failure/policy paths.
- [ ] No secrets, personal data, model weights, generated archives, or runtime state are included.
- [ ] Architecture, threat model, schemas, support matrix, and changelog are updated where needed.
- [ ] The change preserves loopback/local-only defaults and manual operation without a model.
- [ ] Simulator behavior is not used as runtime acceptance evidence.

## Manual evidence

List any local smoke steps and use only synthetic data. Do not attach sensitive logs or databases.
