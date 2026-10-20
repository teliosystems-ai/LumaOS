# G3 held-out quality evidence protocol

`scripts/g3_quality.py` validates and aggregates externally executed quality
evidence. It never executes a corpus task, starts a model, runs a command from
an input, obtains a grant, changes an image or supplies native acceptance.
The schema is [g3_quality.schema.json](../../../schemas/g3_quality.schema.json).
The Python validator additionally enforces cross-file joins, UTF-8 byte limits,
uniqueness, exact measurements, file identities and freshness.

This supports the development plan's G3 weekly quality record and governing
Q10: 500 held-out core tasks, at least425 successes for compact or450 for
mainstream. Initial and final-attempt scores are separate. The tool does not
choose an allowable repair policy or turn a numeric threshold into gate closure.
Other latency, crash, sustained-load, energy and accessibility requirements need
their own actual experiments and qualification.

## Independently provision inputs

Use a private evidence directory containing ordinary single-link regular files.
All paths in documents are canonical relative paths with ASCII filename
components; no symlinks, reparse ancestors, hardlinks, absolute paths, streams,
`..`, globbing, URLs or executable commands are accepted. Documents are bounded
to4MiB, individual artifacts to16MiB and the unique retained file closure to128MiB.
Larger experiments require a separately reviewed protocol, not clipping.

Each file pin is exactly `{"path":"relative/name","bytes":123,"sha256":"…"}`.
Lists of named files contain exactly `{"name":"input","file":PIN}` entries,
strictly sorted by unique name. Digests are lowercase SHA256 of exact file bytes.
Canonical commitments use UTF-8 JSON, sorted keys, compact separators, unescaped
Unicode and no nonfinite values. Wire JSON rejects duplicate fields.

Provision and independently approve four document digests outside the model:

1. Corpus: schema1, corpus ID, classification `external-held-out`, exactly500
   tasks sorted by unique task ID. Every task declares nonempty retained inputs,
   expected `complete` or `refuse`, and one exact oracle. Distinct IDs cannot
   disguise identical retained input/disposition/oracle content. This detects
   literal duplication, not semantic duplication or training contamination.
2. Current manifest: schema1, unique run ID, compact/mainstream profile, corpus
   digest, start/end UTC and exact tuple hashes for source manifest, image
   manifest, model, runtime and machine identity. Run interval must be positive,
   at most24hours, not in the future and finished within7days by default.
   `--max-age-seconds` may only shorten that age. This uses the ingestion host's
   UTC for evidence freshness; it is not protected product UTC or certification.
3. Run: schema1, exact context and one complete observation per corpus task.
   Context contains run ID, corpus/current-manifest hashes and the exact tuple.
   Every task binds its canonical input-set digest and1–8 sequential attempts.
4. External adjudications: schema1, exact run digest, canonical context digest,
   origin `external-human`, and decisions for every completed human-rubric
   attempt. Use an empty decisions list if no human oracle is required.

The operator's independent pins are mandatory; a model-provided digest is not
an independent approval. This tool does not verify signing custody, full tuple
payloads such as multi-GB model weights, reviewer identity or measurement origin.
Those remain existing release/native authority and QA responsibilities. Receipt
correlations are data validation, not cryptographic authentication of execution.

## Oracles and observations

Supported deterministic oracles are exact literal bytes, strict typed JSON and
rectangular numeric CSV with exact decimal comparison. Numeric CSV accepts
fixed decimal literals only: no formulas, exponents, nonfinite values, rounding
or implicit evaluation. These oracles compare actual retained output artifacts,
not a model assertion, a claimed exit status or a claimed test pass.
JSON oracle fractional/exponent literals use exact decimal values, with at
most96 characters and adjusted exponent magnitude at most10,000; integer and
fractional JSON number types remain distinct. Floating-point underflow or
rounding cannot turn an incorrect answer into a match. Malformed actual JSON or
numeric CSV is an observed task-oracle failure, not an aborted aggregate;
malformed expected oracles or evidence envelopes still refuse ingestion.

Qualitative tasks use a retained human rubric. A separately pinned decision
names reviewer, reason, task/attempt, exact rubric hash and exact output-set
hash, and explicitly says pass/fail. Missing, duplicate, extra or mismatched
decisions refuse the aggregate. Reviewer names are asserted external identities;
the protocol does not authenticate a person or prove that no model judged them.
Expected-refusal tasks use `must-refuse`; a refusal with returned artifacts is
not a successful refusal. Wrong refusals on permitted tasks remain false refusals.

Attempts retain completed/refused/failed/cancelled disposition, reason, output
pins, a correlation receipt and a measurement pin. Failed/cancelled partial
artifacts may be retained but never pass a completion oracle. A receipt must
join run/task/attempt, context, input/output-set digests and status, with
`authority_returned:false`. Native receipt bytes may be retained as an additional
named artifact; the correlation wrapper is not itself a native effect receipt.

Measurement records use run-relative monotonic integer nanoseconds. They bind
run/task/attempt/context and start/end, acknowledgement, optional first result
and cancellation request/ack times. Completed attempts need first-result and
artifact observations. Cancellation fields must be complete and correspond to
cancelled attempts. This initial protocol is serialized: attempts cannot overlap
or move backwards. It does not represent a concurrent30-minute mixed workload.

Each measurement also pins an exact decimal peak-memory counter file ending in
a newline and a closed energy record. Energy records join the same context and
measurement interval, name a kernel-counter/external-meter method and domain,
and retain monotonic start/end integer microjoule counters. Wrapped counters,
estimates, absent readings, negative values and booleans-as-integers refuse.
Normalize an actual instrument's wrap externally with retained methodology;
do not invent a zero reading when no energy observation exists. Different
methods/domains are reported separately, never summed as equivalent meters.

## Commands and results

Validate the independently pinned corpus before running any actual journey:

```text
python scripts/g3_quality.py validate-corpus --evidence-root DIRECTORY --corpus corpus.json --corpus-sha256 APPROVED_HASH
```

Execute the actual tasks separately using existing authorized product/native
ceremonies and measurement instruments. Then ingest complete retained evidence:

```text
python scripts/g3_quality.py aggregate --evidence-root DIRECTORY --corpus corpus.json --corpus-sha256 APPROVED_HASH --current-manifest manifest.json --current-manifest-sha256 APPROVED_HASH --run run.json --run-sha256 APPROVED_HASH --adjudications adjudications.json --adjudications-sha256 APPROVED_HASH
```

Successful ingestion writes one JSON report to stdout and exits0; malformed or
incomplete evidence exits2 with no report. Exit0 means valid evidence ingestion,
not passing quality: inspect both Q10 threshold booleans and the full task list.
The output preserves every attempt, initial/final successes, failures/refusals,
false refusals, cancellations, retries and repairs. Nearest-rank P95 timings and
memory and per-meter energy totals include every attempt, not only successful
ones. A final re-observation verifies the complete retained file closure before
any report is delivered. All production, installed and gate-closing claims stay
false. There is no bundled or invented held-out corpus and no claimed product
quality result. Unit fixtures are explicitly synthetic protocol tests only.
