# Bounded local speech and human visual clarification

This is an auxiliary speech profile, not another text LLM and not a vision/OCR
model. The current profile is `whisper-tiny-multilingual-f16-cpu-v1`, using pinned
Whisper.cpp v1.9.5 source and the multilingual tiny F16 GGML weights. The initial
product decoder is **English only**. Qwen remains text-only. A transcript or
human-described visual relationship is untrusted data, not a verified citation,
an OS instruction or permission to apply a workflow.

## Build inputs and reproducible worker recipe

The normal image build acquires exact public inputs through `prepare_speech.py`;
`package_runtime.py` builds both fixed workers inside the image root before
signing. It does not run a model, open an audio device, generate signing keys or
grant runtime authority. The builder uses the complete pinned Whisper archive,
exact 77,691,713-byte model, original model notice, and exact Ubuntu eSpeak source
package plus Ubuntu patches. Missing bytes, changed hashes and unknown members
refuse. No host compiler installation is required.

`speech_policy.verify(root)` verifies the complete closed source/input inventory,
actual worker and policy/runtime hashes, embedded tokenizer and tensor closure,
required playback packages and reviewed confinement profiles. CPU compilation is
baseline amd64/SSE2; AVX/AVX2/FMA/F16C, native CPU tuning, GPU backends, network
backends and dynamic backend loading are disabled.

The image retains corresponding source and its fixed build commands under
`/usr/src/luma-speech`. Whisper and its model notices are MIT. eSpeak-NG is
GPL-3.0-or-later with its package-noticed exceptions: retain its corresponding
source, Ubuntu patches, package notices and the renderer's complete source/recipe
when redistributing. The source kit is not an untrusted-code execution grant.

## Provisioning authority before native ASR use

Downloading or packaging weights does **not** enable ASR. Complete these steps
through the existing Admin/model custody workflow on the intended installation:

1. Prepare the auxiliary pack/catalog metadata using
   `catalog.proposal(weights, license_bytes, signer_key_id)`. Its default profile
   is unavailable/unverified/untested. For an intended usable lab candidate,
   explicitly supply `lab_candidate=True` and the SHA-256 of the retained actual
   software test report as `software_test_report_sha256`. This proposes final
   immutable capability declarations; it does not sign or admit them, or create
   certificates. The catalog/profile digest must already match the candidate
   declarations when the image is assembled.
2. Have existing authorized model custodians approve and sign the actual trust,
   pack and catalog inputs. Provision their public outputs through the normal
   image input path. The ASR adapter is separate from the text/GGUF adapter but
   uses the same existing trust domain, signing separation and protected UTC.
   Do not generate a substitute signing root or edit a signed catalog by hand.
3. After native installation and required Admin/trust/release setup, inspect
   `model-pack-import-review` for this exact profile. Obtain the separately
   scoped Admin **model-import session, at most 30 minutes**, and its reviewed
   finite resource grant. `model-pack-import` copies the exact image-owned
   auxiliary weights into the signed retained pack under the normal acquisition
   lease. It performs no network download, text-model selection or serving
   activation. Incomplete copies are preserved for explicit review/retention.
4. Supply actual required qualification. A lab catalog's declared execution and
   interactive certifications require genuine separately signed lab inputs;
   metadata generation alone does not provide them. For production, test the
   actual final image on the actual machine. Use `model-qualification-observe`
   to obtain an unsigned measured descriptor naming the actual report digest,
   release, profile, runtime tuple, installation and machine. Existing authorized
   qualification custodians must sign the required execution and interactive
   records. Review and deliver the exact packages using the original Admin
   `model-qualification-review` / `model-qualification-install` finite workflow.
   Production certificates are delivered after final-image identity exists;
   they are not fabricated or embedded using a circular pre-build image hash.
5. Admit the correctly signed catalog using the existing Admin model command
   workflow. Current anchored custody, protected UTC, immutable public profile,
   retained pack bytes, runtime and required certifications must all agree.
   There is no separate persistent ASR text-model activation. It is explicitly
   on-demand, independent of whether the selected text LLM is available. Global
   Infer revocation still fences ASR.

The signing operations depend on existing authorized custody and its real key
identities. This guide intentionally supplies no invented signing command or
development key masquerading as production authority.

### Implemented native command shapes

These are verb/argument contracts for the existing authenticated native launcher,
not credentials, issued grants or permission to invoke internal workers directly.
`MODEL-ID` is `whisper-tiny-multilingual-f16-cpu-v1` in this guide. `LOGIN`, `GRANT`,
`INPUT`, `REQUEST` and digests are actual reviewed operator inputs, never defaults.

| Native verb and arguments | Purpose |
| --- | --- |
| `model-pack-import-review MODEL-ID` | Display the exact inert import/resource scope. |
| `model-pack-import LOGIN GRANT MODEL-ID` | Original Admin finite model-import purpose; copy and verify image bytes only. |
| `model-pack-pending-review MODEL-ID` | Inspect interrupted unverified import state without deleting or activating it. |
| `model-pack-pending-retain LOGIN GRANT MODEL-ID REVIEW-SHA256` | Fresh reviewed retention of an interrupted pack. |
| `model-qualification-observe MODEL-ID LEVEL REPORT-SHA256` | Unsigned actual-image/machine observation; `LEVEL` is execution or interactive. |
| `model-qualification-review MODEL-ID INPUT` | Inspect externally signed qualification and its exact finite provision scope. |
| `model-qualification-install LOGIN GRANT MODEL-ID INPUT` | Original Admin finite delivery with exact predecessor/replay checks. |
| `model-qualification-pending-review MODEL-ID` | Inspect interrupted unverified qualification delivery. |
| `model-qualification-pending-retain LOGIN GRANT MODEL-ID REVIEW-SHA256` | Preserve the exact interrupted qualification batch under fresh retention authority. |
| `speech-review REQUEST` | Current model/runtime and exact finite audio/Infer scope; returns data, not a grant. |
| `speech-transcribe LOGIN GRANT REQUEST` | Explicit auxiliary inference under fresh original authorization and broker resource generation. |

The trusted workspace constructs/stages `REQUEST` itself from one selected saved
capture. It is the canonical closed schema with version 1, this profile ID and
lowercase `pcm_hex`, not a caller-selected executable, model path, language or
decoder option. Use the workspace journey rather than starting resource workers.

## ASR limits and observed quality

The physical resource allowance remains **512 MiB**, no swap, 16 tasks and two
CPU equivalents (`CPUQuota=200%`) in the fixed serialized acquisition pool. The separately bounded
virtual address space is **1 GiB**: virtual reservations are not a second physical
allocation. A 512-MiB virtual ceiling was actually tested and failed; increasing
only that ceiling was approved and the final limits were retested. Do not change
the catalog/cgroup physical allowance to compensate.

Input is one mono 16-kHz S16LE utterance, 0.1 to 30 seconds / at most 960,000 PCM
bytes. Exact digital silence is refused. The model has 448 decoder positions;
the independent job output limit is fewer than 128 decoder tokens and at most
8,192 UTF-8 bytes. Decode is bounded to 18 wall-clock seconds, with a separate
20-second child fence and an 18-CPU-second worker limit. Reaching the token limit,
invalid output, cancellation or a lost generation is refusal, not clipped success.

Final offline engine diagnostics under observed 1-GiB virtual / 512-MiB physical
limits took about 8.3 seconds per tested utterance and peaked at 343,965,696 bytes
for the whole diagnostic cgroup. The upstream 22-word JFK fixture had zero word
errors; the synthetic eight-word English fixture had **four word errors (50%
WER)**. This tiny profile can hallucinate and mistranscribe. These two fixtures
are not broad English, multilingual, microphone or production-quality
qualification. They do not prove installed AppArmor/PAM/custody enforcement.

## Explicit human speech input and output

For input, open **Permission-bound capture**, explicitly consent, then press and
hold talk again; release/Stop ends capture. Explicitly save the completed local
`.luma-capture.zip`. Use **Transcribe saved audio** to select that one file and
open the separate native terminal. Review its actual PCM digest and finite Infer
scope, obtain a new exact grant, and explicitly confirm submission. The observed
transcript is escaped data. Correct it yourself before selecting a separate text
conversation, which obtains its own fresh model review and Infer authority.
Nothing is sent to a text LLM, published or acted on automatically.

For output, open **Speak reviewed text**, review/edit up to 4,096 UTF-8 bytes, then
click **Render reviewed text**. eSpeak's literal English rendering opens no audio
device. Only a separate **Play audio** click authorizes the bounded default local
output. Audio is at most 30 seconds, mono 22,050-Hz S16LE. Completion is not proof
that sound was audible.

Both capture and output query fresh unique-owner session lock state. Unknown,
locked or disconnected state refuses. Stop, hiding, lock, lock-service owner
replacement, bus loss and window destruction revoke the local generation and
discard pending data/audio. A queued click or accepted modal dialog cannot revive
an old generation. Uncertain process cleanup retains ownership and refuses
renewal; do not infer worker/resource release from a failed UI observation.

## Images, permitted screen samples and exact artifact references

Use **Clarify captured reference** for an explicitly saved image/screen/video
envelope. The terminal validates actual bounded PNG samples and requires the
exact capture ID, frame index and digest. Enter your literal human description
and the complete owner binding plus immutable artifact ID/version/content and
receipt digests. There is no guessed latest version.

Explicit confirmation starts a separate actual native Read/reopen with its own
finite Read grant and original authorization. Only after that delivery can you
review the complete proposed historical text snapshot and human-described sample
metadata, confirm its prompt digest and choose separately granted text-only
inference. Pixels are never forwarded; no OCR, pixel understanding or verified
capture-to-artifact semantic relationship is claimed. A later consequential
workflow still requires a new exact target/review and independent authority.

## Qualification evidence

The permanent component record is
`docs/gates/g3/speech_capture_clarification_2026-10-20.json`. It distinguishes actual
C/C++ engine jobs, actual production-worker refusal, ordered software boundary
fixtures and actual private D-Bus transport from native installed authorization
and hardware qualification. Final bootable-image testing must still confirm the
actual capture/output devices, session integration, enforcing profiles, PAM,
model custody, cancellation/drain and required production quality on the target.
