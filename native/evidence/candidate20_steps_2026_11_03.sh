#!/bin/bash
# Sequence-20 native desktop steps (profile N), parameterized by the cut.
# Each step is a versioned copy of the executed sequence-19 wrapper with the
# same name in .luma/candidate19-*-20261028.sh. The sequence-19 wrappers,
# outputs and evidence are never changed or reused as outputs.
#
# Run as root in Ubuntu WSL, from any directory:
#   bash native/evidence/candidate20_steps_2026_11_03.sh STEP ARGS...
#
#   plan         CUT LETTER                    print the plan; changes nothing
#   preflight    STEP                          read-only admission for STEP
#   freeze       CUT LETTER                    light; no lock
#   source-tests LETTER FROZEN ATTEMPT [RUST_TEST_FILTER]   heavy
#   assemble     LETTER FROZEN                 heavy, about 70 minutes
#   verify       LETTER FROZEN BUILD_ID        heavy, about 20 minutes
#   update-compat LETTER BUILD_ID              light, read-only: 19 -> 20 update geometry
#   smoke       LETTER FROZEN BUILD_ID MEDIUM heavy; MEDIUM is usb-disk, virtio-disk or optical
#   download     LETTER FROZEN BUILD_ID [copy] heavy; never signs, uploads or publishes
#   download19   LETTER FROZEN [copy]          the same layout for the sequence-19 export
#
# CUT is the 40-hex commit the main checkout must be at; LETTER is the attempt
# letter (a-z); FROZEN is the build-inputs.json SHA-256 that freeze prints and
# the coordinator approves. Heavy steps need the heavy-job lock held under
# LUMA_LOCK_OWNER (the first word of locks/heavy.lock/owner), mains power, no
# running container and the RAM and disk floors in floors() below.
set -euo pipefail

REPO=/mnt/c/Users/hakim/LumaOS
WORK=/mnt/luma-build/work
D=/mnt/d/LumaOS-builds
LOCK=$D/locks/heavy.lock
DAY=20261103
TOOLS=sha256:819dfe7772da1e3c76ffdc8f9ea4a1fa44c7c549bd4fa988e35d9397d87924b2
RELEASE=luma-native-lab-20260927-desktop-20
CERT_SHA256=2637785a3cb4798db902bf62732324984d3f2475d7f2eecc318442772d9c06c8
RELEASE_PUBLIC_SHA256=62588a16a8901fbdf20cdfee1c1df5c243e85022693f6edb275a51366d01878f
PCR_PUBLIC_SHA256=b55221f37d366b64367db37394852d7af70b328a9c8173f5aa2e499762bfad26
VERIFIER=native/evidence/candidate20_image_verify_2026_11_03.py
VERIFIER_SHA256=0bf5e76526ee06d12d73eb158ca2e5e9c41fa2e18b76bcd7fc50362488dfddfa
PRIOR=$WORK/candidate19-source-20261028-a
PRIOR_SHA256=7d05afd79e9e26ed689c3d5c4ed6764da037f6aa21bab1a94546ca8087252be8
INPUTS=$D/native-inputs/20261019T135331Z-desktop
SPEECH=$WORK/speech-input-20261020-Y1z2j35g/cache
SEQ19_BUILD=20261028T162354Z-desktop
SEQ19_COMMIT=6528ea1411b2dc0057bbc1ecdbaad538df21b4f3
SEQ19_SUMS_SHA256=d440805f8c8aabe69a7dfc852acabadbbdb57eb04ff19e587d59847ce85492bf

die() { echo "candidate20: $*" >&2; exit 2; }
step=${1:-}; shift || true
letter_ok() { [[ "${1:-}" =~ ^[a-z]$ ]] || die 'attempt letter must be one lowercase letter'; }
sha_ok() { [[ "${1:-}" =~ ^[0-9a-f]{64}$ ]] || die 'a 64-hex SHA-256 is required'; }
build_ok() { [[ "${1:-}" =~ ^2026(1[1-2])[0-3][0-9]T[0-9]{6}Z-desktop$ ]] || die 'a sequence-20 build ID is required'; }
paths() {
    frozen=$WORK/candidate20-source-$DAY-$1
    aids=$WORK/candidate20-aids-$DAY-$1
}

# Floors per step: MemAvailable GiB, D free GiB, store free GiB.
floors() {
    case $1 in
        freeze) echo '1 1 1';;
        source-tests) echo '3 1 4';;
        assemble) echo '9 40 32';;
        verify) echo '3 1 2';;
        smoke) echo '10 1 2';;
        download|download19) echo '3 30 1';;
        *) die "unknown step $1";;
    esac
}

host_check() {  # STEP: read-only; fails closed
    local name=$1 memory dfree sfree power owner limits
    limits=$(floors "$name")
    read -r memory dfree sfree <<< "$limits"
    source /etc/luma-build/environment.sh
    local available
    available=$(awk '/^MemAvailable:/{print int($2/1048576)}' /proc/meminfo)
    echo "MemAvailable ${available} GiB (floor $memory)"
    [ "$available" -ge "$memory" ] || die "MemAvailable below $memory GiB; stop other work first (never raise WSL memory)"
    local d_free s_free
    d_free=$(df -B1G --output=avail "$D" | tail -1 | tr -d ' ')
    s_free=$(df -B1G --output=avail /mnt/luma-build | tail -1 | tr -d ' ')
    echo "D free ${d_free} GiB (floor $dfree); store free ${s_free} GiB (floor $sfree)"
    [ "$d_free" -ge "$dfree" ] || die 'D has too little free space'
    [ "$s_free" -ge "$sfree" ] || die 'the build store has too little free space'
    if [ "$name" != freeze ]; then
        [ -z "$(docker ps -q)" ] || die 'another container is running; heavy jobs are serialized'
        test -f "$LOCK/owner" || die 'the heavy-job lock is not held'
        owner=$(head -c 200 "$LOCK/owner")
        [ -n "${LUMA_LOCK_OWNER:-}" ] && [ "${owner%% *}" = "$LUMA_LOCK_OWNER" ] \
            || die "the heavy-job lock is held by '${owner%% *}', not LUMA_LOCK_OWNER"
        power=$(/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -NonInteractive -Command \
            '(Get-CimInstance -Namespace root/wmi -ClassName BatteryStatus).PowerOnline' | tr -d '\r' | sort -u)
        echo "PowerOnline $power"
        [ "$power" = True ] || die 'the laptop is not on mains power'
    fi
}

frozen_check() {  # FROZEN_SHA256 -> prints "<files> <head>"
    python3 -B - "$frozen" "$1" <<'PY'
import hashlib, json, sys
from pathlib import Path
frozen, pin = Path(sys.argv[1]), sys.argv[2]
raw = (frozen/'build-inputs.json').read_bytes()
if hashlib.sha256(raw).hexdigest() != pin:
    raise SystemExit('frozen build inputs differ from the approved pin')
records = json.loads(raw)['files']
for row in records:
    data = (frozen/row['path']).read_bytes()
    if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
        raise SystemExit('frozen record differs from its manifest: '+row['path'])
join = json.loads((frozen.parent/(frozen.name+'.join.json')).read_text())
if join['build_inputs_sha256'] != pin or join['files'] != len(records):
    raise SystemExit('join record differs from the approved pin')
print(len(records), join['head'], 'fixtures-unchanged' if join['verifier_fixture_sources_unchanged_since_sequence19']
      else 'fixtures-changed')
PY
}

load_frozen() {  # FROZEN_SHA256 -> FILES HEAD FIXTURES; a failed check stops the script
    local out
    out=$(frozen_check "$1")
    read -r FILES HEAD FIXTURES <<< "$out"
    [[ "$HEAD" =~ ^[0-9a-f]{40}$ ]] || die 'the join record names no cut commit'
}

store_check() {  # VOLUME HEADROOM_GIB: the sequence-19 dedicated store admission
    python3 -B - "$frozen" "$1" "$2" <<'PY'
import importlib.util, json, os, sys, tomllib
from pathlib import Path
spec = importlib.util.spec_from_file_location('candidate_storage', Path(sys.argv[1])/'native/image/build_storage.py')
storage = importlib.util.module_from_spec(spec); spec.loader.exec_module(storage)
assert os.environ.get('DOCKER_HOST') == storage.ENDPOINT and not os.environ.get('DOCKER_CONTEXT')
storage.verify_store()
storage.validate_daemon(json.loads(storage.command('docker', 'info', '--format', '{{json .}}')))
storage.validate_runtime(tomllib.loads(storage.command('containerd', '--config', '/etc/luma-build/containerd.toml',
                                                       'config', 'dump')))
name = sys.argv[2]
volume = json.loads(storage.command('docker', 'volume', 'inspect', name))
assert len(volume) == 1 and volume[0]['Name'] == name and volume[0]['Driver'] == 'local' and not volume[0].get('Options')
assert volume[0]['Mountpoint'] == str(storage.STORE/'docker/volumes'/name/'_data')
assert not storage.command('docker', 'ps', '--format', '{{.ID}}'), 'serialized: no other container may run'
storage.check_space(storage.STORE, int(sys.argv[3]))
print('Dedicated store, daemon and volume verified:', name, flush=True)
PY
}

sums_row() {  # EXPORT NAME -> the SHA-256 that the export SHA256SUMS lists for NAME
    awk -v name="$2" 'length($1) == 64 && $2 == name && NF == 2 {print $1; found++} END {exit found != 1}' "$1/SHA256SUMS"
}

plan() {
    local cut=$1 letter=$2
    paths "$letter"
    local self
    self="bash $REPO/native/evidence/candidate20_steps_2026_11_03.sh"
    cat <<EOF
Sequence-20 native desktop plan (profile N). Cut $cut, attempt $letter. Changes nothing.

Preconditions for every heavy step (preflight checks each one and fails closed):
  - the heavy-job lock is held by the runner, exported as LUMA_LOCK_OWNER;
  - no container is running and nothing else large runs in WSL;
  - the laptop is on mains power (PowerOnline True);
  - MemAvailable is at least: assemble 9 GiB, smoke 10 GiB (8 GiB guest: the live
    payload staging refuses below 6732 MiB), others 3 GiB;
  - store free at least 32 GiB for assemble; D free at least 40 GiB for assemble.
The main checkout $REPO must be clean and at $cut from freeze until the
assembly log prints its source snapshot (the first minutes of assemble).

  1. $self freeze $cut $letter
       about 2 min; writes $frozen, its .join.json and .head-eol.json, and
       $aids/verify.py (the verifier taken from the cut, SHA-256 pinned)
     The coordinator approves the printed build_inputs_sha256 as FROZEN.
  2. $self source-tests $letter FROZEN a [RUST_TEST_FILTER]
       Python suite about 3 min at 1.5 GiB (sequence 19: 966 tests in 132 s), then
       rustfmt --check alone (seconds); a Rust filter adds 6 min to 2 h at 5 GiB
  3. $self assemble $letter FROZEN
       about 70 min (sequence 19: 67 min), assembly container 8 GiB; store +about
       28 GiB (new volume), D +about 11 GiB export, +about 0.3 GiB sources and inputs
  4. $self verify $letter FROZEN BUILD_ID
       about 20 min at 2 GiB; offline image and export verification
 4b. $self update-compat $letter BUILD_ID
       seconds, read-only, no lock: the 19 -> 20 update needs equal environment,
       edition, root_bytes and hash_bytes (sequence 19: lab, desktop, 6442450944,
       50733056); a mismatch means the owner cannot test the update path
  5. $self smoke $letter FROZEN BUILD_ID usb-disk
     $self smoke $letter FROZEN BUILD_ID virtio-disk
     $self smoke $letter FROZEN BUILD_ID optical      (continuity only)
       each 7-15 min (sequence 19: disk 7, optical 13), 10 GiB container;
       software TCG with emulated Secure Boot
  6. $self download $letter FROZEN BUILD_ID copy
     $self download19 $letter FROZEN copy
       not yet measured, estimated 15-30 min each at 2 GiB (hash, decompress 16 GB,
       copy); new folders under $D/downloads, about 11 GiB each

Outputs created (each step refuses one that exists):
  $frozen  (+ .join.json, .head-eol.json)
  $aids
  $WORK/candidate20-source-tests-$DAY$letter-ATTEMPT, $D/candidate20-source-tests-$DAY$letter-ATTEMPT
  $D/candidate20-assembly-STAMP.log, $D/native/BUILD_ID, $D/native-inputs/BUILD_ID, $D/native-sources/BUILD_ID,
  docker volume luma-native-build-BUILD_ID
  $WORK/candidate20-image-verification-$DAY-$letter, $D/candidate20-image-verification-BUILD_ID-$letter.log
  /work/vm-candidate20-$DAY-MEDIUM-secureboot-tcg in that volume, $D/candidate20-MEDIUM-smoke-BUILD_ID.log
  $D/downloads/candidate20-BUILD_ID-$letter, $D/downloads/candidate19-$SEQ19_BUILD-$letter
Never overwritten: every earlier native, native-inputs and native-sources folder, the
candidate15-19 logs and records, $PRIOR and its records, $SPEECH, $INPUTS, the
gwin0-hyperv work folders and every luma-native-build-* volume.
EOF
    local existing=0 target
    for target in "$frozen" "$frozen.join.json" "$frozen.head-eol.json" "$aids"; do
        if [ -e "$target" ]; then echo "EXISTS: $target"; existing=1; fi
    done
    [ "$existing" = 0 ] && echo 'None of the attempt outputs exists yet.'
    return 0
}

freeze() {
    local cut=$1 letter=$2
    paths "$letter"
    host_check freeze
    test ! -e "$frozen" && test ! -e "$frozen.join.json" && test ! -e "$frozen.head-eol.json" && test ! -e "$aids" \
        || die 'this attempt letter is already used'
    cd "$REPO"
    git_() { git -c safe.directory="$REPO" "$@"; }
    [ -z "$(git_ status --porcelain)" ] || die 'the main checkout is not clean'
    [ "$(git_ rev-parse HEAD)" = "$cut" ] || die "the main checkout is not at $cut"
    mkdir -m 700 "$aids"
    git_ show "$cut:$VERIFIER" > "$aids/verify.py"
    [ "$(sha256sum "$aids/verify.py" | cut -d' ' -f1)" = "$VERIFIER_SHA256" ] || die 'the verifier at the cut differs from its pin'
    chmod 444 "$aids/verify.py"
    python3 -B native/image/snapshot.py --repository "$REPO" --output "$frozen" --include-tests
    python3 -B - "$REPO" "$frozen" "$PRIOR" "$cut" "$PRIOR_SHA256" <<'PY'
import hashlib, json, subprocess, sys
from pathlib import Path
repo, frozen, prior = map(Path, sys.argv[1:4])
head, prior_pin = sys.argv[4], sys.argv[5]
raw = (frozen/'build-inputs.json').read_bytes()
records = json.loads(raw)['files']
prior_raw = (prior/'build-inputs.json').read_bytes()
assert hashlib.sha256(prior_raw).hexdigest() == prior_pin, 'sequence-19 frozen manifest differs from its pin'
prior_records = {r['path']: r['sha256'] for r in json.loads(prior_raw)['files']}
assert len(prior_records) == 880
prior_eol = json.loads((prior.parent/(prior.name+'.head-eol.json')).read_text())
accepted_crlf = {row['path'] for row in prior_eol['rows']}
not_head, changed, added, rows = [], [], [], []
for record in records:
    data = (frozen/record['path']).read_bytes()
    assert len(data) == record['bytes'] and hashlib.sha256(data).hexdigest() == record['sha256'], record['path']
    shown = subprocess.run(['git', '-c', f'safe.directory={repo}', 'show', f'{head}:{record["path"]}'],
                           cwd=repo, capture_output=True)
    if shown.returncode or shown.stdout != data:
        not_head.append(record['path'])
        rows.append(dict(path=record['path'], crlf_normalized_equals_head=not shown.returncode
                         and data.replace(b'\r\n', b'\n') == shown.stdout, head_blob_has_cr=b'\r' in shown.stdout))
    if record['path'] not in prior_records:
        added.append(record['path'])
    elif prior_records[record['path']] != record['sha256']:
        changed.append(record['path'])
names = {r['path'] for r in records}
removed = sorted(set(prior_records) - names)
# The copied verifier's fixed counts (30 CLI tests, 4 workflow and 4 recovery
# DATA cases, the 13-member export) come from these sources.
fixtures = ['native/image/assemble.py', 'native/image/export.py', 'native/tests/content_contract_cli.py',
            'native/tests/test_workspace_recovery.py', 'native/tests/test_workspace_workflow.py']
fixture_changes = sorted(path for path in fixtures if path in changed or path in removed)
value = dict(head=head, frozen=str(frozen), build_inputs_sha256=hashlib.sha256(raw).hexdigest(),
             files=len(records), bytes=sum(r['bytes'] for r in records),
             not_byte_identical_to_head=sorted(not_head),
             prior_frozen=str(prior), prior_build_inputs_sha256=hashlib.sha256(prior_raw).hexdigest(),
             changed_from_prior=sorted(changed), added_since_prior=sorted(added), removed_since_prior=removed,
             verifier_fixture_sources=fixtures, verifier_fixture_sources_changed=fixture_changes,
             verifier_fixture_sources_unchanged_since_sequence19=not fixture_changes)
with (frozen.parent/(frozen.name+'.join.json')).open('x') as stream:
    json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')
summary = {k: v for k, v in value.items() if k not in ('not_byte_identical_to_head', 'changed_from_prior')}
summary['changed_from_prior_count'] = len(changed)
print(json.dumps(summary, indent=2, sort_keys=True))
for path in ('native/image/live_media_smoke.py', 'native/image/download_manifest.py'):
    assert path in names, 'the cut lacks '+path
unexpected = sorted(set(not_head) - accepted_crlf)
assert not unexpected, ('files differ from the cut beyond the accepted working-tree CRLF list', unexpected)
assert all(r['crlf_normalized_equals_head'] and not r['head_blob_has_cr'] for r in rows), rows
eol = dict(frozen=str(frozen), head=head, build_inputs_sha256=value['build_inputs_sha256'],
           subset_of_accepted_20261028_a_list=True, files=len(rows), all_differ_only_by_working_tree_crlf=True,
           rust_changed_since_prior=[p for p in changed if p.startswith('rust/')], rows=rows)
out = frozen.parent/(frozen.name+'.head-eol.json')
with out.open('x') as stream:
    json.dump(eol, stream, indent=2, sort_keys=True); stream.write('\n')
print('join sha256', hashlib.sha256((frozen.parent/(frozen.name+'.join.json')).read_bytes()).hexdigest())
print('head-eol sha256', hashlib.sha256(out.read_bytes()).hexdigest())
if fixture_changes:
    print('WARNING: verifier fixture sources changed since sequence 19:', fixture_changes,
          '- re-derive the verifier before the verify step', flush=True)
print('FROZEN='+value['build_inputs_sha256'])
PY
}

source_tests() {
    local letter=$1 pin=$2 attempt=$3; shift 3
    paths "$letter"
    [[ "$attempt" =~ ^[a-z]$ ]] || die 'test attempt must be one lowercase letter'
    local work=$WORK/candidate20-source-tests-$DAY$letter-$attempt logs=$D/candidate20-source-tests-$DAY$letter-$attempt
    test ! -e "$work" && test ! -e "$logs" || die 'this test attempt is already used'
    host_check source-tests
    load_frozen "$pin"
    echo "Frozen cut $HEAD verified: $FILES records."
    mkdir -m 700 "$work" "$work/pytmp" "$work/storage-py" "$work/storage-rs"
    mkdir "$logs"
    # Standard sticky world-writable /tmp: fixtures assert it is refused as a parent.
    chmod 1777 "$work/pytmp"
    test "$(stat -f -c %T "$work/storage-py")" = ext2/ext3
    df -B1 /mnt/luma-build | tail -1 > "$logs/store-before.txt"
    run_step() {
        local name=$1; shift
        { date -u +start=%Y-%m-%dT%H:%M:%SZ; set +e; "$@"; local status=$?; set -e
          date -u +end=%Y-%m-%dT%H:%M:%SZ; echo "exit=$status"; } > "$logs/$name.log" 2>&1
        echo "== $name: $(tail -1 "$logs/$name.log")"
    }
    run_step python docker run --rm --network none --memory 1536m --memory-swap 1536m --cpus 2 --pids-limit 512 \
        --mount "type=bind,src=$frozen,dst=/repo,readonly" \
        --mount "type=bind,src=$work/pytmp,dst=/tmp" \
        --mount "type=bind,src=$work/storage-py,dst=/storage" \
        --env PYTHONDONTWRITEBYTECODE=1 --env LUMA_STORAGE_TEST_ROOT=/storage --workdir /repo \
        "$TOOLS" timeout -k 30 3600 python3 -W error -m unittest discover -s native/tests
    tail -5 "$logs/python.log" | head -3
    grep -E '^(FAIL|ERROR):' "$logs/python.log" || true
    rust() {
        docker run --rm --network none --memory 5g --memory-swap 5g --cpus 6 \
            --mount "type=bind,src=$frozen,dst=/repo,readonly" \
            --mount "type=bind,src=$work/storage-rs,dst=/storage" \
            --mount "type=volume,src=luma-g2-rust-targeted-cache-20261001,dst=/cache" \
            --env CARGO_TARGET_DIR=/cache/target-claude-g3-strict --env CARGO_INCREMENTAL=0 \
            --env RUSTFLAGS=-Dwarnings --env LUMA_STORAGE_TEST_ROOT=/storage \
            --workdir /repo/rust "$TOOLS" timeout -k 30 3600 "$@"
    }
    # rustfmt runs alone first: a later full check would not stop on a format miss.
    run_step rustfmt rust cargo fmt --check
    if [ "$#" -gt 0 ]; then
        run_step rust-tests rust cargo test --offline --locked -p luma-platform --lib -- "$@" --test-threads=4
        grep -E '^test result:' "$logs/rust-tests.log" | tail -5 || true
    fi
    df -B1 /mnt/luma-build | tail -1 > "$logs/store-after.txt"
    (cd "$logs" && sha256sum ./*.log ./*.txt)
}

assemble() {
    local letter=$1 pin=$2
    paths "$letter"
    host_check assemble
    load_frozen "$pin"
    cd "$REPO"
    [ -z "$(git -c safe.directory="$REPO" status --porcelain)" ] || die 'the main checkout is not clean'
    [ "$(git -c safe.directory="$REPO" rev-parse HEAD)" = "$HEAD" ] || die "the main checkout is not at the frozen cut $HEAD"
    python3 -B - "$REPO" "$frozen" <<'PY'
import hashlib, importlib.util, json, sys
from pathlib import Path
repo, frozen = Path(sys.argv[1]), Path(sys.argv[2])
records = {r['path']: r for r in json.loads((frozen/'build-inputs.json').read_bytes())['files']}
spec = importlib.util.spec_from_file_location('candidate_snapshot', frozen/'native/image/snapshot.py')
snapshot = importlib.util.module_from_spec(spec); spec.loader.exec_module(snapshot)
if set(snapshot.inventory(repo, include_tests=True)) != set(records):
    raise SystemExit('current source membership differs from the frozen candidate-20 snapshot')
for relative, record in records.items():
    data = (repo/relative).read_bytes()
    if len(data) != record['bytes'] or hashlib.sha256(data).hexdigest() != record['sha256']:
        raise SystemExit('current source differs from the frozen candidate-20 snapshot: '+relative)
print(f'All {len(records)} source records match the frozen candidate-20 snapshot.', flush=True)
PY
    printf '%s  %s\n' \
        "$(sha256sum "$INPUTS/llama-runtime.tar.gz" | cut -d' ' -f1)" llama-runtime.tar.gz \
        "$(sha256sum "$INPUTS/chrony-4.9.tar.gz" | cut -d' ' -f1)" chrony-4.9.tar.gz
    test -d "$SPEECH" || die "the speech inputs are missing: $SPEECH"
    local stamp log
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    log=$D/candidate20-assembly-$stamp.log
    test ! -e "$log" || die "refusing an existing assembly log $log"
    env -u LUMA_NATIVE_PRODUCTION_PUBLIC_INPUTS -u LUMA_NATIVE_PUBLIC_TRUST -u LUMA_NATIVE_MODEL_PUBLIC_INPUTS \
        LUMA_NATIVE_ENVIRONMENT=lab \
        LUMA_NATIVE_ASSEMBLY_MEMORY_GIB=8 \
        LUMA_BUILD_NETWORK=host \
        LUMA_RUNTIME_ARCHIVE="$INPUTS/llama-runtime.tar.gz" \
        LUMA_UTC_ARCHIVE="$INPUTS/chrony-4.9.tar.gz" \
        LUMA_SPEECH_INPUTS="$SPEECH" \
        bash native/image/build-on-d.sh desktop 20 2>&1 | tee "$log"
    printf 'ASSEMBLY_LOG=%s\n' "$log"
}

verify() {
    local letter=$1 pin=$2 build_id=$3
    paths "$letter"
    host_check verify
    load_frozen "$pin"
    [ "$FIXTURES" = fixtures-unchanged ] || die 'verifier fixture sources changed since sequence 19; re-derive the verifier first'
    [ "$(sha256sum "$aids/verify.py" | cut -d' ' -f1)" = "$VERIFIER_SHA256" ] || die 'the verifier differs from its pin'
    store_check "luma-native-build-$build_id" 2
    local evidence=$WORK/candidate20-image-verification-$DAY-$letter
    local log=$D/candidate20-image-verification-$build_id-$letter.log
    test ! -e "$log" && test ! -e "$evidence" || die 'this verification attempt is already used'
    mkdir -m 700 "$evidence"
    docker run --rm --network none --memory 2g --memory-swap 2g --cpus 2 --pids-limit 64 \
        --cap-drop ALL --cap-add SETUID --cap-add SETGID --security-opt no-new-privileges \
        --mount "type=volume,src=luma-native-build-$build_id,dst=/work,readonly" \
        --mount "type=bind,src=$D/native/$build_id,dst=/out,readonly" \
        --mount "type=bind,src=$frozen,dst=/repo,readonly" \
        --mount "type=bind,src=$evidence,dst=/evidence" \
        --mount "type=bind,src=$aids/verify.py,dst=/verify.py,readonly" \
        "$TOOLS" python3 -I -B /verify.py \
        --release-public-sha256 "$RELEASE_PUBLIC_SHA256" \
        --pcr-public-sha256 "$PCR_PUBLIC_SHA256" \
        --secureboot-cert-sha256 "$CERT_SHA256" \
        --frozen-source-sha256 "$pin" \
        --frozen-source-files "$FILES" --build-id "$build_id" 2>&1 | tee "$log"
    sha256sum "$evidence/verification.json"
}

verified() {  # LETTER BUILD_ID: the offline verification of this attempt must have passed
    python3 -B - "$WORK/candidate20-image-verification-$DAY-$1/verification.json" "$2" <<'PY'
import json, sys
value = json.loads(open(sys.argv[1], 'rb').read())
if value.get('status') != 'candidate20-offline-image-and-export-verification-passed':
    raise SystemExit('the offline verification of this build has not passed')
if value.get('build_identity', {}).get('build_id') != sys.argv[2]:
    raise SystemExit('the offline verification names another build')
PY
}

update_compat() {  # LETTER BUILD_ID: read-only; no lock, no container
    # The owner's 19 -> 20 update test needs what platform.rs update() checks
    # against installed.json: equal environment, edition, root_bytes and
    # hash_bytes, and a higher sequence. Both releases must carry the pinned
    # laboratory Secure Boot certificate so one db enrollment serves both.
    local letter=$1 build_id=$2
    local old=$D/native/$SEQ19_BUILD new=$D/native/$build_id
    [ "$(sha256sum "$old/SHA256SUMS" | cut -d' ' -f1)" = "$SEQ19_SUMS_SHA256" ] \
        || die 'the sequence-19 export SHA256SUMS differs from its pin'
    verified "$letter" "$build_id"
    python3 -B - "$old" "$new" "$CERT_SHA256" <<'PY'
import hashlib, json, sys
from pathlib import Path
old, new, cert = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
def listed(export, name):
    rows = [line.split() for line in (export/'SHA256SUMS').read_text().splitlines()]
    found = [r[0] for r in rows if len(r) == 2 and r[1] == name]
    if len(found) != 1:
        raise SystemExit(f'{export}/SHA256SUMS has no single row for {name}')
    if hashlib.sha256((export/name).read_bytes()).hexdigest() != found[0]:
        raise SystemExit(f'{export}/{name} differs from its SHA256SUMS row')
    return (export/name).read_bytes()
releases = []
for export in (old, new):
    if hashlib.sha256(listed(export, 'secureboot.cer')).hexdigest() != cert:
        raise SystemExit(f'{export}/secureboot.cer is not the pinned laboratory certificate')
    releases.append(json.loads(listed(export, 'release.json')))
a, b = releases
fields = ('environment', 'edition', 'root_bytes', 'hash_bytes')
value = dict(old=dict((k, a.get(k)) for k in ('release', 'sequence', 'architecture', 'ubuntu') + fields),
             new=dict((k, b.get(k)) for k in ('release', 'sequence', 'architecture', 'ubuntu') + fields),
             geometry_and_identity_equal={k: a.get(k) == b.get(k) for k in fields},
             sequence_increases=isinstance(a.get('sequence'), int) and isinstance(b.get('sequence'), int)
             and b['sequence'] > a['sequence'],
             same_secureboot_certificate=True)
print(json.dumps(value, indent=2, sort_keys=True))
if a.get('sequence') != 19 or b.get('sequence') != 20:
    raise SystemExit('expected sequence 19 then sequence 20')
if not all(value['geometry_and_identity_equal'].values()):
    raise SystemExit('sequence 19 cannot update to this build: installed.json geometry or identity differs')
print('UPDATE-COMPATIBLE: platform.rs update() geometry and sequence checks would admit 19 -> 20')
PY
}

smoke() {
    local letter=$1 pin=$2 build_id=$3 medium=$4 suffix
    paths "$letter"
    case $medium in optical) suffix=iso;; usb-disk|virtio-disk) suffix=img;; *) die 'medium is usb-disk, virtio-disk or optical';; esac
    host_check smoke
    load_frozen "$pin"
    verified "$letter" "$build_id"
    store_check "luma-native-build-$build_id" 2
    local media_sha256
    media_sha256=$(sums_row "$D/native/$build_id" "$RELEASE.$suffix") || die "the export SHA256SUMS has no single $RELEASE.$suffix row"
    local log=$D/candidate20-$medium-smoke-$build_id.log
    test ! -e "$log" || die "this smoke was already run: $log"
    docker run --rm --network none --memory 10g --memory-swap 10g --cpus 2 --pids-limit 128 \
        --mount "type=volume,src=luma-native-build-$build_id,dst=/work" \
        --mount "type=bind,src=$frozen,dst=/repo,readonly" \
        --env PYTHONDONTWRITEBYTECODE=1 \
        "$TOOLS" python3 -B /repo/native/image/live_media_smoke.py \
        --medium "$medium" \
        --media "/work/artifacts/$RELEASE.$suffix" \
        --media-sha256 "$media_sha256" \
        --certificate-sha256 "$CERT_SHA256" \
        --work "/work/vm-candidate20-$DAY-$medium-secureboot-tcg" 2>&1 | tee "$log"
}

download() {  # EXPORT SEQUENCE COMMIT CUT OUTPUT COPY LOG...
    local export=$1 sequence=$2 commit=$3 cut=$4 output=$5 copy=$6; shift 6
    case $copy in ''|copy) ;; *) die 'the last argument may only be copy';; esac
    test ! -e "$output" && test ! -e "$output.log" || die "refusing an existing download folder or log $output"
    mkdir -p "$D/downloads"
    local args=(--export "$export" --output "$output" --sequence "$sequence" --source-commit "$commit"
                --source-cut "$cut" --verify-decompressed)
    [ "$copy" = copy ] && args+=(--copy)
    local log
    for log in "$@"; do args+=(--build-log "$log"); done
    docker run --rm --network none --memory 2g --memory-swap 2g --cpus 2 --pids-limit 64 \
        --cap-drop ALL --security-opt no-new-privileges \
        --mount "type=bind,src=$D,dst=$D,readonly" \
        --mount "type=bind,src=$D/downloads,dst=$D/downloads" \
        --mount "type=bind,src=$frozen,dst=/repo,readonly" \
        "$TOOLS" python3 -I -B /repo/native/image/download_manifest.py "${args[@]}" \
        2>&1 | tee "$output.log"
}

case $step in
    plan)
        [ "$#" = 2 ] || die 'usage: plan CUT LETTER'
        [[ "$1" =~ ^[0-9a-f]{40}$ ]] || die 'CUT must be a 40-hex commit'; letter_ok "$2"
        plan "$1" "$2";;
    preflight)
        [ "$#" = 1 ] || die 'usage: preflight STEP'
        host_check "$1"
        echo "preflight for $1 passed; nothing was changed";;
    freeze)
        [ "$#" = 2 ] || die 'usage: freeze CUT LETTER'
        [[ "$1" =~ ^[0-9a-f]{40}$ ]] || die 'CUT must be a 40-hex commit'; letter_ok "$2"
        freeze "$1" "$2";;
    source-tests)
        [ "$#" -ge 3 ] || die 'usage: source-tests LETTER FROZEN ATTEMPT [RUST_TEST_FILTER]'
        letter_ok "$1"; sha_ok "$2"
        source_tests "$@";;
    assemble)
        [ "$#" = 2 ] || die 'usage: assemble LETTER FROZEN'
        letter_ok "$1"; sha_ok "$2"
        assemble "$1" "$2";;
    verify)
        [ "$#" = 3 ] || die 'usage: verify LETTER FROZEN BUILD_ID'
        letter_ok "$1"; sha_ok "$2"; build_ok "$3"
        verify "$1" "$2" "$3";;
    update-compat)
        [ "$#" = 2 ] || die 'usage: update-compat LETTER BUILD_ID'
        letter_ok "$1"; build_ok "$2"
        update_compat "$1" "$2";;
    smoke)
        [ "$#" = 4 ] || die 'usage: smoke LETTER FROZEN BUILD_ID MEDIUM'
        letter_ok "$1"; sha_ok "$2"; build_ok "$3"
        smoke "$1" "$2" "$3" "$4";;
    download)
        [ "$#" -ge 3 ] && [ "$#" -le 4 ] || die 'usage: download LETTER FROZEN BUILD_ID [copy]'
        letter_ok "$1"; sha_ok "$2"; build_ok "$3"; paths "$1"
        host_check download
        load_frozen "$2"
        verified "$1" "$3"
        # Build log references: the assembly log naming this build, its
        # verification log and every smoke log of this build.
        mapfile -t logs < <({ grep -l -F -- "$3" "$D"/candidate20-assembly-*.log
                              ls "$D/candidate20-image-verification-$3-$1.log" "$D"/candidate20-*-smoke-"$3".log
                            } 2>/dev/null | sort -u)
        download "$D/native/$3" 20 "$HEAD" "candidate20-source-$DAY-$1" "$D/downloads/candidate20-$3-$1" \
            "${4:-}" "${logs[@]}";;
    download19)
        [ "$#" -ge 2 ] && [ "$#" -le 3 ] || die 'usage: download19 LETTER FROZEN [copy]'
        letter_ok "$1"; sha_ok "$2"; paths "$1"
        host_check download19
        load_frozen "$2"
        [ "$(sha256sum "$D/native/$SEQ19_BUILD/SHA256SUMS" | cut -d' ' -f1)" = "$SEQ19_SUMS_SHA256" ] \
            || die 'the sequence-19 export SHA256SUMS differs from its pin'
        download "$D/native/$SEQ19_BUILD" 19 "$SEQ19_COMMIT" candidate19-source-20261028-a \
            "$D/downloads/candidate19-$SEQ19_BUILD-$1" "${3:-}" \
            "$D/candidate19-assembly-20261028T162354Z.log" \
            "$D/candidate19-image-verification-$SEQ19_BUILD-a.log" \
            "$D/candidate19-vm-smoke-$SEQ19_BUILD.log" \
            "$D/candidate19-optical-smoke-$SEQ19_BUILD.log";;
    *)
        sed -n '2,25p' "${BASH_SOURCE[0]}"; exit 2;;
esac
