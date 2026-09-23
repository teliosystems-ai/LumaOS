# Ubuntu runtime and G2 qualification handoff

This guide separates three activities that must not be treated as equivalent:

1. running the Luma OS developer runtime on Ubuntu or Ubuntu under WSL2;
2. admitting a native Ubuntu 24.04 machine as a *candidate* for later G2 lab work; and
3. executing destructive installation, boot, security, and recovery qualification.

The repository currently supports the first activity and supplies read-only
preparation tools for the second. It does not yet supply or authorize a disk
installer, bootable product image, firmware-key enrollment, or destructive test
runner. WSL evidence can support development but can never satisfy a physical
Ubuntu board, firmware, boot, suspend, power-loss, or device-reset requirement.

## What the two probes do

`scripts/collect_g2_host.py` is the authoritative bounded host-inventory
collector. It runs allow-listed read-only commands, never selects a disk, and
labels every discovered block device `unclassified-never-auto-selected`.

`scripts/ubuntu_preflight.py` consumes that record and decides only whether the
current checkout and host are ready for the next documented step. It binds the
record to the live OS facts and pseudonymous machine identity. For native
admission it accepts only an explicitly selected `e1` or `e2` class and a
collector record no more than 15 minutes old (with at most five minutes of
future clock skew). It independently re-probes the live OS, kernel, memory,
cgroup v2, AppArmor/LSM, seccomp interface, UEFI/efivars, Secure Boot,
virtualization, and accelerator visibility. Inventory claims never override a
failed live probe. Native positive security, storage, virtualization, and
accelerator observations also require the collector's root-owned, absolute,
digest-bound executable provenance; ambient `PATH`, loader, or shell state is
not accepted as corroboration. Its JSON always sets `certification_closing` to
`false`.

The readiness probe has two modes:

| Mode | May pass on WSL2 | Meaning of a pass |
| --- | --- | --- |
| `development` | Yes | The source runtime and tests can be exercised; warnings preserve differences from the retained native baseline. |
| `native-candidate` | No | A native Ubuntu 24.04 x86-64 host has passed the initial read-only admission checks. Destructive and enforcing tests are still outstanding. |

Both tools emit machine-readable JSON. Neither installs software, downloads a
model, uses `sudo`, starts a service, modifies firmware, or writes a disk. The
collector writes a file only when the operator explicitly supplies `--output`;
it refuses to replace an existing file.

## Current Ubuntu WSL development lane

From PowerShell, the installed distribution is named `Ubuntu` in the current
environment. Run the source path without installing anything:

```powershell
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/c/Users/hakim/LumaOS && python3 scripts/collect_g2_host.py --environment-id DEV-WSL-UBUNTU-26-01 --compact'
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/c/Users/hakim/LumaOS && python3 scripts/ubuntu_preflight.py --mode development --pretty'
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/c/Users/hakim/LumaOS && python3 -m unittest discover -s tests -p "test_*.py" -v'
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/c/Users/hakim/LumaOS && ./scripts/run.sh --help'
```

For a collector-to-preflight integration run, first choose an evidence path
inside the Linux filesystem and outside the repository. The parent directory
must already exist:

```bash
cd /mnt/c/Users/hakim/LumaOS
python3 scripts/collect_g2_host.py \
  --environment-id DEV-WSL-UBUNTU-26-01 \
  --output "$HOME/luma-evidence/wsl-host-inventory.json" \
  --compact >/dev/null
python3 scripts/ubuntu_preflight.py \
  --mode development \
  --host-inventory "$HOME/luma-evidence/wsl-host-inventory.json" \
  --pretty
```

The current WSL result is expected to identify Ubuntu 26.04, WSL2, a shared
physical host, and a Windows-mounted `9p` checkout. Those are development
warnings, not failures and not native evidence. AppArmor, UEFI/Secure Boot, and
physical-host checks are also expected not to close in WSL.

For stronger Linux filesystem semantics, use the existing unprivileged user
install, which copies the runtime into the WSL user's Linux data directory:

```powershell
.\packaging\wsl\install.ps1 -Distribution Ubuntu
.\packaging\wsl\launch.ps1 -Distribution Ubuntu --help
```

This changes only the selected WSL user's marked Luma installation. It does not
install a distribution, request administrator rights, enable a service, or
change Windows disks. Review an existing installation before adding `-Upgrade`.

## Native Ubuntu 24.04 source-runtime procedure

Use the checksumed source archive or a pinned Git commit. Extract or clone it
onto a native Linux filesystem such as ext4, XFS, or Btrfs, not an SMB/NFS
share or Windows-mounted filesystem. Python 3.11 or newer is required; the
runtime itself has no third-party Python dependency.

Before running as a service, use an ordinary non-root account:

```bash
cd /path/to/LumaOS
python3 scripts/ubuntu_preflight.py --mode development --pretty
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -O -m unittest \
  tests.test_boot_control \
  tests.test_installer \
  tests.test_privileged_helper \
  tests.test_durable_effects \
  tests.test_model_pack \
  tests.test_model_selection -v
bash -n scripts/*.sh packaging/systemd/*.sh
./scripts/run.sh --help
./scripts/run.sh
```

The last command starts the loopback developer service. Keep the listener at
`127.0.0.1`; press `Ctrl+C` for a normal stop. Do not expose it through a LAN,
reverse proxy, public interface, or production workload.

The optional user installation is also non-root:

```bash
./scripts/install-user.sh
"$HOME/.local/bin/luma-os" --help
```

It writes only the documented marked install and launcher paths. It does not
start a service. Review the unit before separately authorizing activation:

```bash
./packaging/systemd/install-user-service.sh
systemctl --user cat luma-os.service
systemctl --user enable --now luma-os.service
systemctl --user status luma-os.service
```

The `enable --now` command is a distinct operator-approved mutation. It is not
part of read-only preflight.

## Admitting each physical G2 candidate

Two independently identified native x86-64 systems are required. The current
planning classes are:

- E1: 16 GiB compact physical PC with a supported CPU and one GPU or NPU path.
- E2: 32–64 GiB mainstream physical PC with a different accelerator path.

Install Ubuntu 24.04 natively in UEFI mode with Secure Boot enabled. Use a
separate evidence destination and run the following once on each candidate.
Replace only the environment ID, hardware class, repository path, and evidence
path:

```bash
cd /path/to/LumaOS
python3 scripts/collect_g2_host.py \
  --environment-id E1 \
  --require-native-ubuntu-24.04 \
  --output /path/to/protected-evidence/e1-host-inventory.json \
  --compact >/dev/null
python3 scripts/ubuntu_preflight.py \
  --mode native-candidate \
  --hardware-class e1 \
  --host-inventory /path/to/protected-evidence/e1-host-inventory.json \
  --pretty > /path/to/protected-evidence/e1-runtime-preflight.json
sha256sum \
  /path/to/protected-evidence/e1-host-inventory.json \
  /path/to/protected-evidence/e1-runtime-preflight.json
```

Repeat with `E2`, `--hardware-class e2`, and separate filenames. Do not proceed
if the collector exits `3`, the preflight exits `2`, `exit_ready` is false, or
`missing_prerequisites` is non-empty. A passing preflight still does not
authorize destructive activity.

Run each preflight immediately after its collector command. If the record is
older than 15 minutes, the clock differs by more than the permitted skew, its
structure is incomplete, its host identity differs, or any security, firmware,
memory, or accelerator observation disagrees with the live re-probe, discard
it from admission and collect a new record. Do not edit an old JSON record to
make it pass. `--hardware-class none` is always denied in native-candidate
mode; the operator must explicitly choose the board's approved E1 or E2 role.

The collector intentionally does not decide whether a disk is disposable. The
lab owner must map its pseudonymous disk identities to separately controlled
asset records and sign an exact target-disk disposition. If raw serial/WWN
capture is required, use `--include-sensitive-identifiers` only with an
access-controlled output outside Git and public support bundles.

## What must be supplied from the physical-lab side

For each of E1 and E2, provide:

- a dedicated physical machine and independently recorded firmware, CPU,
  memory, accelerator, driver, and storage inventory;
- native Ubuntu 24.04 media and package provenance, plus retained 26.04 media
  for the later E8 migration matrix;
- one separately identified disposable installation disk that contains no
  needed data and is not the evidence/control disk;
- a tested way to restore firmware settings and keys, boot recovery media, and
  an independent copy of LUKS2 recovery credentials;
- a remotely controlled or supervised power-interruption facility for the
  specified crash windows;
- access-controlled evidence storage that survives target-disk replacement,
  rollback, and power interruption;
- the exact signed release/model/runtime catalog and corresponding public
  verification roots; and
- named platform, QA, security, and release witnesses with authority to stop
  the run on any unexpected target, trust, or recovery state.

Before any destructive test, the operator must return the two collector JSON
files, the two preflight JSON files and SHA-256 values, the signed target-disk
dispositions, and the approved run identifier. That material is the admission
input for a separately reviewed destructive runbook; it is not permission to
infer a target from `lsblk` output.

## Evidence boundary

The source runtime, WSL tests, user install, and candidate preflight do not
prove any of the following:

- installation target selection or preservation of non-target storage;
- signed UKI verification, dm-verity, A/B trial boot, or three-attempt fallback;
- LUKS2 enrollment, independent recovery, or loss-of-key handling;
- Secure Boot tamper rejection or firmware trust-key recovery;
- enforcement by cgroup v2, AppArmor, seccomp, device policy, KVM, or peer credentials;
- power-loss durability, suspend/resume, device reset, thermals, or sustained pressure;
- model quality, cancellation, interactive service class, or signed catalog custody; or
- G2 passage on either board.

These remain blocked until the governed physical procedures are implemented,
authorized, executed, independently reviewed, and retained against exact
release bytes and hardware tuples.

Continue with the witnessed case matrix in
[`gates/g2/PHYSICAL_QUALIFICATION_RUNBOOK.md`](gates/g2/PHYSICAL_QUALIFICATION_RUNBOOK.md)
only after its owner approvals and stop conditions are satisfied. Model-catalog
keys, approval quorum, signing ceremony, revocation, and recovery custody are
separately defined in
[`PRODUCTION_SIGNING_CUSTODY.md`](PRODUCTION_SIGNING_CUSTODY.md).
