# G2 isolated fixture sweep

The isolated sweep runs the software boundary fixtures from one frozen source
snapshot, in fresh containers using the D-backed build daemon. It serializes
the lanes with a 4 GiB memory ceiling and two CPUs per container. The source is
read-only; caches, temporary files and evidence remain on D. It never attaches
host disks or physical TPM devices or changes host accounts or clocks.

Run `native/tests/g2_fixture_sweep.py` from the root Linux build environment
after sourcing `/etc/luma-build/environment.sh`. Supply `--repository` with a
snapshot captured by `native/image/snapshot.py --include-tests`, `--output`
with a new child of an existing D build directory, `--cache` with an existing
D cache directory searchable by unprivileged fixture children, and
`--utc-archive` with the pinned chrony 4.9 archive on D. The daemon must also
store its data on D. The runner pins the inspected local tools image identity
for the complete run and never pulls an image.

The default selection has 24 lanes. `--private-mounts` includes the storage
and recovery ENOSPC fixtures, using SYS_ADMIN only in disposable container
namespaces. Those lanes receive neither host devices nor a privileged
container. Repeated `--lane NAME` selects an explicit subset; omitted lanes
remain listed as unexecuted rather than passed.

The inventory maps all 42 currently ignored Rust entries: 35 independently
launchable fixtures and seven child-only entries owned by their parent tests.
Children are not double-counted. A new ignored entry without an explicit
mapping fails the sweep. Each selected lane must retain positive named test
execution and its required completion evidence; empty selections, unexpected
ignores, skipped Python cases and success markers without actual executions
are rejected. Source bytes are checked before and after each lane.

Fourteen orchestration regression tests passed on 2026-10-12 in the isolated
Linux tools container. They test the runner's accounting and rejection paths,
not the underlying hardware or product fixtures. Actual selected fixture
results belong to their frozen source manifest and retained `result.json`.
The PAM catalog lane also requires all six scoped model-custody case markers
alongside actual named Rust executions. The public-model lane runs the real
signature and sidecar tests; neither an empty suite nor skipped cases passes.
Sparse model fixtures have an independent 8 GiB file extent bound. Each
transcript retains its separate 64 MiB ceiling; an oversized transcript fails
even when its child exits successfully. This does not change product limits.
The consolidated source sweep can additionally use `--apparmor-parse` to parse
each shipped profile with kernel loading and policy caches disabled. Parser
success is not evidence of enforcing installed confinement.

Native NTS/provider connectivity, clock and confinement behavior, the signed
installer image, boot and interruption recovery, installed graphical login,
physical hardware and production signing custody require separate evidence.
Passing this development sweep does not close G2 or Requirement 1.
