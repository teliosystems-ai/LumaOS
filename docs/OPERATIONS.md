# Local operations guide

## Operating boundary

These procedures are for a single developer running Luma OS `0.1.0` locally on Ubuntu 24.04 or Windows 11/WSL2. Do not expose the service to a LAN, internet, reverse proxy, shared host, or production workload.

## Start from source

```bash
./scripts/run.sh
```

The launcher resolves the checkout, places `src/` on `PYTHONPATH`, and executes `python -m luma_os.cli`. Use `./scripts/run.sh --help` for current CLI options.

The default browser/API endpoint is `http://127.0.0.1:8765`. Keep the literal loopback bind. If that port is occupied, choose another loopback port through the CLI/configuration supported by the runtime.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `LUMA_HOME` | `${XDG_STATE_HOME}/luma-os` or `~/.local/state/luma-os` | Private SQLite/object state root |
| `LUMA_HOST` | `127.0.0.1` | Listener address; non-loopback is unsupported |
| `LUMA_PORT` | `8765` | Local listener port |
| `LUMA_MAX_SOURCE_BYTES` | `10485760` | Maximum enrolled source-file size |
| `LUMA_MODEL_ENDPOINT` | unset | Optional operator-controlled local model endpoint |
| `LUMA_MODEL_NAME` | unset | Optional model label |
| `LUMA_MODEL_API_KEY` | unset | Optional process-only credential; never commit it |

Prefer temporary shell environment configuration to files. Avoid placing model credentials in service units, command history, screenshots, or support bundles.

## Stop

For a foreground source run, press `Ctrl+C` and wait for normal process exit. Do not remove or copy SQLite state while the process is active.

For the optional user service:

```bash
systemctl --user stop luma-os.service
```

## Health and smoke checks

With the process running:

```bash
python3 -c "import json, urllib.request; print(json.load(urllib.request.urlopen('http://127.0.0.1:8765/api/health')))"
```

Use synthetic data for workflow smoke tests. Confirm that:

- an unenrolled path is rejected;
- enrollment returns the expected root and scope;
- workflow creation prepares but does not run the plan;
- run creates an application artifact and effect receipt;
- repeating the same idempotent request does not duplicate an effect; and
- state remains visible after a clean restart.

## Backup

The MVP has no online backup command. Use this offline procedure:

1. stop the process or user service;
2. verify no Luma OS process is using the selected `LUMA_HOME`;
3. copy the entire state directory—including the database and `objects/`—to access-controlled storage;
4. record the application version and checksum the backup; and
5. restart only after the copy completes.

Copying only `luma.sqlite3` may omit WAL state or object content. Backups may contain sensitive paths, source-derived values, workflow history, and artifacts.

## Restore

Restore is best-effort in `0.1.0`:

1. stop Luma OS;
2. retain the current state directory as a separate rollback copy;
3. place the complete backup at a new private path;
4. set `LUMA_HOME` to that path and start the same application version;
5. inspect health, counts, workflows, artifacts, and receipts before normal use.

The runtime refuses a database schema newer than the running build. There is no supported downgrade migration.

## Logs and support bundles

Foreground diagnostics go to the terminal. User-service output is available through:

```bash
journalctl --user -u luma-os.service --since today
```

Before sharing diagnostics, remove source paths, user names, model endpoint details, workflow inputs/results, artifacts, cookies/session values, and credentials. Never send the SQLite database or objects directory in a public issue.

## Reset local development state

There is no automatic reset script because deletion is destructive. To reset, stop the process, resolve the exact `LUMA_HOME`, inspect it, and move that specific directory to a quarantine/backup location. Do not use a broad recursive delete or an unresolved environment variable.

## User install and service

`scripts/install-user.sh` performs an unprivileged, versioned source install. It refuses existing unmarked paths and does not start services. `scripts/uninstall-user.sh --yes` deletes only a marked Luma OS user install and its marked launcher.

See `packaging/systemd/README.md` for the optional service and `packaging/wsl/README.md` for the Windows 11/WSL2 path.

## Model assets

Model weights are never downloaded by repository scripts, included in archives, or backed up as application content. Obtain them separately and follow their license, privacy, and export requirements. Connecting an endpoint expands the trust boundary; review the [threat model](THREAT_MODEL.md) first.

## Incident response

If unexpected access, disclosure, or effects occur:

1. stop the local process;
2. disconnect any configured model endpoint;
3. preserve a copy of relevant logs and state with restricted access;
4. revoke affected grants after restart only if inspection is safe;
5. rotate any possibly exposed external credential; and
6. follow the private reporting process in [SECURITY.md](../SECURITY.md).
