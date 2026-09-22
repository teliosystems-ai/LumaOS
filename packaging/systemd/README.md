# systemd user service

This optional unit runs an existing Luma OS **user install** as the current unprivileged account. It is intended for Ubuntu 24.04 developer workstations only.

```bash
./scripts/install-user.sh
./packaging/systemd/install-user-service.sh
```

The installer copies the unit and reloads the user manager, but does not enable or start it. After reviewing the resolved unit:

```bash
systemctl --user cat luma-os.service
systemctl --user enable --now luma-os.service
systemctl --user status luma-os.service
```

Or explicitly request enablement during install:

```bash
./packaging/systemd/install-user-service.sh --enable
```

The service binds to `127.0.0.1:8765`, writes only to the Luma state directory, uses a restrictive umask, and includes baseline systemd hardening. Its home-directory read access remains necessary for folders that the operator explicitly enrolls.

Stop and disable it with:

```bash
systemctl --user disable --now luma-os.service
```

Disabling does not delete the unit, application install, runtime state, or artifacts. Remove those only through reviewed, explicit user actions.

The unit is a developer convenience—not a production service definition, network deployment, watchdog guarantee, or availability claim.
