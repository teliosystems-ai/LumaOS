"""Build-owned GNOME/Wayland profile. No model or broker dependency for login."""
from pathlib import Path

PROFILE = 'gnome-wayland-v1'
REQUIRED = (
    'usr/sbin/gdm3', 'usr/bin/gnome-session', 'usr/bin/gnome-shell',
    'usr/bin/kgx', 'usr/bin/nautilus', 'usr/bin/gnome-text-editor',
    'usr/bin/gnome-control-center', 'usr/bin/epiphany',
    'usr/share/gnome-session/sessions/gnome.session',
    'usr/lib/systemd/system/gdm.service',
)
SESSION = '''#!/bin/sh
set -eu
if [ "${XDG_SESSION_TYPE:-}" != wayland ]; then
    echo 'Luma desktop requires a Wayland session; use the independent console for recovery.' >&2
    exit 1
fi
if [ "$(id -u)" -lt 1000 ] || [ "$(id -u)" -ge 65534 ]; then
    echo 'Luma desktop requires an installed interactive account.' >&2
    exit 1
fi
export XDG_CURRENT_DESKTOP=GNOME
export XDG_SESSION_DESKTOP=luma
exec /usr/bin/gnome-session --session=gnome
'''


def target(edition, mode):
    if edition not in ('headless', 'desktop') or mode not in ('live', 'installed'):
        raise ValueError('unknown edition or boot mode')
    return 'graphical.target' if (edition, mode) == ('desktop', 'installed') else 'multi-user.target'


def geometry(edition):
    if edition not in ('headless', 'desktop'):
        raise ValueError('unknown edition')
    # MiB. GNOME's larger root and its offline bundle need separate capacity.
    return (6144, 8192) if edition == 'desktop' else (4096, 6144)


def verify_boot_target(command_line, edition, mode):
    expected = 'systemd.unit='+target(edition, mode)
    words = command_line.rstrip(b'\0').decode('ascii').split()
    if [word for word in words if word.startswith('systemd.unit=')] != [expected]:
        raise ValueError('signed boot target does not match edition/mode')
    if any(word.startswith(('rd.systemd.unit=', 'systemd.wants=')) or
           word in ('single', 'rescue', 'emergency', '1', '3', '5') for word in words):
        raise ValueError('unexpected alternate boot target override')


def put(root, name, data, mode=0o644):
    path = root/name
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError('refusing linked desktop configuration: '+name)
    path.write_text(data)
    path.chmod(mode)


def configure(root, edition):
    target(edition, 'installed')  # Closed edition validation.
    if edition == 'headless':
        return {'profile': 'console', 'wayland_session_tested': False}
    for name in REQUIRED:
        path = root/name
        if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
            raise ValueError('missing packaged desktop prerequisite: '+name)
    put(root, 'usr/share/luma-os/desktop-profile', PROFILE+'\n')
    put(root, 'etc/locale.conf', 'LANG=C.UTF-8\n')
    locale = root/'etc/default/locale'
    if locale.is_symlink():
        if str(locale.readlink()) != '../locale.conf':
            raise ValueError('unexpected packaged locale alias')
    else:
        put(root, 'etc/default/locale', 'LANG=C.UTF-8\n')
    put(root, 'usr/libexec/luma-os/luma-wayland-session', SESSION, 0o755)
    put(root, 'usr/share/wayland-sessions/luma.desktop', '''[Desktop Entry]
Name=Luma (Wayland)
Comment=Model-independent local GNOME session
Type=Application
Exec=/usr/libexec/luma-os/luma-wayland-session
TryExec=/usr/libexec/luma-os/luma-wayland-session
DesktopNames=GNOME;
''')
    put(root, 'etc/gdm3/custom.conf', '''[daemon]
WaylandEnable=true
DefaultSession=luma.desktop
AutomaticLoginEnable=false
TimedLoginEnable=false
[security]
DisallowTCP=true
[xdmcp]
Enable=false
''')
    # Do not present an X11 session as fulfillment of the Wayland baseline.
    # Preserve packaged bytes under non-session filenames in this fresh root.
    for path in sorted((root/'usr/share/xsessions').glob('*.desktop')):
        disabled = path.with_suffix('.desktop.disabled')
        if path.is_symlink() or not path.is_file() or disabled.exists() or disabled.is_symlink():
            raise ValueError('unexpected existing desktop session artifact')
        path.rename(disabled)
    manager = root/'etc/systemd/system/display-manager.service'
    manager.parent.mkdir(parents=True, exist_ok=True)
    if manager.is_symlink():
        destination = str(manager.readlink())
        if destination in ('/lib/systemd/system/gdm3.service', '/usr/lib/systemd/system/gdm3.service'):
            alias = root/'usr/lib/systemd/system/gdm3.service'
            if not alias.is_symlink() or str(alias.readlink()) != 'gdm.service':
                raise ValueError('unexpected packaged GDM alias')
        elif destination not in ('/lib/systemd/system/gdm.service', '/usr/lib/systemd/system/gdm.service'):
            raise ValueError('unexpected display manager')
    elif manager.exists():
        raise ValueError('refusing non-link display manager unit')
    else:
        manager.symlink_to('/usr/lib/systemd/system/gdm.service')
    put(root, 'etc/systemd/system/gdm.service.d/luma.conf', '''[Unit]
ConditionKernelCommandLine=luma.mode=installed
# Login must remain independent of inference and product control services.
[Service]
TimeoutStartSec=90
TimeoutStopSec=30
''')
    put(root, 'usr/share/applications/luma-workspace.desktop', '''[Desktop Entry]
Type=Application
Name=Luma Workspace (laboratory)
Comment=Local reference workspace; files and desktop remain available independently
Exec=epiphany http://127.0.0.1:8765
Icon=utilities-terminal
Terminal=false
Categories=Utility;
''')
    return {'profile': PROFILE, 'wayland_session_tested': False,
            'model_required_for_login': False, 'live_graphical_login': False}
