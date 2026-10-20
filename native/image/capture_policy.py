"""Closed build-time prerequisites for permission-bound native input capture."""
from pathlib import Path

PACKAGES = ('python3-gi', 'gir1.2-gstreamer-1.0', 'gstreamer1.0-plugins-base',
            'gstreamer1.0-plugins-good', 'gstreamer1.0-pipewire',
            'xdg-desktop-portal', 'xdg-desktop-portal-gnome', 'pipewire-pulse', 'apparmor-utils')
PROFILE = 'etc/apparmor.d/luma-workspace-capture'
PROFILES = ('luma-workspace-capture-audio', 'luma-workspace-capture-video')
REQUIRED = ('usr/libexec/luma-os/workspace_capture.py', 'usr/bin/python3.12',
            'usr/bin/aa-exec', PROFILE,
            'usr/lib/x86_64-linux-gnu/girepository-1.0/Gst-1.0.typelib',
            'usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstcoreelements.so',
            'usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstapp.so',
            'usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstaudioconvert.so',
            'usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstaudioresample.so',
            'usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstvideoconvertscale.so',
            'usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstvideorate.so',
            'usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstpulseaudio.so',
            'usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstpipewire.so',
            'usr/libexec/xdg-desktop-portal', 'usr/libexec/xdg-desktop-portal-gnome')


def verify(root):
    root = Path(root)
    for name in REQUIRED:
        target = root/name
        if not target.is_file() or target.is_symlink() or target.stat().st_size == 0:
            raise ValueError('missing native input capture prerequisite: '+name)
    profile = (root/PROFILE).read_text(encoding='utf-8')
    if (root/PROFILE).read_bytes() != (Path(__file__).parent/'overlay'/PROFILE).read_bytes():
        raise ValueError('capture confinement bytes differ from the reviewed build source')
    if (root/REQUIRED[0]).read_bytes() != (Path(__file__).parents[1]/'desktop/workspace_capture.py').read_bytes():
        raise ValueError('capture controller differs from the reviewed build source')
    for name in PROFILES:
        if f'profile {name} flags=(attach_disconnected,mediate_deleted)' not in profile:
            raise ValueError('capture worker profile identity is missing: '+name)
    return {'profile': 'explicit-input-capture-v1', 'runtime_prerequisites_present': True,
            'worker_profiles': list(PROFILES), 'device_permission_qualified': False,
            'speech_transcription_available': False,
            'native_publication_authority': False, 'model_submission_automatic': False}
