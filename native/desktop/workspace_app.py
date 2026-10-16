#!/usr/bin/python3
"""GTK/WebKit manual native preview. Launch installed with python3 -I.

WebKitGTK API references:
https://webkitgtk.org/reference/webkit2gtk/stable/ctor.WebContext.new_ephemeral.html
https://webkitgtk.org/reference/webkit2gtk/stable/method.WebContext.register_uri_scheme.html
https://webkitgtk.org/reference/webkit2gtk/stable/method.UserContentManager.register_script_message_handler.html
https://webkitgtk.org/reference/webkit2gtk/stable/method.WebView.evaluate_javascript.html
"""
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import threading
from urllib.parse import urlsplit

BASE = Path('/usr/share/luma-os/workspace')
PAGE = 'luma-workspace://manual/native-workspace.html'
ASSETS = {'/native-workspace.html': ('native-workspace.html', 'text/html'),
          '/native-workspace.js': ('native-workspace.js', 'application/javascript'),
          '/native-workspace.css': ('native-workspace.css', 'text/css')}


def protected_file(path, maximum):
    if path.resolve(strict=True) != path:
        raise ValueError('workspace asset path must be canonical')
    for parent in path.parents:
        metadata = parent.stat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError('workspace asset ancestor is not root protected')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or before.st_mode & 0o7022 or not 0 < before.st_size <= maximum:
            raise ValueError('workspace asset metadata refused')
        data = bytearray()
        while len(data) <= maximum:
            block = os.read(descriptor, min(65536, maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        after = os.fstat(descriptor)
        identity = lambda m: (m.st_dev, m.st_ino, m.st_mode, m.st_uid, m.st_gid, m.st_nlink, m.st_size, m.st_mtime_ns, m.st_ctime_ns)
        if len(data) != before.st_size or identity(before) != identity(after):
            raise ValueError('workspace asset changed during capture')
        return bytes(data)
    finally:
        os.close(descriptor)


def main():
    if os.getuid() == 0 or os.geteuid() != os.getuid() or not sys.flags.isolated:
        raise ValueError('run as an ordinary user with /usr/bin/python3 -I')
    if any(os.environ.get(key) for key in ('WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS', 'GTK_MODULES', 'GI_TYPELIB_PATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH')):
        raise ValueError('workspace refuses injected runtime modules or disabled sandbox')
    host_path = Path('/usr/libexec/luma-os/workspace_host.py')
    protected_file(host_path, 128 * 1024)
    spec = importlib.util.spec_from_file_location('luma_native_workspace_host', host_path)
    host_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host_module)
    import gi
    gi.require_version('Gtk', '3.0')
    gi.require_version('WebKit2', '4.1')
    from gi.repository import Gio, GLib, Gtk, WebKit2
    Gtk.init([])

    # Capture the fixed trusted UI before enabling script messaging; arbitrary
    # local paths are never registered or served by this custom scheme.
    assets = {key: (protected_file(BASE / filename, 256 * 1024), mime)
              for key, (filename, mime) in ASSETS.items()}
    binary = host_module.PinnedExecutable(Path('/usr/libexec/luma-os/luma-platform'))
    context = WebKit2.WebContext.new_ephemeral()
    context.set_sandbox_enabled(True)
    if not context.get_sandbox_enabled():
        raise ValueError('WebKit process sandbox is unavailable')

    def serve(scheme_request):
        uri = urlsplit(scheme_request.get_uri())
        if uri.scheme != 'luma-workspace' or uri.netloc != 'manual' or uri.query or uri.fragment or uri.path not in assets:
            scheme_request.finish_error(GLib.Error('Unknown workspace resource'))
            return
        data, mime = assets[uri.path]
        scheme_request.finish(Gio.MemoryInputStream.new_from_bytes(GLib.Bytes.new(data)), len(data), mime)

    context.register_uri_scheme('luma-workspace', serve)
    view = WebKit2.WebView.new_with_context(context)
    settings = view.get_settings()
    for name, value in {'enable-javascript': True, 'enable-developer-extras': False,
                        'javascript-can-open-windows-automatically': False,
                        'allow-file-access-from-file-urls': False,
                        'allow-universal-access-from-file-urls': False,
                        'enable-html5-local-storage': False,
                        'media-playback-requires-user-gesture': True}.items():
        settings.set_property(name, value)
    closing = False
    pending_bytes = 0
    delivery_lock = threading.Lock()

    def deliver(event):
        nonlocal pending_bytes
        encoded = json.dumps(event, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
        size = len(encoded)
        with delivery_lock:
            if pending_bytes + size > 32 * 1024 * 1024:
                raise ValueError('workspace display backlog exceeds its bound')
            pending_bytes += size
        def on_main():
            nonlocal pending_bytes
            try:
                if not closing and view.get_uri() == PAGE:
                    # Data is serialized, never interpolated as executable source.
                    view.evaluate_javascript('window.LumaWorkspace.receive(' + encoded + ')', -1, None, PAGE, None, None, None)
            finally:
                with delivery_lock:
                    pending_bytes -= size
            return False
        GLib.idle_add(on_main)

    host = host_module.Host(binary, deliver)

    def message(_manager, javascript_result):
        try:
            if closing or view.get_uri() != PAGE:
                raise ValueError('workspace origin changed')
            value = javascript_result.get_js_value()
            if not value.is_string():
                raise ValueError('workspace message must be a bounded JSON string')
            host.submit(value.to_string())
        except Exception:
            deliver(dict(schema_version=1, id='protocol', state='refused', reason='closed-preview-protocol-refused', **host_module.FLAGS))

    manager = view.get_user_content_manager()
    manager.connect('script-message-received::workspace', message)
    if not manager.register_script_message_handler('workspace'):
        raise ValueError('workspace message channel registration failed')

    def decide(_view, decision, kind):
        if kind in (WebKit2.PolicyDecisionType.NAVIGATION_ACTION, WebKit2.PolicyDecisionType.NEW_WINDOW_ACTION):
            uri = decision.get_navigation_action().get_request().get_uri()
            if kind == WebKit2.PolicyDecisionType.NEW_WINDOW_ACTION or uri not in (PAGE, 'about:blank', 'about:srcdoc'):
                decision.ignore()
                return True
        return False

    view.connect('decide-policy', decide)
    view.connect('create', lambda *_: None)
    view.connect('permission-request', lambda _view, permission: (permission.deny(), True)[1])
    context.connect('download-started', lambda _context, download: download.cancel())
    window = Gtk.Window(title='Luma manual native preview — no publication authority')
    window.set_default_size(1100, 820)
    window.add(view)

    def close(*_):
        nonlocal closing
        closing = True
        host.close()
        Gtk.main_quit()
        return False

    window.connect('delete-event', close)
    view.load_uri(PAGE)
    window.show_all()
    Gtk.main()


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Luma manual preview unavailable: installed ordinary-user runtime or trusted inputs refused.', file=sys.stderr)
        raise SystemExit(1)
