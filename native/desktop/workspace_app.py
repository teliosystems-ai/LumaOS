#!/usr/bin/python3
"""GTK/WebKit manual native preview. Launch installed with python3 -I.

WebKitGTK API references:
https://webkitgtk.org/reference/webkit2gtk/stable/ctor.WebContext.new_ephemeral.html
https://webkitgtk.org/reference/webkit2gtk/stable/method.WebContext.register_uri_scheme.html
https://webkitgtk.org/reference/webkit2gtk/stable/method.UserContentManager.register_script_message_handler.html
https://webkitgtk.org/reference/webkit2gtk/stable/method.WebView.evaluate_javascript.html
"""
import importlib.util
import hashlib
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
    auth_path = Path('/usr/libexec/luma-os/workspace_auth.py')
    protected_file(auth_path, 128 * 1024)
    auth_spec = importlib.util.spec_from_file_location('luma_native_workspace_auth', auth_path)
    auth_module = importlib.util.module_from_spec(auth_spec)
    auth_spec.loader.exec_module(auth_module)
    browser_path = Path('/usr/libexec/luma-os/browser_adapter.py')
    protected_file(browser_path, 128 * 1024)
    browser_spec = importlib.util.spec_from_file_location('luma_native_browser_adapter', browser_path)
    browser_module = importlib.util.module_from_spec(browser_spec)
    browser_spec.loader.exec_module(browser_module)
    import gi
    gi.require_version('Gtk', '3.0')
    gi.require_version('WebKit2', '4.1')
    from gi.repository import Gio, GLib, Gtk, WebKit2
    browser_version = (WebKit2.get_major_version(), WebKit2.get_minor_version(), WebKit2.get_micro_version())
    browser_manifest = protected_file(Path('/usr/share/luma-os/adapters/browser-presentation-v1.json'), 65536)
    browser_pin = browser_module.runtime_manifest(browser_manifest, browser_version)
    library = protected_file(Path(browser_pin['path']), 256*1024*1024)
    if len(library) != browser_pin['bytes'] or hashlib.sha256(library).hexdigest() != browser_pin['sha256']:
        raise ValueError('actual WebKit library differs from the fixed image dependency pin')
    del library
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
    last_document = None

    def deliver(event):
        nonlocal pending_bytes
        encoded = json.dumps(event, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
        size = len(encoded)
        with delivery_lock:
            if pending_bytes + size > 32 * 1024 * 1024:
                raise ValueError('workspace display backlog exceeds its bound')
            pending_bytes += size
        def on_main():
            nonlocal pending_bytes, last_document
            try:
                if not closing and view.get_uri() == PAGE:
                    if event.get('state') == 'completed' and event.get('result', {}).get('operation') == 'document':
                        last_document = event['result']['rendering']
                        presentation_button.set_sensitive(True)
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
    layout = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
    toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    authority_button = Gtk.Button(label='Authenticated native owner operation…')
    authority_note = Gtk.Label(label='Private results and passwords stay in the separate native terminal.')
    authority_note.set_line_wrap(True)
    toolbar.pack_start(authority_button, False, False, 4)
    toolbar.pack_start(authority_note, True, True, 4)
    presentation_button = Gtk.Button(label='Present verified document…')
    presentation_button.set_sensitive(False)
    toolbar.pack_start(presentation_button, False, False, 4)
    layout.pack_start(toolbar, False, False, 4)
    layout.pack_start(view, True, True, 0)
    window.add(layout)

    def authenticated_operation(_button):
        # Native GTK controls, not messages from rendered source/JavaScript.
        # No password field exists; only the real terminal can perform PAM.
        dialog = Gtk.Dialog(title='Original PAM / finite-grant native ceremony', transient_for=window, modal=True)
        dialog.add_buttons('Cancel', Gtk.ResponseType.CANCEL, 'Open native terminal', Gtk.ResponseType.OK)
        dialog.set_default_size(850, 620)
        area = dialog.get_content_area()
        note = Gtk.Label(label='Paste a full native request. Workflow requests select the image-defined engine workflow, never a caller workflow hash. Review grants and approvals in the terminal. Launch is not completion; interruption may leave an exact checkpoint requiring reconciliation.')
        note.set_line_wrap(True)
        area.pack_start(note, False, False, 6)
        entries = {}
        for key, label in [('login', 'Human login'), ('read_grant', 'Finite Read grant ID (review/apply)'),
                           ('effect_grant', 'Finite effect grant ID (apply)'), ('approval', 'Exact write:/retain:/recover: review (apply)')]:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            row.pack_start(Gtk.Label(label=label), False, False, 4)
            entry = Gtk.Entry()
            entry.set_max_length(128)
            row.pack_start(entry, True, True, 4)
            entries[key] = entry
            area.pack_start(row, False, False, 3)
        operation = Gtk.ComboBoxText()
        for name, text in [('inspection', 'Obtain exact inspection scope (no private read)'), ('review', 'Read/query or review the exact proposed effect'), ('apply', 'Apply the exact separately granted reviewed effect'),
                           ('office-proposal', 'Review independent native Office Read/Export scopes'), ('office-export', 'Export reviewed document to a new PDF file')]:
            operation.append(name, text)
        operation.set_active_id('inspection')
        area.pack_start(operation, False, False, 4)
        target_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        target_row.pack_start(Gtk.Label(label='New PDF target (Office export only)'), False, False, 4)
        target_entry = Gtk.Entry()
        target_row.pack_start(target_entry, True, True, 4)
        target_button = Gtk.Button(label='Choose new PDF…')
        target_row.pack_start(target_button, False, False, 4)
        area.pack_start(target_row, False, False, 4)

        def choose_pdf(_):
            chooser = Gtk.FileChooserDialog(title='Choose a new PDF file (existing files never overwritten)', transient_for=dialog,
                                            action=Gtk.FileChooserAction.SAVE)
            chooser.add_buttons('Cancel', Gtk.ResponseType.CANCEL, 'Select new file', Gtk.ResponseType.OK)
            chooser.set_current_name('luma-document.pdf')
            if chooser.run() == Gtk.ResponseType.OK:
                target_entry.set_text(chooser.get_filename() or '')
            chooser.destroy()

        target_button.connect('clicked', choose_pdf)
        source = Gtk.TextView()
        source.set_wrap_mode(Gtk.WrapMode.CHAR)
        scroll = Gtk.ScrolledWindow()
        scroll.add(source)
        area.pack_start(scroll, True, True, 4)
        dialog.show_all()
        if dialog.run() == Gtk.ResponseType.OK:
            try:
                buffer = source.get_buffer()
                text = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False)
                value = dict(schema_version=1, operation=operation.get_active_id(), request=text,
                             **{key: entry.get_text() for key, entry in entries.items()})
                if value['operation'] == 'office-export':
                    value['output_path'] = target_entry.get_text()
                auth_module.launch(value)
                authority_note.set_text('Native terminal launched; authentication, private results and actual checkpoint status are shown there. No completion inferred here.')
            except Exception:
                authority_note.set_text('Native terminal launch refused. Check the closed request, exact fields and installed private runtime; no completion inferred.')
        dialog.destroy()

    authority_button.connect('clicked', authenticated_operation)

    presentations = []

    def present_document(_button):
        if last_document is None:
            return
        if len(presentations) >= 2:
            authority_note.set_text('Two bounded presentation contexts have been used in this workspace session. No unobserved browser drainage or automatic capacity release is inferred; close the workspace before another session.')
            presentation_button.set_sensitive(False)
            return
        rendered = last_document
        observation = browser_module.Presentation(rendered['canonical_html'], rendered['html_sha256'], browser_version, browser_pin['sha256'])
        document_context = WebKit2.WebContext.new_ephemeral()
        document_context.set_sandbox_enabled(True)
        if not document_context.get_sandbox_enabled():
            raise ValueError('actual document WebKit sandbox unavailable')
        uri = 'luma-presentation://native/' + observation.sha256 + '.html'
        data = rendered['canonical_html'].encode('utf-8')

        def resource(request):
            if request.get_uri() != uri:
                observation.failed('resource-refused')
                request.finish_error(GLib.Error('Only the exact native document is available'))
                return
            request.finish(Gio.MemoryInputStream.new_from_bytes(GLib.Bytes.new(data)), len(data), 'text/html')

        document_context.register_uri_scheme('luma-presentation', resource)
        document_view = WebKit2.WebView.new_with_context(document_context)
        settings = document_view.get_settings()
        for name, value in {'enable-javascript': False, 'enable-developer-extras': False,
                            'allow-file-access-from-file-urls': False, 'allow-universal-access-from-file-urls': False,
                            'enable-html5-local-storage': False, 'javascript-can-open-windows-automatically': False}.items():
            settings.set_property(name, value)
        presentation = Gtk.Window(title='Native document presentation — load observation, not publication authority')
        presentation.set_default_size(950, 760)
        layout = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        stop = Gtk.Button(label='Stop document WebKit process (observe termination)')
        receipt = Gtk.Label()
        receipt.set_line_wrap(True)
        receipt.set_selectable(True)
        layout.pack_start(stop, False, False, 4)
        layout.pack_start(receipt, False, False, 4)
        layout.pack_start(document_view, True, True, 0)
        presentation.add(layout)

        def report():
            receipt.set_text(json.dumps(observation.receipt(), sort_keys=True, ensure_ascii=True, separators=(',', ':')))

        def changed(_view, event):
            if document_view.get_uri() != uri:
                observation.failed('unexpected-navigation')
            elif event == WebKit2.LoadEvent.STARTED:
                observation.started()
            elif event == WebKit2.LoadEvent.COMMITTED:
                observation.commit()
            elif event == WebKit2.LoadEvent.FINISHED:
                observation.finish()
            report()

        def failed(*_):
            observation.failed('load-failed')
            report()
            return True

        def terminated(*_):
            observation.terminated()
            report()

        def stop_now(reason):
            observation.request_stop(reason)
            document_view.stop_loading()
            document_view.terminate_web_process()
            report()

        def policy(_view, decision, kind):
            if kind in (WebKit2.PolicyDecisionType.NAVIGATION_ACTION, WebKit2.PolicyDecisionType.NEW_WINDOW_ACTION):
                target = decision.get_navigation_action().get_request().get_uri()
                if kind == WebKit2.PolicyDecisionType.NEW_WINDOW_ACTION or target != uri:
                    decision.ignore()
                    observation.failed('unexpected-navigation')
                    report()
                    return True
            return False

        document_view.connect('load-changed', changed)
        document_view.connect('load-failed', failed)
        document_view.connect('web-process-terminated', terminated)
        document_view.connect('decide-policy', policy)
        document_view.connect('create', lambda *_: None)
        document_view.connect('permission-request', lambda _view, permission: (permission.deny(), True)[1])
        document_context.connect('download-started', lambda _context, download: download.cancel())
        stop.connect('clicked', lambda *_: stop_now('human-cancel'))
        presentation.connect('delete-event', lambda *_: (stop_now('window-close'), False)[1])

        def deadline():
            # This is an observed event-loop deadline, not a realtime guarantee
            # or a forged claim that a browser process has actually drained.
            if observation.state not in ('failed', 'terminated'):
                stop_now('deadline')
            return False

        GLib.timeout_add_seconds(browser_module.SECONDS, deadline)
        presentations.append((document_view, observation))
        report()
        document_view.load_uri(uri)
        presentation.show_all()

    presentation_button.connect('clicked', present_document)

    def close(*_):
        nonlocal closing
        closing = True
        for document_view, observation in presentations:
            observation.request_stop('window-close')
            document_view.stop_loading()
            document_view.terminate_web_process()
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
