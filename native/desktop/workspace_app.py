#!/usr/bin/python3
"""Native workspace with inert WebKit previews and separate PAM terminals.

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
import re
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


def conversation_proposal(auth, login, prompt, maximum):
    """Initial explicit prompt DATA only; no model, grant or history is assumed."""
    source = auth.conversation_request(dict(schema_version=1, login=login,
        messages=[dict(role='user', content=prompt)], max_tokens=maximum))
    return auth.proposal(dict(schema_version=1, operation='conversation-journey', login=login,
        read_grant='', effect_grant='', approval='', request=auth.encoded(source).decode('utf-8')))


def discovery_proposal(auth, login, binding_text, mode, selector_text, query, limit, dimensions):
    """Prepare exact discovery DATA for the separate original native terminal.

    No account, grant, publication or returned hit is established here. Python
    parses reference integers exactly; these values never pass through JS.
    """
    if mode not in ('search-semantic-selected', 'collection-search-semantic'):
        raise ValueError('select one supported semantic discovery mode')
    auth.discovery_query(query)
    if type(limit) is not int or not 1 <= limit <= 32 or type(dimensions) is not int or not 1 <= dimensions <= 8:
        raise ValueError('select 1 to 32 results and 1 to 8 latent dimensions')
    if not isinstance(selector_text, str) or not 0 < len(selector_text.encode('utf-8')) <= 32768:
        raise ValueError('exact reference selector exceeds its 32-KiB bound')
    if not isinstance(binding_text, str) or not 0 < len(binding_text.encode('utf-8')) <= 1024:
        raise ValueError('explicit owner binding exceeds its 1024-byte bound')
    selector = auth.strict_json(selector_text)
    operation = dict(kind=mode, query=query, limit=limit, dimensions=dimensions)
    if mode == 'search-semantic-selected':
        if not isinstance(selector, list) or not 1 <= len(selector) <= 64:
            raise ValueError('select 1 to 64 explicit exact references')
        previous = None
        for reference in selector:
            auth.reference_data(reference)
            if previous is not None and previous >= reference['artifact_id']:
                raise ValueError('references must be unique and sorted by artifact ID; no reference is silently replaced')
            previous = reference['artifact_id']
        operation['references'] = selector
    else:
        operation['expected'] = auth.reference_data(selector)
    source = auth.owner_request(dict(schema_version=1, login=login,
        binding=auth.strict_json(binding_text), operation=operation))
    return auth.proposal(dict(schema_version=1, operation='search-journey', login=login,
        read_grant='', effect_grant='', approval='', request=auth.encoded(source).decode('utf-8')))


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
    # The fixed ELF attachment is essential on restricted-userns Ubuntu. Bare
    # Python, generic unconfined, complain/enforce substitutions and stacked
    # labels are not a launcher bypass. This named userns permission is NOT a
    # claim of whole-app confinement or independently measured loaded policy.
    with open('/proc/self/attr/current', 'rb', buffering=0) as label:
        browser_module.require_workspace_label(label.read(257))
    import gi
    gi.require_version('Gtk', '3.0')
    gi.require_version('WebKit2', '4.1')
    from gi.repository import Gio, GLib, Gtk, WebKit2
    browser_version = (WebKit2.get_major_version(), WebKit2.get_minor_version(), WebKit2.get_micro_version())
    browser_manifest = protected_file(Path('/usr/share/luma-os/adapters/browser-presentation-v1.json'), 65536)
    browser_policy = browser_module.runtime_manifest(browser_manifest, browser_version)
    browser_module.verify_runtime_files(browser_policy, lambda path, maximum: protected_file(Path(path), maximum))
    browser_pin = browser_policy['library']
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
    window = Gtk.Window(title='Luma native workspace — authenticated operations in native terminals')
    window.set_default_size(1100, 820)
    layout = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
    toolbar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
    owner_actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    engine_actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    input_actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    toolbar.pack_start(owner_actions, False, False, 0)
    toolbar.pack_start(engine_actions, False, False, 0)
    toolbar.pack_start(input_actions, False, False, 0)
    authority_button = Gtk.Button(label='Authenticated native owner operation…')
    authority_note = Gtk.Label(label='Private results and passwords stay in the separate native terminal.')
    authority_note.set_line_wrap(True)
    authority_note.set_selectable(True)
    owner_actions.pack_start(authority_button, False, False, 4)
    toolbar.pack_start(authority_note, True, True, 4)
    conversation_button = Gtk.Button.new_with_mnemonic('_Local conversation…')
    conversation_button.set_tooltip_text('Genuine local model and fresh finite inference grant per explicit turn. Reviewed replies may become editable literal-text document drafts in the trusted terminal; publication still needs separate original PAM, target review and Read/effect grants.')
    owner_actions.pack_start(conversation_button, False, False, 4)
    read_button = Gtk.Button.new_with_mnemonic('_Read exact owner artifact…')
    read_button.set_tooltip_text('Fresh finite Read of one exact immutable reference. Complete reads may explicitly forward a bounded historical snapshot into separately reviewed/granted inference; private data never enters WebKit.')
    owner_actions.pack_start(read_button, False, False, 4)
    discovery_button = Gtk.Button.new_with_mnemonic('_Discover owner collections…')
    discovery_button.set_tooltip_text('Exact-selection or exact typed-collection semantic discovery in the separate native terminal. Each query and selected hit read requires a fresh finite Read grant; similarity never grants access.')
    owner_actions.pack_start(discovery_button, False, False, 4)
    workflow_button = Gtk.Button.new_with_mnemonic('_Managed engine workflow…')
    workflow_button.set_tooltip_text('Review, approve and apply an image-defined deterministic engine workflow in the original native PAM terminal; reopen and recalculate under fresh Read authority.')
    engine_actions.pack_start(workflow_button, False, False, 4)
    capture_button = Gtk.Button.new_with_mnemonic('_Permission-bound capture…')
    capture_button.set_tooltip_text('Independent visible consent window for selected PNG, portal screenshot/sampled video and short push-to-talk audio. Nothing is automatically sent to a model, published, transcribed or shared.')
    engine_actions.pack_start(capture_button, False, False, 4)
    speech_button = Gtk.Button.new_with_mnemonic('_Speak reviewed text…')
    speech_button.set_tooltip_text('Independent local rule-based English output: review literal text, Render, then separately Play. No microphone, model inference or publication; Stop, hiding and session lock revoke output.')
    input_actions.pack_start(speech_button, False, False, 4)
    transcription_button = Gtk.Button.new_with_mnemonic('_Transcribe saved audio…')
    transcription_button.set_tooltip_text('Explicit saved PCM capture to separately qualified auxiliary ASR under a fresh finite Infer grant. Review/correct the observed transcript before a separately granted text-model conversation; never an automatic OS effect.')
    input_actions.pack_start(transcription_button, False, False, 4)
    grounding_button = Gtk.Button.new_with_mnemonic('_Clarify captured reference…')
    grounding_button.set_tooltip_text('Explicit saved visual sample ID/index/digest plus human description and an exact immutable artifact/version. No pixel understanding or OCR. Fresh native Read and later text-only Infer remain independently reviewed and granted.')
    input_actions.pack_start(grounding_button, False, False, 4)
    collection_button = Gtk.Button.new_with_mnemonic('_Edit exact collection…')
    collection_button.set_tooltip_text('Human-authored exact typed collection with fresh original native review and independent Read/effect grants. Model/capture references never confer membership or publication authority.')
    input_actions.pack_start(collection_button, False, False, 4)
    lifecycle_button = Gtk.Button.new_with_mnemonic('_Versioned trash…')
    lifecycle_button.set_tooltip_text('Fresh original native lifecycle status, or explicitly reviewed logical trash/restore of an exact reference. Separate Read and Delete/Write grants; no physical purge, automatic undo or inferred latest version.')
    owner_actions.pack_start(lifecycle_button, False, False, 4)
    editor_button = Gtk.Button.new_with_mnemonic('_Bounded native editor…')
    editor_button.set_tooltip_text('Real original-PAM 30-second resource-leased edit period. Explicit Freeze drains but is NOT Saved; checkpoint commit and exact reopen require separately reviewed fresh C Read/effect authority. No automatic renewal, save or guessed latest resume.')
    engine_actions.pack_start(editor_button, False, False, 4)
    index_button = Gtk.Button.new_with_mnemonic('Native _index reads…')
    index_button.set_tooltip_text('Current status, lexical/feature queries and proposed build reviews through fresh original PAM and finite Read. No automatic build phase, effect, recovery or qualification.')
    engine_actions.pack_start(index_button, False, False, 4)
    recovery_button = Gtk.Button.new_with_mnemonic('_Admin encrypted recovery…')
    recovery_button.set_tooltip_text('Open the original native Admin terminal for encrypted fresh-owner restore, exact-prefix resume, or reviewed damaged-batch retirement. No key, password, grant or private result enters WebKit.')
    engine_actions.pack_start(recovery_button, False, False, 4)
    presentation_button = Gtk.Button(label='Present verified document…')
    presentation_button.set_sensitive(False)
    engine_actions.pack_start(presentation_button, False, False, 4)
    layout.pack_start(toolbar, False, False, 4)
    layout.pack_start(view, True, True, 0)
    window.add(layout)
    capture_windows = []
    capture_module = None
    speech_windows = []
    speech_module = None

    def permission_capture(_button):
        nonlocal capture_module
        if capture_windows:
            capture_windows[0].present()
            return
        try:
            if capture_module is None:
                path = Path('/usr/libexec/luma-os/workspace_capture.py')
                protected_file(path, 128*1024)
                spec = importlib.util.spec_from_file_location('luma_workspace_capture', path)
                loaded = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = loaded
                spec.loader.exec_module(loaded)
                capture_module = loaded
            child = capture_module.launch_capture(window)
            capture_windows.append(child)
            child.connect('destroy', lambda closed: capture_windows.remove(closed) if closed in capture_windows else None)
            authority_note.set_text('Independent capture consent/control window opened. Private captures remain there; no data is forwarded to WebKit, inference, publication or sharing. Stop/revoke and window close retain their own worker-drain obligations. Only one capture window may be active.')
        except Exception:
            authority_note.set_text('Capture unavailable or refused. The installed protected module, enforcing worker confinement and required portal/media runtime must be available. No capture, inference, publication or completion was inferred. Other manual controls remain usable.')

    capture_button.connect('clicked', permission_capture)

    def reviewed_speech(_button):
        nonlocal speech_module
        if speech_windows:
            speech_windows[0].present()
            return
        try:
            if speech_module is None:
                speech_module = auth_module.workspace_controller('speech')
            child = speech_module.launch_speech(window)
            speech_windows.append(child)
            child.connect('destroy', lambda closed: speech_windows.remove(closed) if closed in speech_windows else None)
            authority_note.set_text('Local speech review window opened. Render does not open audio; Play needs a separate human click. No inference, microphone, publication or audible completion was inferred.')
        except Exception:
            authority_note.set_text('Speech output unavailable or refused. No fallback runtime, playback or completion is inferred; other manual controls remain available.')
    speech_button.connect('clicked', reviewed_speech)

    def transcribe_saved(_button):
        dialog = Gtk.Dialog(title='Explicit saved speech — fresh native Infer terminal', transient_for=window, modal=True)
        dialog.add_buttons('Cancel', Gtk.ResponseType.CANCEL, 'Choose saved audio and open terminal', Gtk.ResponseType.OK)
        area = dialog.get_content_area()
        note = Gtk.Label(label='First use Permission-bound capture to hold-to-talk, stop and explicitly save audio as a private .luma-capture.zip. Select that one local envelope here. Separate qualified ASR uses current signed model custody, original PAM and a new finite Infer grant, even when the text LLM is unavailable. Tiny ASR can be wrong: review/edit its transcript before any fresh text-model or consequential workflow handoff. No private results or credentials enter WebKit.')
        note.set_line_wrap(True); area.pack_start(note, False, False, 8)
        label = Gtk.Label.new_with_mnemonic('_Human login')
        login = Gtk.Entry(); login.set_max_length(32); label.set_mnemonic_widget(login)
        area.pack_start(label, False, False, 4); area.pack_start(login, False, False, 4)
        dialog.show_all()
        try:
            if dialog.run() == Gtk.ResponseType.OK:
                chooser = Gtk.FileChooserDialog(title='Select one explicitly saved speech capture', transient_for=dialog, action=Gtk.FileChooserAction.OPEN)
                chooser.add_buttons('Cancel', Gtk.ResponseType.CANCEL, 'Select local audio envelope', Gtk.ResponseType.OK)
                chooser.set_local_only(True); chooser.set_select_multiple(False)
                try:
                    if chooser.run() == Gtk.ResponseType.OK:
                        source = {'schema_version': 1, 'login': login.get_text(), 'capture_path': chooser.get_filename()}
                        value = {'schema_version': 1, 'operation': 'speech-journey', 'login': source['login'],
                            'read_grant': '', 'effect_grant': '', 'approval': '', 'request': json.dumps(source, separators=(',', ':'))}
                        auth_module.launch(value)
                        authority_note.set_text('Auxiliary ASR terminal launched, not authenticated or completed here. Its exact audio, current signed auxiliary model, fresh finite Infer, original PAM, observed transcript and separate reviewed handoff remain in the native terminal.')
                finally:
                    chooser.destroy()
        except Exception:
            authority_note.set_text('Saved-audio transcription not launched. Select one explicit local saved PCM capture and valid human login; no inferred ASR/model/effect authority or completion.')
        finally:
            dialog.destroy()
            transcription_button.grab_focus()
    transcription_button.connect('clicked', transcribe_saved)

    def edit_collection(_button):
        try:
            auth_module.workspace_controller('collections').launch_dialog(window, auth_module)
            authority_note.set_text('Exact collection editor opened. Any native terminal launch is not authentication, membership validation or publication; fresh native review and independent grants remain mandatory.')
        except Exception:
            authority_note.set_text('Collection editor unavailable or refused; no collection, membership, grant or publication was inferred.')
    collection_button.connect('clicked', edit_collection)

    def lifecycle_control(_button):
        try:
            opened = auth_module.workspace_controller('lifecycle').launch_dialog(window, auth_module)
            authority_note.set_text('Native lifecycle terminal launched, not authenticated or completed. Current status and historical replay remain distinct; fresh original PAM, review and independent grants stay in that terminal.' if opened else 'Lifecycle selection cancelled; no native Read or logical change requested.')
        except Exception:
            authority_note.set_text('Lifecycle unavailable or refused; no current status, logical change, purge, restore permission or completion inferred.')
    lifecycle_button.connect('clicked', lifecycle_control)

    def bounded_editor(_button):
        try:
            opened = auth_module.workspace_controller('editor').launch_dialog(window, auth_module)
            authority_note.set_text('Native editor terminal launched, not authenticated, leased, Frozen or Saved here. Actual editing, bounded period, independent checkpoint review and exact reopen remain in the original terminal.' if opened else 'Editor selection cancelled; no edit period, checkpoint Read or publication requested.')
        except Exception:
            authority_note.set_text('Editor unavailable or refused; no active lease, Frozen draft, Saved checkpoint, automatic renewal or resume permission inferred.')
    editor_button.connect('clicked', bounded_editor)

    def index_reads(_button):
        try:
            opened = auth_module.workspace_controller('index').launch_dialog(window, auth_module)
            authority_note.set_text('Index terminal launched, not authenticated or completed. Actual Read, resource admission and current C proofs stay in the original terminal. No build effect requested.' if opened else 'Index selection cancelled; no private Read or build requested.')
        except Exception:
            authority_note.set_text('Index unavailable/refused. No current selection, private result, permission, build completion or automatic retry inferred.')
    index_button.connect('clicked', index_reads)

    def clarify_capture(_button):
        try:
            opened = auth_module.workspace_controller('grounding').launch_dialog(window, auth_module)
            authority_note.set_text('Human visual clarification terminal launched, not authenticated or completed. Exact sample, actual artifact-version Read and separately reviewed text-only Infer stay private in the native terminal; no pixels, OCR or verified visual citation was inferred.' if opened else 'Visual clarification cancelled before terminal launch; no Read, Infer or effect requested.')
        except Exception:
            authority_note.set_text('Visual clarification unavailable or refused. No private Read, model submission, pixel understanding or effect is inferred.')
    grounding_button.connect('clicked', clarify_capture)

    def local_conversation(_button):
        dialog = Gtk.Dialog(title='Local model conversation — separate original native terminal', transient_for=window, modal=True)
        dialog.add_buttons('Cancel', Gtk.ResponseType.CANCEL, 'Open conversation terminal', Gtk.ResponseType.OK)
        dialog.set_default_size(820, 530)
        area = dialog.get_content_area()
        note = Gtk.Label(label='Enter only your initial prompt and human login here. The genuine installed admitted model is selected by native authority, not this form. Every turn reviews its exact input, obtains original PAM and a fresh finite inference grant, and requires explicit confirmation in the terminal. Responses remain escaped untrusted text ONLY there. No private artifact, capture or history is attached automatically; model text never invokes tools, publishes, exports or changes system state. Manual workflows remain available without a model. The existing native 25-second request and 30-second authentication bounds are unchanged; the separate Windows five-minute purpose is not used here.')
        note.set_line_wrap(True)
        area.pack_start(note, False, False, 8)
        fields = {}
        for key, label_text, length in [('login', '_Human login', 32), ('maximum', '_Maximum output tokens (1–128)', 3)]:
            label = Gtk.Label.new_with_mnemonic(label_text)
            label.set_xalign(0)
            entry = Gtk.Entry()
            entry.set_max_length(length)
            label.set_mnemonic_widget(entry)
            fields[key] = entry
            area.pack_start(label, False, False, 3)
            area.pack_start(entry, False, False, 3)
        fields['maximum'].set_text('128')
        label = Gtk.Label.new_with_mnemonic('Initial _prompt (at most 4096 UTF-8 bytes; no credentials or grant IDs)')
        label.set_xalign(0)
        prompt = Gtk.TextView()
        prompt.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        label.set_mnemonic_widget(prompt)
        area.pack_start(label, False, False, 3)
        scroll = Gtk.ScrolledWindow()
        scroll.set_min_content_height(150)
        scroll.add(prompt)
        area.pack_start(scroll, True, True, 4)
        error = Gtk.Label()
        error.set_line_wrap(True)
        error.set_selectable(True)
        area.pack_start(error, False, False, 4)
        dialog.show_all()
        while dialog.run() == Gtk.ResponseType.OK:
            try:
                maximum = fields['maximum'].get_text()
                if not re.fullmatch(r'[1-9][0-9]{0,2}', maximum):
                    raise ValueError('explicit canonical token limit required')
                buffer = prompt.get_buffer()
                value = conversation_proposal(auth_module, fields['login'].get_text(),
                    buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False), int(maximum))
                auth_module.launch(value)
                authority_note.set_text('Native conversation terminal launched; not authenticated or completed here. Exact inference review, new finite grant, original PAM, observed results and cancellation remain there. Model text is never an OS action.')
                break
            except Exception:
                error.set_text('Conversation not launched. Enter a valid human login, a nonempty prompt no larger than 4096 UTF-8 bytes, and an exact 1–128 token limit. Manual controls remain available; no model, grant or completion was inferred.')
                prompt.grab_focus()
        dialog.destroy()
        conversation_button.grab_focus()

    conversation_button.connect('clicked', local_conversation)

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

    def grounded_read(_button):
        dialog = Gtk.Dialog(title='Grounded owner read — exact reference', transient_for=window, modal=True)
        dialog.add_buttons('Cancel', Gtk.ResponseType.CANCEL, 'Open read terminal', Gtk.ResponseType.OK)
        dialog.set_default_size(820, 430)
        area = dialog.get_content_area()
        note = Gtk.Label(label='Select the full installation / owner / account generation and immutable reference obtained from native review. These fields are data, not authority. Complete-envelope delivery uses one exact finite Read grant and continuous native owner, C-state and output checks. Advanced paging requires a separately granted 16-KiB page each time. No private content enters this browser. Stop with q before a read or Ctrl+C during it; no publication or export is requested.')
        note.set_line_wrap(True)
        area.pack_start(note, False, False, 8)
        entries = {}
        for key, text, maximum in [('login', '_Human login', 32),
                                   ('binding', '_Exact owner binding JSON', 1024),
                                   ('reference', 'Exact immutable _reference JSON', 2048)]:
            label = Gtk.Label.new_with_mnemonic(text)
            label.set_xalign(0)
            entry = Gtk.Entry()
            entry.set_max_length(maximum)
            label.set_mnemonic_widget(entry)
            entries[key] = entry
            area.pack_start(label, False, False, 3)
            area.pack_start(entry, False, False, 3)
        help_text = Gtk.Label(label='Binding keys: installation, owner, owner_generation. Reference keys: artifact_id, version, content_sha256, receipt_sha256. Paste complete exact values; there are no assumed identities or grants.')
        help_text.set_line_wrap(True)
        area.pack_start(help_text, False, False, 8)
        mode = Gtk.ComboBoxText()
        mode.append('envelope-read', 'Complete exact envelope — one fresh finite Read grant')
        mode.append('paged-read', 'Advanced: independently granted 16-KiB pages')
        mode.set_active_id('envelope-read')
        area.pack_start(mode, False, False, 4)
        error = Gtk.Label()
        error.set_line_wrap(True)
        area.pack_start(error, False, False, 4)
        dialog.show_all()
        while dialog.run() == Gtk.ResponseType.OK:
            try:
                operation = dict(kind='envelope', expected=auth_module.strict_json(entries['reference'].get_text()))
                if mode.get_active_id() == 'paged-read':
                    operation = dict(kind='page', expected=operation['expected'], offset=0, bytes=auth_module.PAGE_BYTES)
                source = dict(schema_version=1, login=entries['login'].get_text(),
                    binding=auth_module.strict_json(entries['binding'].get_text()), operation=operation)
                value = dict(schema_version=1, operation=mode.get_active_id(), login=source['login'],
                             read_grant='', effect_grant='', approval='', request=auth_module.encoded(source).decode('utf-8'))
                auth_module.launch(value)
                authority_note.set_text('Exact-reference read terminal launched. Native delivery checks the current owner, exact finite Read, C-state and output generation. Private results and observed completion remain there; no GUI completion is inferred.')
                break
            except Exception:
                error.set_text('Read not launched. Enter a valid human login and complete exact owner/reference JSON. No identity, authority or completion was inferred.')
                entries['binding'].grab_focus()
        dialog.destroy()

    read_button.connect('clicked', grounded_read)

    def owner_discovery(_button):
        dialog = Gtk.Dialog(title='Owner-local semantic discovery — exact selection', transient_for=window, modal=True)
        dialog.add_buttons('Cancel', Gtk.ResponseType.CANCEL, 'Open discovery terminal', Gtk.ResponseType.OK)
        dialog.set_default_size(900, 680)
        area = dialog.get_content_area()
        note = Gtk.Label(label='Choose one exact sorted selection or one genuine typed collection reference. These are DATA, not membership proof or authority. The separate original PAM terminal obtains a fresh finite Read scope and continuously checks owner, custody, generation and revocation. Results and private content stay ONLY there. A hit is rounded local TF-IDF/LSA similarity, not truth or permission. Reading a hit requires a new explicitly selected exact reference and independently granted Read; nothing opens automatically. Stop with q or Ctrl+C in that terminal.')
        note.set_line_wrap(True)
        area.pack_start(note, False, False, 8)
        entries = {}
        for key, text, maximum in [('login', '_Human login', 32), ('binding', 'Exact _owner binding JSON', 1024),
                                   ('query', '_Query: 1–8 ASCII alphanumeric terms; at most 256 bytes', 256)]:
            label = Gtk.Label.new_with_mnemonic(text)
            label.set_xalign(0)
            entry = Gtk.Entry()
            entry.set_max_length(maximum)
            label.set_mnemonic_widget(entry)
            entries[key] = entry
            area.pack_start(label, False, False, 2)
            area.pack_start(entry, False, False, 2)
        mode_label = Gtk.Label.new_with_mnemonic('_Discovery selection')
        mode = Gtk.ComboBoxText()
        mode.append('search-semantic-selected', 'Exact sorted references — 1 to 64 unique artifact IDs')
        mode.append('collection-search-semantic', 'One exact typed collection — current versions are never substituted')
        mode.set_active_id('search-semantic-selected')
        mode_label.set_mnemonic_widget(mode)
        area.pack_start(mode_label, False, False, 3)
        area.pack_start(mode, False, False, 3)
        limits = {}
        for key, text, lower, upper, value in [('limit', '_Maximum returned hits', 1, 32, 16), ('dimensions', '_Latent dimensions (not confidence)', 1, 8, 4)]:
            label = Gtk.Label.new_with_mnemonic(text + ' (' + str(lower) + '–' + str(upper) + ')')
            label.set_xalign(0)
            control = Gtk.Entry()
            control.set_max_length(2)
            control.set_text(str(value))
            label.set_mnemonic_widget(control)
            limits[key] = control
            area.pack_start(label, False, False, 2)
            area.pack_start(control, False, False, 2)
        selector_label = Gtk.Label.new_with_mnemonic('Exact _references JSON array, or a single typed collection reference object (at most 32 KiB)')
        selector_label.set_xalign(0)
        selector = Gtk.TextView()
        selector.set_wrap_mode(Gtk.WrapMode.CHAR)
        selector_label.set_mnemonic_widget(selector)
        area.pack_start(selector_label, False, False, 3)
        scroll = Gtk.ScrolledWindow()
        scroll.set_min_content_height(150)
        scroll.add(selector)
        area.pack_start(scroll, True, True, 4)
        help_text = Gtk.Label(label='Binding: installation, owner, owner_generation. Every exact reference: artifact_id, version, content_sha256, receipt_sha256. Paste complete values from native review. Full unsigned-64-bit versions/generations remain exact native integers. Semantic indexing is owner-local, ASCII-token statistical retrieval; it is not neural or multilingual search. To create or edit a typed collection, compose public source separately and use the authenticated native owner review/apply controls; this query dialog cannot publish membership.')
        help_text.set_line_wrap(True)
        area.pack_start(help_text, False, False, 6)
        error = Gtk.Label()
        error.set_line_wrap(True)
        error.set_selectable(True)
        area.pack_start(error, False, False, 4)
        dialog.show_all()
        while dialog.run() == Gtk.ResponseType.OK:
            try:
                buffer = selector.get_buffer()
                if any(not re.fullmatch(r'[1-9][0-9]?', control.get_text()) for control in limits.values()):
                    raise ValueError('exact positive integer limits required; decimals are never rounded')
                value = discovery_proposal(auth_module, entries['login'].get_text(), entries['binding'].get_text(),
                    mode.get_active_id(), buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False),
                    entries['query'].get_text(), int(limits['limit'].get_text()), int(limits['dimensions'].get_text()))
                auth_module.launch(value)
                authority_note.set_text('Discovery terminal launched. Original PAM, independently granted finite Read, exact native results and any separately selected fresh hit read are observed only there. No GUI query completion, current permission or publication is inferred.')
                break
            except Exception:
                error.set_text('Discovery not launched. Check the exact owner binding and reference shape/order, ASCII query and numeric limits. No identities, memberships, grants or result authority were assumed.')
                selector.grab_focus()
        dialog.destroy()
        discovery_button.grab_focus()

    discovery_button.connect('clicked', owner_discovery)

    def managed_workflow(_button):
        dialog = Gtk.Dialog(title='Native managed workflow — review before effect', transient_for=window, modal=True)
        dialog.add_buttons('Cancel', Gtk.ResponseType.CANCEL, 'Open workflow terminal', Gtk.ResponseType.OK)
        dialog.set_default_size(900, 740)
        area = dialog.get_content_area()
        note = Gtk.Label(label='Model-independent deterministic workflow. The image selects the workflow graph. Enter only exact source and identity data here; native PAM, separate finite Read/effect grants and exact approval stay in the terminal. Actual C-backed published, conflict-retained and no-change outcomes are shown there. Interruption after apply starts may leave a checkpoint; it is never treated as rollback or automatic retry. Fresh reopen/recalculation and subsequent edits require explicit new selections.')
        note.set_line_wrap(True)
        area.pack_start(note, False, False, 8)
        entries = {}
        for key, text, maximum in [('login', '_Human login', 32), ('binding', 'Exact _owner binding JSON', 1024),
            ('artifact_id', '_Artifact ID', 128), ('request_id', 'Stable _request ID (retain for reconciliation)', 128),
            ('expected', '_Expected immutable reference JSON; explicitly enter null for a NEW artifact', 2048)]:
            label = Gtk.Label.new_with_mnemonic(text)
            label.set_xalign(0)
            entry = Gtk.Entry()
            entry.set_max_length(maximum)
            label.set_mnemonic_widget(entry)
            entries[key] = entry
            area.pack_start(label, False, False, 2)
            area.pack_start(entry, False, False, 2)
        engine_label = Gtk.Label.new_with_mnemonic('_Deterministic engine')
        engine = Gtk.ComboBoxText()
        for name in auth_module.ENGINES:
            engine.append(name, name.capitalize())
        engine.set_active_id('document')
        engine_label.set_mnemonic_widget(engine)
        area.pack_start(engine_label, False, False, 3)
        area.pack_start(engine, False, False, 3)
        source_label = Gtk.Label.new_with_mnemonic('Exact editable engine _source JSON (up to 1 MiB)')
        source = Gtk.TextView()
        source.set_wrap_mode(Gtk.WrapMode.CHAR)
        source_label.set_mnemonic_widget(source)
        area.pack_start(source_label, False, False, 3)
        scroll = Gtk.ScrolledWindow()
        scroll.set_min_content_height(180)
        scroll.add(source)
        area.pack_start(scroll, True, True, 4)
        error = Gtk.Label()
        error.set_line_wrap(True)
        area.pack_start(error, False, False, 4)
        dialog.show_all()
        while dialog.run() == Gtk.ResponseType.OK:
            try:
                buffer = source.get_buffer()
                text = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False)
                request = dict(schema_version=1, request_id=entries['request_id'].get_text(), artifact_id=entries['artifact_id'].get_text(),
                    expected=auth_module.strict_json(entries['expected'].get_text()), engine=engine.get_active_id(), source=text)
                native = dict(schema_version=1, login=entries['login'].get_text(),
                    binding=auth_module.strict_json(entries['binding'].get_text()), operation=dict(kind='workflow', request=request))
                value = dict(schema_version=1, operation='workflow-journey', login=native['login'],
                    read_grant='', effect_grant='', approval='', request=auth_module.encoded(native).decode('utf-8'))
                auth_module.launch(value)
                authority_note.set_text('Native workflow terminal launched. Exact review, independent finite grants, approval, actual C-backed outcome and fresh reopen/recalculation are observed only there. No GUI success or current permission is inferred.')
                break
            except Exception:
                error.set_text('Workflow not launched. Supply a valid exact owner binding, identifiers, explicit expected reference or null, and bounded engine JSON. No account, graph, grant or completion was assumed.')
                entries['request_id'].grab_focus()
        dialog.destroy()

    workflow_button.connect('clicked', managed_workflow)

    def admin_recovery(_button):
        dialog = Gtk.Dialog(title='Native Admin recovery — exact reviewed data', transient_for=window, modal=True)
        dialog.add_buttons('Cancel', Gtk.ResponseType.CANCEL, 'Open Admin terminal', Gtk.ResponseType.OK)
        dialog.set_default_size(900, 680)
        area = dialog.get_content_area()
        note = Gtk.Label(label='Enter public request DATA only. Restore requires an independently selected origin SPKI digest, exact encrypted capsule path/size/digest, current Admin binding, and independently provisioned target binding. Explicit review:null requests a fresh empty-target review; an exact retained review requests native prefix validation/resume. Native PAM, recipient private-key input, finite Read + Recover/Write, exact approval and actual C-backed results remain ONLY in the separate terminal. Never paste a private key, password, grant, decrypted archive or content into this form.')
        note.set_line_wrap(True)
        area.pack_start(note, False, False, 8)
        mode_label = Gtk.Label.new_with_mnemonic('_Recovery action')
        mode = Gtk.ComboBoxText()
        mode.append('restore-journey', 'Encrypted fresh-owner restore / exact-prefix resume')
        mode.append('retire-journey', 'Inspect then retire a damaged restore owner-generation; retain all evidence')
        mode.set_active_id('restore-journey')
        mode_label.set_mnemonic_widget(mode)
        area.pack_start(mode_label, False, False, 3)
        area.pack_start(mode, False, False, 3)
        label = Gtk.Label.new_with_mnemonic('Exact restore Input _JSON (up to 96 KiB; DATA, never authority)')
        source = Gtk.TextView()
        source.set_wrap_mode(Gtk.WrapMode.CHAR)
        label.set_mnemonic_widget(source)
        area.pack_start(label, False, False, 3)
        scroll = Gtk.ScrolledWindow()
        scroll.set_min_content_height(280)
        scroll.add(source)
        area.pack_start(scroll, True, True, 4)
        fields = Gtk.Label(label='Required keys: schema_version, login, admin, target_login, target, independently_selected_origin_spki_sha256, request_namespace, key_role (owner or offline-admin), capsule_path, capsule_bytes, capsule_sha256, review. Retain the original encrypted capsule and exact native-reviewed Input for interrupted apply. For retirement paste that original Input with its complete non-null review; fresh protected Read/Recover inspection is mandatory. Retirement marks only that generation unavailable; it never heals, resets, removes evidence or creates an account.')
        fields.set_line_wrap(True)
        area.pack_start(fields, False, False, 8)
        error = Gtk.Label()
        error.set_line_wrap(True)
        error.set_selectable(True)
        area.pack_start(error, False, False, 4)
        dialog.show_all()
        while dialog.run() == Gtk.ResponseType.OK:
            try:
                buffer = source.get_buffer()
                text = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False)
                if not 0 < len(text.encode('utf-8')) <= auth_module.MAX_RECOVERY_REQUEST:
                    raise ValueError('bounded explicit recovery data required')
                request = auth_module.strict_json(text)
                auth_module.recovery_request(request)
                action = mode.get_active_id()
                if action == 'retire-journey':
                    request = dict(input=request, expected_review_sha256=None)
                value = dict(schema_version=1, operation=action, login=request['input']['login'] if action == 'retire-journey' else request['login'],
                    read_grant='', effect_grant='', approval='', request=auth_module.encoded(request).decode('utf-8'))
                auth_module.launch(value)
                authority_note.set_text('Admin recovery terminal launched, not completed. Original native PAM/key prompts, exact finite grants, durable inert resume data, approval and observed C-backed results remain there. Interruption after effect starts is uncertain/possibly partial, never automatic rollback or retry.')
                break
            except Exception:
                error.set_text('Recovery not launched. Supply only the complete bounded public Input with explicit current Admin/target bindings, independent origin pin and exact encrypted capsule. Retirement also requires its retained non-null batch review. No key, identity, authority or completion was inferred.')
                source.grab_focus()
        dialog.destroy()

    recovery_button.connect('clicked', admin_recovery)

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
        for capture_window in list(capture_windows):
            capture_window.destroy()
        for speech_window in list(speech_windows):
            speech_window.destroy()
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
