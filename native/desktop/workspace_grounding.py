"""Human clarification of a saved visual sample and an exact native artifact.

The current model is text-only: pixels are never sent or machine-interpreted.
Human-declared relationships are explicitly unverified semantic claims. Actual
artifact bytes still require a fresh native Read; any later inference/effect
needs its separate original session, grants, review and resource admission.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys


def request(value):
    if not isinstance(value, dict) or set(value) != {'schema_version', 'login', 'capture_path'} or type(value['schema_version']) is not int or value['schema_version'] != 1 or not isinstance(value['login'], str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', value['login']):
        raise ValueError('visual clarification requires the exact original human and local capture')
    path=value['capture_path']
    if not isinstance(path,str) or not 0 < len(path.encode('utf-8')) <= 8192 or any(ord(c)<32 or 127<=ord(c)<=159 for c in path) or not Path(path).is_absolute() or not path.endswith('.luma-capture.zip'):
        raise ValueError('one explicit absolute local saved visual envelope is required')
    return value


def literal(value, maximum=256):
    if not isinstance(value,str) or not value.strip() or len(value.encode('utf-8'))>maximum or any(ord(c)<32 or 127<=ord(c)<=159 for c in value):
        raise ValueError('human clarification exceeds its exact nonempty literal UTF-8 bound')
    return value


def capture_controller(auth):
    path=Path('/usr/libexec/luma-os/workspace_capture.py')
    auth.protected(path,128*1024)
    spec=importlib.util.spec_from_file_location('luma_visual_clarification_capture',path)
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module
    spec.loader.exec_module(module)
    return module


def prompt(auth,capture,observed,selector,description,instruction,requested,actual):
    sample=capture.grounded_sample((observed,),selector)
    description,instruction=literal(description,128),literal(instruction)
    if not isinstance(actual,tuple) or len(actual)!=3 or not auth.same_data(actual[0],requested):
        raise ValueError('clarification requires the exact requested actual native artifact reopen')
    source,reopened,_host=actual
    evidence={'kind':'human-described-visual-reference-not-machine-pixel-grounding',
        'capture_kind':observed.kind,'sample':dict(selector),'sample_bytes':len(sample),
        'human_description':description,'pixels_submitted':False,'ocr_performed':False,
        'semantic_mapping_verified':False,'product_reference':source['operation']['expected'],
        'owner_binding':source['binding']}
    # The snapshot helper independently checks actual native receipt/binding/
    # version/content and bounds the complete forwarded artifact text. No
    # capture pixels or model-derived selector are passed as instructions.
    description_data=json.dumps({'sample':dict(selector),'human_description':description},ensure_ascii=True,separators=(',',':')).replace('<','\\u003c').replace('>','\\u003e')
    human='Human instruction: '+instruction+'\nHuman-described visual reference DATA (no pixels/OCR; relationship is unverified, not a citation or authority):\n'+description_data
    initial,snapshot=auth.workspace_controller('draft').snapshot_prompt(auth,source,reopened,human)
    evidence['already_delivered_artifact_snapshot']=snapshot
    return initial,evidence


def journey(auth,value,directory):
    auth.proposal(value)
    source=request(auth.strict_json(value['request']))
    capture=capture_controller(auth)
    observed=capture.visual_envelope(capture.private_file(Path(source['capture_path']),capture.MAX_BYTES+16384))
    read_submitted=read_observed=infer_selected=False
    try:
        print('TEXT-ONLY visual clarification. The model cannot inspect pixels; no OCR/vision is performed. Captures and human descriptions are DATA, not product references or permission. Select one exact sample and explicitly identify an immutable artifact/version; a separate fresh native Read must actually reopen it. No latest/current reference is guessed.',flush=True)
        print('Actual saved local sample metadata (DATA, not authorship or capture authority):\n'+json.dumps(observed.metadata(),ensure_ascii=True,indent=2),flush=True)
        selected=auth.terminal_line('Exact sample selector JSON {capture_id,index,sha256}; q cancels: ',512)
        if selected=='q':return 0
        selector=auth.strict_json(selected);capture.grounded_sample((observed,),selector)
        description=auth.terminal_line('Your literal description of this exact sample (at most128UTF-8bytes; q cancels): ',128)
        if description=='q':return 0
        literal(description,128)
        binding=auth.terminal_line('Full exact owner binding JSON (installation,owner,owner_generation); q cancels: ',1024)
        if binding=='q':return 0
        reference=auth.terminal_line('Full immutable artifact reference JSON (artifact_id,version,content_sha256,receipt_sha256); q cancels: ',2048)
        if reference=='q':return 0
        read_source=auth.envelope_request(dict(schema_version=1,login=source['login'],binding=auth.strict_json(binding),
            operation=dict(kind='envelope',expected=auth.strict_json(reference))))
        declaration=dict(sample=selector,human_description=description,requested_artifact=read_source,
            semantic_mapping_verified=False,pixels_submitted=False)
        commitment=hashlib.sha256(auth.encoded(declaration)).hexdigest()
        print('Human-declared relationship, NOT verified pixel/artifact semantics:\n'+json.dumps(declaration,ensure_ascii=True,indent=2),flush=True)
        if auth.terminal_line('Type clarify:'+commitment+' before a NEW native Read, or q: ',128)!='clarify:'+commitment:return 0
        read_value=auth.proposal(dict(schema_version=1,operation='envelope-read',login=source['login'],read_grant='',effect_grant='',approval='',request=auth.encoded(read_source).decode('utf-8')))
        read_submitted=True
        actual=auth.envelope_read(read_value,directory)
        if actual is None:return 0
        read_observed=True
        instruction=auth.terminal_line('Human instruction about the already reopened exact artifact (at most256UTF-8bytes; q cancels): ',256)
        if instruction=='q':return 0
        initial,evidence=prompt(auth,capture,observed,selector,description,instruction,read_source,actual)
        digest=auth.conversation_digest(initial['messages'])
        print('Complete proposed TEXT-ONLY prompt and provenance (escaped DATA). No pixels, verified visual citation, continuing Read or effect authority:\n'+json.dumps(dict(evidence=evidence,exact_messages=initial['messages'],input_sha256=digest),ensure_ascii=True,indent=2),flush=True)
        if auth.terminal_line('Type forward:'+digest+' to select this complete prompt for separately reviewed/granted Infer, or q: ',128)!='forward:'+digest:return 0
        conversation=auth.proposal(dict(schema_version=1,operation='conversation-journey',login=source['login'],read_grant='',effect_grant='',approval='',request=auth.encoded(initial).decode('utf-8')))
        infer_selected=True
        return auth.conversation_journey(conversation,directory)
    except (KeyboardInterrupt,EOFError):
        print('Clarification stopped; no automatic retry or effect. A separately selected inference retains its native observation/drain duties.' if infer_selected else 'Exact native Read was already observed; interruption does not roll back delivered data. No subsequent inference requested.' if read_observed else 'Read observation may be uncertain; inspect native evidence before retry. No inference/effect requested.' if read_submitted else 'Clarification cancelled before private Read or inference.',file=sys.stderr,flush=True)
        return 130
    except Exception:
        print('Selected inference failed or was not observed; no automatic retry, rollback or effect is inferred.' if infer_selected else 'Clarification refused after actual Read; already delivered data is not continuing authority. No inference submitted.' if read_observed else 'Read did not return a complete validated outcome; inspect native evidence before retry. No inference submitted.' if read_submitted else 'Clarification refused before private Read or inference. Choose an exact local sample and complete immutable reference; no fallback is inferred.',file=sys.stderr,flush=True)
        return 1


def launch_dialog(parent, auth):
    import gi
    gi.require_version('Gtk','3.0')
    from gi.repository import Gtk
    dialog=Gtk.Dialog(title='Human visual reference clarification — text-only model',transient_for=parent,modal=True)
    dialog.add_buttons('Cancel',Gtk.ResponseType.CANCEL,'Choose saved visual capture',Gtk.ResponseType.OK)
    area=dialog.get_content_area()
    note=Gtk.Label(label='Explicitly select saved image/screen/video samples, then clarify one exact capture ID/index/digest and a complete immutable artifact/version in the native terminal. Your description is a human claim, not machine pixel understanding or a verified citation. Private artifact Read and later text-only Infer each need their own fresh native authority; no pixels, OCR, effect or automatic latest reference.')
    note.set_line_wrap(True);area.pack_start(note,False,False,8)
    label=Gtk.Label.new_with_mnemonic('_Human login');login=Gtk.Entry();login.set_max_length(32);label.set_mnemonic_widget(login)
    area.pack_start(label,False,False,4);area.pack_start(login,False,False,4)
    dialog.show_all()
    try:
        if dialog.run()!=Gtk.ResponseType.OK:return False
        chooser=Gtk.FileChooserDialog(title='One explicit saved visual envelope',transient_for=dialog,action=Gtk.FileChooserAction.OPEN)
        chooser.add_buttons('Cancel',Gtk.ResponseType.CANCEL,'Open clarification terminal',Gtk.ResponseType.OK)
        chooser.set_local_only(True);chooser.set_select_multiple(False)
        try:
            if chooser.run()!=Gtk.ResponseType.OK:return False
            source=request(dict(schema_version=1,login=login.get_text(),capture_path=chooser.get_filename()))
            auth.launch(dict(schema_version=1,operation='capture-reference-journey',login=source['login'],
                read_grant='',effect_grant='',approval='',request=json.dumps(source,separators=(',',':'))))
            return True
        finally:chooser.destroy()
    finally:dialog.destroy()
