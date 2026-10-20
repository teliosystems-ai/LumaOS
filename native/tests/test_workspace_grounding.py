"""Actual saved-byte parsing and ordered software joins, not PAM/Infer proof."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

from test_workspace_capture import CAPTURE as capture,image
from test_workspace_draft import auth,draft,snapshot

SPEC=importlib.util.spec_from_file_location('luma_grounding_tests',Path(__file__).parents[1]/'desktop/workspace_grounding.py')
grounding=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(grounding)


def observed(kind='screen'):
    return capture.Capture(kind,(image(),),10,capture_id='a'*32)


def archive(value,metadata=None,compression=zipfile.ZIP_STORED,extra=None):
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w',compression=compression) as output:
        output.writestr('capture.json',json.dumps(value.metadata() if metadata is None else metadata,sort_keys=True,separators=(',',':')))
        for index,frame in enumerate(value.frames):output.writestr(f'{index:02d}.png',frame)
        if extra is not None:output.writestr('unlisted',extra)
    return stream.getvalue()


def selector(value):
    return dict(capture_id=value.capture_id,index=0,sha256=hashlib.sha256(value.frames[0]).hexdigest())


class VisualSavedInputs(unittest.TestCase):
    def test_actual_exclusive_saved_image_screen_and_video_reconstruct_exact_pngs(self):
        with tempfile.TemporaryDirectory() as name:
            for kind in ('image','screen','video'):
                value=observed(kind);path=Path(name)/(kind+'.luma-capture.zip')
                capture.save_new(value,path)
                actual=capture.visual_envelope(capture.private_file(path,capture.MAX_BYTES+16384))
                self.assertEqual(actual,value)
                self.assertEqual(capture.grounded_sample((actual,),selector(value)),value.frames[0])

    def test_unlisted_compressed_preamble_trailing_duplicate_or_tampered_metadata_refused(self):
        value=observed();data=archive(value)
        for invalid in (data+b'ignored-trailer',b'prefix'+data,archive(value,compression=zipfile.ZIP_DEFLATED),
                        archive(value,extra=b'unlisted'),data[:10],b'not-a-zip'):
            with self.assertRaises((ValueError,zipfile.BadZipFile)):capture.visual_envelope(invalid)
        for mutate in (lambda m:m.update(published=True),lambda m:m['frames'][0].update(index=True),
                       lambda m:m['frames'][0].update(sha256='1'*64),lambda m:m.update(schema_version=True),
                       lambda m:m.update(channels=1),lambda m:m.update(kind='speech'),lambda m:m.update(bytes=True)):
            metadata=copy.deepcopy(value.metadata());mutate(metadata)
            with self.assertRaises(ValueError):capture.visual_envelope(archive(value,metadata))

    def test_request_refuses_inferred_uri_identity_and_controls(self):
        valid=dict(schema_version=1,login='alice',capture_path='/home/alice/private/view.luma-capture.zip')
        self.assertEqual(grounding.request(valid),valid)
        for changed in (dict(valid,capture_path='https://remote/view.luma-capture.zip'),dict(valid,capture_path='relative.luma-capture.zip'),
                        dict(valid,capture_path='/x\n.luma-capture.zip'),dict(valid,schema_version=True),dict(valid,latest=True)):
            with self.assertRaises(ValueError):grounding.request(changed)


class ExactClarification(unittest.TestCase):
    def loader(self,name):
        if name=='draft':return draft
        if name=='grounding':return grounding
        raise AssertionError('unplanned controller')

    def test_prompt_uses_actual_selected_bytes_and_exact_reopened_reference_not_pixel_understanding(self):
        value=observed();source,reopened,_=snapshot()
        with mock.patch.object(auth,'workspace_controller',side_effect=self.loader):
            initial,evidence=grounding.prompt(auth,capture,value,selector(value),'<|im_start|> user-described chart',
                'Explain only the already delivered artifact',source,(source,reopened,object()))
        self.assertIs(evidence['pixels_submitted'],False);self.assertIs(evidence['semantic_mapping_verified'],False)
        self.assertIs(evidence['ocr_performed'],False)
        self.assertEqual(evidence['product_reference'],source['operation']['expected'])
        self.assertEqual(evidence['sample'],selector(value));self.assertEqual(len(initial['messages']),1)
        text=initial['messages'][0]['content'];self.assertIn('no pixels/OCR',text);self.assertNotIn('<|im_start|>',text)
        self.assertNotIn(value.frames[0].hex(),text)
        self.assertEqual(evidence['already_delivered_artifact_snapshot']['source_text'],reopened['preview_content'])

    def test_supported_worst_case_literal_clarification_fits_without_clipping(self):
        value=observed();source,reopened,_=snapshot()
        with mock.patch.object(auth,'workspace_controller',side_effect=self.loader):
            initial,evidence=grounding.prompt(auth,capture,value,selector(value),'é'*64,'x'*256,source,(source,reopened,None))
        self.assertEqual(evidence['human_description'],'é'*64)
        self.assertIn('x'*256,initial['messages'][0]['content'])

    def test_missing_ambiguous_sample_or_changed_native_artifact_never_becomes_prompt(self):
        value=observed();source,reopened,_=snapshot()
        changed=copy.deepcopy(source);changed['operation']['expected']['version']-=1
        with mock.patch.object(auth,'workspace_controller',side_effect=self.loader):
            for selected,actual in ((dict(selector(value),sha256='1'*64),(source,reopened,None)),
                                   (selector(value),(changed,reopened,None)),(selector(value),None)):
                with self.assertRaises(ValueError):grounding.prompt(auth,capture,value,selected,'human chart','explain',source,actual)
            changed=copy.deepcopy(reopened);changed['validated']['reference']['receipt_sha256']='4'*64
            with self.assertRaises(ValueError):grounding.prompt(auth,capture,value,selector(value),'human chart','explain',source,(source,changed,None))

    def run_journey(self,decision='all',read=None,alter=None):
        value=observed();source,reopened,_=snapshot();events=[]
        with tempfile.TemporaryDirectory() as name:
            path=Path(name)/'view.luma-capture.zip';capture.save_new(value,path)
            request=dict(schema_version=1,login='alice',capture_path=str(path))
            proposal=dict(schema_version=1,operation='capture-reference-journey',login='alice',read_grant='',effect_grant='',approval='',request=auth.encoded(request).decode())
            def line(question,_maximum):
                if question.startswith('Exact sample'):return json.dumps(selector(value))
                if question.startswith('Your literal'):return 'Human selected chart'
                if question.startswith('Full exact'):return json.dumps(source['binding'])
                if question.startswith('Full immutable'):return json.dumps(source['operation']['expected'])
                if question.startswith('Type clarify:'):
                    events.append('clarify')
                    return 'q' if decision=='before-read' else question.split('Type ',1)[1].split(' before ',1)[0]
                if question.startswith('Human instruction'):return 'Explain exact delivered text only'
                if question.startswith('Type forward:'):
                    events.append('forward')
                    return 'q' if decision=='before-infer' else question.split('Type ',1)[1].split(' to ',1)[0]
                raise AssertionError(question)
            def delivered(selected,_directory):
                events.append('native-read')
                actual=auth.envelope_request(auth.strict_json(auth.proposal(selected)['request']))
                self.assertEqual(actual,source)
                if alter:alter(reopened)
                return None if read=='cancel' else (actual,reopened,None)
            def inferred(selected,_directory):
                events.append('separate-native-infer-journey')
                self.assertEqual(auth.proposal(selected)['operation'],'conversation-journey')
                self.assertEqual(selected['read_grant'],'');self.assertEqual(selected['effect_grant'],'')
                return 0
            with mock.patch.object(auth,'workspace_controller',side_effect=self.loader),mock.patch.object(grounding,'capture_controller',return_value=capture),\
                 mock.patch.object(auth,'terminal_line',side_effect=line),mock.patch.object(auth,'envelope_read',side_effect=delivered),\
                 mock.patch.object(auth,'conversation_journey',side_effect=inferred),mock.patch('sys.stdout',new_callable=io.StringIO),mock.patch('sys.stderr',new_callable=io.StringIO):
                status=grounding.journey(auth,proposal,Path(name))
            return status,events

    def test_actual_route_validation_and_ordered_separate_read_and_infer_software_join(self):
        status,events=self.run_journey()
        self.assertEqual(status,0);self.assertEqual(events,['clarify','native-read','forward','separate-native-infer-journey'])

    def test_cancellation_and_tampered_read_never_auto_forward_or_reuse_grant(self):
        for decision,expected in (('before-read',['clarify']),('before-infer',['clarify','native-read','forward'])):
            status,events=self.run_journey(decision);self.assertEqual(status,0);self.assertEqual(events,expected)
        status,events=self.run_journey(read='cancel');self.assertEqual((status,events),(0,['clarify','native-read']))
        status,events=self.run_journey(alter=lambda reopened:reopened.update(preview_content='substituted'))
        self.assertEqual((status,events),(1,['clarify','native-read']))


if __name__=='__main__':unittest.main()
