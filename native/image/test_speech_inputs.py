"""Actual public signatures plus the separate auxiliary ASR metadata adapter."""
import base64
import copy
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import provision_model_inputs as models
from test_model_inputs import Fixture


class SpeechPublicInputs(unittest.TestCase):
    def fixture(self, base):
        fixture = Fixture(base)
        fixture.pack()
        license_bytes = (Path(__file__).parent/'speech/WHISPER-MODEL-LICENSE').read_bytes()
        # This suite checks metadata/signatures, not model bytes/accuracy. The
        # actual 77.7MB parser and inference are separately executed on D.
        with mock.patch.object(models.speech.layout, 'inspect', return_value={'metadata_fixture': True}):
            proposal = models.speech.proposal('unused-metadata-fixture', license_bytes, 'Pack')
        m, p = proposal['manifest'], proposal['profile']
        parsed = models.ModelManifest.parse(models.canonical(m))
        prefix = 'model-packs/'+models.public.sha(parsed.canonical_bytes)+'/'
        fixture.put(prefix+'manifest.json', parsed.canonical_bytes)
        fixture.put(prefix+'manifest.sig', bytes.fromhex(fixture.keys.sign('pack', parsed.canonical_bytes)))
        for name, value in proposal['files'].items(): fixture.put(prefix+name, value)
        fixture.catalog['profiles'].append(p)
        fixture.refresh()
        return fixture, proposal, prefix

    def test_separate_asr_pack_uses_actual_public_signatures_and_no_availability_claim(self):
        with tempfile.TemporaryDirectory() as name:
            fixture, proposal, _ = self.fixture(Path(name))
            with models.ExitStack() as stack:
                tree = models.Tree(fixture.inputs, stack)
                self.assertEqual(models.validate(fixture.root, tree.values), 'lab')
            self.assertEqual(proposal['manifest']['model']['architecture'], 'whisper-tiny-multilingual')
            self.assertEqual(proposal['profile']['context_tokens'], 448)
            self.assertEqual(proposal['profile']['availability'], 'unavailable')
            self.assertEqual(proposal['profile']['certification_state'], 'not-certified')

    def test_auxiliary_metadata_cannot_relabel_llama_or_change_actual_decode_and_pcm_bounds(self):
        with tempfile.TemporaryDirectory() as name:
            _fixture, proposal, _ = self.fixture(Path(name))
            for change in (lambda p,m:p.update(runtime_tuple_sha256='1'*64),
                           lambda p,m:m['model'].update(architecture='qwen3'),
                           lambda p,m:m['runtime_tuples'][0].update(backend='llama.cpp'),
                           lambda p,m:m['context'].update(maximum_tokens=128),
                           lambda p,m:p.update(context_tokens=128),
                           lambda p,m:p['load_reservations'][0].update(bytes=1),
                           lambda p,m:m['blobs'][1].update(sha256='2'*64),
                           lambda p,m:m['model'].update(source='https://example.invalid/model.bin')):
                p,m=copy.deepcopy(proposal['profile']),copy.deepcopy(proposal['manifest'])
                change(p,m)
                with self.assertRaises(ValueError):models.speech.validate(p,m)

    def test_missing_or_changed_signed_asr_bytes_fail_common_closed_inventory(self):
        with tempfile.TemporaryDirectory() as name:
            fixture, _proposal, prefix = self.fixture(Path(name))
            with models.ExitStack() as stack:
                tree = models.Tree(fixture.inputs, stack)
                original = dict(tree.values)
                changed = dict(original); changed[prefix+'manifest.sig'] = b'\0'*64
                with self.assertRaises(ValueError):models.validate(fixture.root, changed)
                changed = dict(original); changed['unlisted-speech-config.json'] = b'{}'
                with self.assertRaises(ValueError):models.validate(fixture.root, changed)

    def test_model_notice_is_exact_and_no_metadata_only_fixture_claims_real_weights(self):
        notice=(Path(__file__).parent/'speech/WHISPER-MODEL-LICENSE').read_bytes()
        self.assertEqual(len(notice),1063)
        self.assertEqual(models.speech.sha(notice),models.speech.LICENSE_SHA256)
        with self.assertRaises(ValueError):
            with mock.patch.object(models.speech.layout,'inspect',return_value={'metadata_fixture':True}):
                models.speech.proposal('unused-metadata-fixture',b'not the model license','Pack')

    def test_explicit_lab_candidate_proposes_usable_signed_requirements_not_certificates(self):
        notice=(Path(__file__).parent/'speech/WHISPER-MODEL-LICENSE').read_bytes()
        with mock.patch.object(models.speech.layout,'inspect',return_value={'metadata_fixture':True}):
            for options in ({'lab_candidate':True}, {'lab_candidate':1,'software_test_report_sha256':'1'*64},
                            {'lab_candidate':True,'software_test_report_sha256':'0'*64},
                            {'lab_candidate':False,'software_test_report_sha256':'1'*64}):
                with self.assertRaises(ValueError):models.speech.proposal('unused',notice,'Pack',**options)
            value=models.speech.proposal('unused',notice,'Pack',lab_candidate=True,software_test_report_sha256='1'*64)
        self.assertEqual(value['profile']['availability'],'available')
        self.assertEqual(value['profile']['verification_state'],'verified')
        self.assertEqual(value['profile']['development_state'],'development-tested')
        self.assertEqual(value['profile']['certification_state'],'interactive-certified')
        self.assertEqual(value['proposal_authority']['required_certifications_before_candidate_admission'],['execution','interactive'])
        self.assertIs(value['proposal_authority']['unsigned'],True)
        self.assertIs(value['proposal_authority']['runtime_admitted'],False)
        self.assertIs(value['proposal_authority']['certifications_generated'],False)
        self.assertIs(value['proposal_authority']['production_certifications_require_actual_image_and_machine'],True)


if __name__ == '__main__':
    unittest.main()
