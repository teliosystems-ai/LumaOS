"""Inference fixture oracles; these tests do not execute a model."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'image'))
from model_vm_test import MODEL, inference_result


class ModelResultTests(unittest.TestCase):
    def setUp(self):
        self.result = {'model': MODEL, 'text': 'Hello',
                       'usage': {'completion_tokens': 2},
                       'effects_executed': False, 'certification_closing': False}

    def encode(self):
        return json.dumps(self.result).encode()+b'\r\n'

    def test_fresh_result_with_real_positive_token_count(self):
        self.assertEqual(inference_result(b'console command\r\n'+self.encode(), MODEL), self.result)

    def test_missing_or_duplicate_current_result_never_reuses_old_success(self):
        inference_result(self.encode(), MODEL)
        for output in (b'', b'healthy\r\n', self.encode()*2):
            with self.assertRaises(RuntimeError):
                inference_result(output, MODEL)

    def test_wrong_model_empty_text_and_authority_claims_refused(self):
        for field, value in (('model', 'other-model'), ('text', ''), ('text', None),
                             ('effects_executed', True), ('effects_executed', 0),
                             ('certification_closing', True)):
            original = self.result[field]
            with self.subTest(field=field, value=value), self.assertRaises(RuntimeError):
                self.result[field] = value
                inference_result(self.encode(), MODEL)
            self.result[field] = original

    def test_usage_requires_integer_completion_count(self):
        for value in (None, {}, {'completion_tokens': 0}, {'completion_tokens': -1},
                      {'completion_tokens': True}, {'completion_tokens': 1.5}):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                self.result['usage'] = value
                inference_result(self.encode(), MODEL)


if __name__ == '__main__':
    unittest.main()
