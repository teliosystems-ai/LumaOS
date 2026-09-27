"""Tests for runtime acquisition boundaries, independent of model evaluation."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import urllib.request

IMAGE=Path(__file__).resolve().parents[1]/'image'
spec=importlib.util.spec_from_file_location('prepare_runtime',IMAGE/'prepare_runtime.py')
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)


class RuntimeInputTests(unittest.TestCase):
    def run_prepare(self,output,cache):
        return subprocess.run([sys.executable,str(IMAGE/'prepare_runtime.py'),'--output',str(output),
            '--cached',str(cache)],capture_output=True,text=True,timeout=30)

    def test_wrong_cached_bytes_never_produce_a_runtime(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);cache=root/'cache';cache.write_bytes(b'not a runtime')
            result=self.run_prepare(root/'input',cache)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse((root/'input/llama-runtime.tar.gz').exists())
            self.assertEqual(cache.read_bytes(),b'not a runtime')

    def test_existing_context_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'llama-runtime.tar.gz').write_bytes(b'preserve')
            result=self.run_prepare(root,root/'missing')
            self.assertNotEqual(result.returncode,0)
            self.assertEqual((root/'llama-runtime.tar.gz').read_bytes(),b'preserve')

    def test_https_downgrade_is_refused(self):
        request=urllib.request.Request('https://github.com/example')
        with self.assertRaises(ValueError):
            runtime.HTTPSRedirect().redirect_request(request,None,302,'Found',{},'http://example.com/runtime')

    def test_model_catalog_has_immutable_identity_and_multiple_tiers(self):
        c=json.loads((IMAGE/'model-catalog.json').read_text())
        self.assertEqual(c['environment'],'lab')
        self.assertEqual({p['parameters'] for p in c['models']},{1_700_000_000,4_000_000_000})
        for p in c['models']:
            self.assertRegex(p['url'],r'^https://huggingface.co/Qwen/[^/]+/resolve/[0-9a-f]{40}/[^/]+\.gguf$')
            self.assertRegex(p['sha256'],r'^[0-9a-f]{64}$')
            self.assertGreater(p['minimum_ram_bytes'],p['memory_max_bytes'])
            self.assertGreater(p['minimum_available_bytes'],p['bytes'])


if __name__=='__main__':unittest.main()
