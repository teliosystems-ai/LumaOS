"""Local inference credentials must never follow a server-directed redirect."""
import importlib.util
from pathlib import Path
import unittest
import urllib.request

SCRIPT=Path(__file__).resolve().parents[1]/'image/overlay/usr/libexec/luma-os/model-chat.py'
spec=importlib.util.spec_from_file_location('model_chat',SCRIPT)
chat=importlib.util.module_from_spec(spec);spec.loader.exec_module(chat)


class ModelChatTransportTests(unittest.TestCase):
    def test_every_redirect_target_is_refused(self):
        req=urllib.request.Request('http://127.0.0.1:8081/v1/chat/completions',
            headers={'Authorization':'Bearer public-test-fixture'},data=b'{}')
        for target in ('https://example.invalid', 'http://127.0.0.1:9999', '/other'):
            for code in (301,302,303,307,308):
                with self.subTest(target=target,code=code), self.assertRaises(ValueError):
                    chat.NoRedirect().redirect_request(req,None,code,'redirect',{},target)

    def test_opener_does_not_install_default_redirect_handler(self):
        handlers=chat.local_opener().handlers
        redirects=[h for h in handlers if isinstance(h,urllib.request.HTTPRedirectHandler)]
        self.assertEqual(len(redirects),1)
        self.assertIsInstance(redirects[0],chat.NoRedirect)
        for handler in handlers:
            if isinstance(handler,urllib.request.ProxyHandler):
                self.assertEqual(handler.proxies,{})


if __name__=='__main__':unittest.main()
