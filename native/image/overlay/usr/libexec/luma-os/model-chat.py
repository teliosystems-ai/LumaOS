#!/usr/bin/python3
"""Bounded local operator inference smoke; output never dispatches OS actions."""
import json
import os
from pathlib import Path
import sys
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('local inference redirects are forbidden')


def local_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def main():
    if os.geteuid()!=0:raise SystemExit('use the local administrator account with sudo')
    prompt=sys.stdin.buffer.read(8193)
    if not prompt or len(prompt)>8192:raise SystemExit('provide 1..8192 UTF-8 prompt bytes on stdin')
    selection=json.loads(Path('/var/lib/luma-os/model-selection.json').read_text())
    token=Path('/var/lib/luma-os/model-auth/api-key').read_text()
    body=json.dumps({'model':selection['id'],'messages':[{'role':'user','content':prompt.decode()+' /no_think'}],
                     'max_tokens':128,'temperature':0.7,'stream':False}).encode()
    request=urllib.request.Request('http://127.0.0.1:8081/v1/chat/completions',data=body,
        headers={'Content-Type':'application/json','Authorization':'Bearer '+token},method='POST')
    # No ambient proxy, redirects, remote endpoint, credential printing or effects.
    with local_opener().open(request,timeout=180) as response:
        raw=response.read(2*1024*1024+1)
    if len(raw)>2*1024*1024:raise SystemExit('model response exceeds limit')
    result=json.loads(raw)
    text=result['choices'][0]['message']['content']
    if not isinstance(text,str) or not text.strip():raise SystemExit('model returned no text')
    print(json.dumps({'model':selection['id'],'text':text,'usage':result.get('usage'),
                      'effects_executed':False,'certification_closing':False},ensure_ascii=False))


if __name__=='__main__':main()
