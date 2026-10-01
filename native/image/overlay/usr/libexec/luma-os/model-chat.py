#!/usr/bin/python3
"""Bounded local operator inference smoke; output never dispatches OS actions."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import sys
import time
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('local inference redirects are forbidden')


def local_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def bounded_integer(minimum, maximum):
    def parse(value):
        try:
            result = int(value)
        except ValueError as error:
            raise argparse.ArgumentTypeError('expected an integer') from error
        if not minimum <= result <= maximum:
            raise argparse.ArgumentTypeError(f'expected {minimum}..{maximum}')
        return result
    return parse


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--timeout-seconds', type=bounded_integer(1, 1800), default=180)
    parser.add_argument('--max-tokens', type=bounded_integer(1, 128), default=128)
    return parser.parse_args(argv)


@contextmanager
def whole_request_deadline(seconds):
    """Bound stdin, headers, body and parsing, not each socket read separately.

    This isolated Linux CLI owns its main thread and does not nest timers. A
    slow trickle from the local runtime must not extend the operation forever.
    """
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise RuntimeError('inference deadline cannot replace an active timer')
    def expired(signum, frame):
        raise TimeoutError('local inference whole-request deadline exceeded')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def inference(options):
    if os.geteuid()!=0:raise SystemExit('use the local administrator account with sudo')
    prompt=sys.stdin.buffer.read(8193)
    if not prompt or len(prompt)>8192:raise SystemExit('provide 1..8192 UTF-8 prompt bytes on stdin')
    selection=json.loads(Path('/var/lib/luma-os/model-selection.json').read_text())
    token=Path('/var/lib/luma-os/model-auth/api-key').read_text()
    body=json.dumps({'model':selection['id'],'messages':[{'role':'user','content':prompt.decode()+' /no_think'}],
                     'max_tokens':options.max_tokens,'temperature':0.7,'stream':False,
                     'chat_template_kwargs':{'enable_thinking':False},
                     'reasoning_effort':'none'}).encode()
    request=urllib.request.Request('http://127.0.0.1:8081/v1/chat/completions',data=body,
        headers={'Content-Type':'application/json','Authorization':'Bearer '+token},method='POST')
    # No ambient proxy, redirects, remote endpoint, credential printing or effects.
    with local_opener().open(request,timeout=options.timeout_seconds) as response:
        raw=response.read(2*1024*1024+1)
    if len(raw)>2*1024*1024:raise SystemExit('model response exceeds limit')
    result=json.loads(raw)
    text=result['choices'][0]['message']['content']
    if not isinstance(text,str) or not text.strip():raise SystemExit('model returned no text')
    return {'model':selection['id'],'text':text,'usage':result.get('usage'),
            'effects_executed':False,'certification_closing':False}


def main():
    options = arguments()
    started = time.monotonic()
    try:
        with whole_request_deadline(options.timeout_seconds):
            result = inference(options)
            result['elapsed_seconds'] = round(time.monotonic() - started, 6)
            result['timeout_seconds'] = options.timeout_seconds
            result['max_tokens'] = options.max_tokens
            print(json.dumps(result, ensure_ascii=False), flush=True)
    except (TimeoutError, urllib.error.URLError):
        # Do not print request headers, credentials, response bodies or a false
        # result. The caller observes nonzero; no retry or authority escalation.
        raise SystemExit('local inference transport failed or exceeded its deadline; manual operation remains available')


if __name__=='__main__':main()
