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


class InferenceReplyError(ValueError):
    """Untrusted runtime output must not become a successful smoke result."""


def completion(raw, model, max_tokens):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise InferenceReplyError('duplicate inference response field')
            result[key] = value
        return result

    def nonfinite(value):
        raise InferenceReplyError('nonfinite inference response value')

    try:
        result = json.loads(raw, object_pairs_hook=unique_object, parse_constant=nonfinite)
    except (ValueError, UnicodeError, RecursionError):
        raise InferenceReplyError('invalid inference response encoding') from None
    if (not isinstance(result, dict) or result.get('model') != model
            or result.get('object') != 'chat.completion'):
        raise InferenceReplyError('inference response identity mismatch')
    choices = result.get('choices')
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        raise InferenceReplyError('expected one inference completion')
    choice = choices[0]
    message = choice.get('message')
    if (type(choice.get('index')) is not int or choice['index'] != 0
            or choice.get('finish_reason') not in ('stop', 'length')
            or not isinstance(message, dict) or message.get('role') != 'assistant'
            or message.get('tool_calls') not in (None, [])
            or message.get('function_call') is not None
            or message.get('refusal') is not None):
        raise InferenceReplyError('unsupported inference completion')
    text = message.get('content')
    if not isinstance(text, str) or not text.strip():
        raise InferenceReplyError('model returned no text')
    usage = result.get('usage')
    keys = ('prompt_tokens', 'completion_tokens', 'total_tokens')
    if not isinstance(usage, dict) or any(type(usage.get(key)) is not int for key in keys):
        raise InferenceReplyError('missing or invalid inference usage')
    if (usage['prompt_tokens'] < 1 or not 1 <= usage['completion_tokens'] <= max_tokens
            or usage['total_tokens'] != usage['prompt_tokens'] + usage['completion_tokens']):
        raise InferenceReplyError('inference token budget or accounting mismatch')
    # Do not relay arbitrary runtime metadata as trusted usage/evidence. Model
    # text remains untrusted text and is never interpreted as an OS operation.
    return text, {key: usage[key] for key in keys}


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
    text, usage = completion(raw, selection['id'], options.max_tokens)
    return {'model':selection['id'],'text':text,'usage':usage,
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
    except InferenceReplyError:
        raise SystemExit('local inference response failed validation; manual operation remains available') from None


if __name__=='__main__':main()
