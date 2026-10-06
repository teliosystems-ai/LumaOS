#!/usr/bin/python3
"""Bounded local operator inference smoke; output never dispatches OS actions."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import struct
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


def strict_json(raw):
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
        if isinstance(raw, bytes):
            raw = raw.decode('utf-8')
        result = json.loads(raw, object_pairs_hook=unique_object, parse_constant=nonfinite)
        pending = [result]
        while pending:
            value = pending.pop()
            if isinstance(value, str):
                value.encode('utf-8')
            elif isinstance(value, dict):
                pending.extend(value.keys())
                pending.extend(value.values())
            elif isinstance(value, list):
                pending.extend(value)
        return result
    except (ValueError, UnicodeError, RecursionError):
        raise InferenceReplyError('invalid inference response encoding') from None


def completion(raw, model, max_tokens):
    result = strict_json(raw)
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


def boot_ms():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 1_000_000


def decimal(value):
    if (not isinstance(value, str) or not value or not value.isascii()
            or not value.isdigit() or (len(value) > 1 and value[0] == '0')
            or len(value) > 20 or int(value) > (1 << 64) - 1):
        raise InferenceReplyError('invalid lossless resource count')
    return int(value)


def worker_token(value):
    if not isinstance(value, dict) or set(value) != {'lease_id', 'generation', 'manager_epoch'}:
        raise InferenceReplyError('invalid serving generation')
    for field in ('lease_id', 'manager_epoch'):
        token = value[field]
        if not isinstance(token, str) or len(token) != 32 or any(c not in '0123456789abcdef' for c in token):
            raise InferenceReplyError('invalid serving identity')
    if decimal(value['generation']) == 0:
        raise InferenceReplyError('invalid serving generation')
    return value


def broker_exchange(payload):
    started = boot_ms()
    request_id = secrets.token_hex(16)
    request = {'schema_version': 1, 'request_id': request_id, 'caller': 0,
               'deadline': str(started + 4000), 'action': 'resource-inference', 'payload': payload}
    encoded = json.dumps(request, separators=(',', ':')).encode()
    if not 1 <= len(encoded) <= 16384:
        raise InferenceReplyError('resource envelope exceeds limit')
    # Independent finite cancellation budget remains usable after the request's
    # outer timer fires. A lost acknowledgement never releases a model allocation.
    until = started + 3000
    def remaining():
        left = until - boot_ms()
        if left <= 0:
            raise TimeoutError('resource exchange deadline exceeded')
        return left / 1000
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(remaining())
        peer.connect('/run/luma-broker/control.sock')
        credentials = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        _, uid, _ = struct.unpack('3i', credentials)
        if uid != 0:
            raise InferenceReplyError('resource peer is not the root broker')
        peer.settimeout(remaining())
        peer.sendall(struct.pack('!I', len(encoded)) + encoded)
        def exact(length):
            data = bytearray()
            while len(data) < length:
                peer.settimeout(remaining())
                block = peer.recv(length - len(data))
                if not block:
                    raise InferenceReplyError('truncated resource response')
                data.extend(block)
            remaining()
            return bytes(data)
        length = struct.unpack('!I', exact(4))[0]
        if not 1 <= length <= 16384:
            raise InferenceReplyError('resource response exceeds limit')
        response = strict_json(exact(length))
    if (not isinstance(response, dict)
            or set(response) != {'schema_version', 'request_id', 'caller', 'result', 'status'}
            or type(response['schema_version']) is not int or response['schema_version'] != 1
            or type(response['caller']) is not int or response['caller'] != 0
            or response['request_id'] != request_id or response['result'] != 'ok'
            or not isinstance(response['status'], dict)):
        raise InferenceReplyError('resource acknowledgement is denied or substituted')
    remaining()
    return response['status']


def permit(status, expected, phase, prompt_tokens=None, token_digest=None,
           output_tokens=None, result_digest=None):
    fields = {'kind', 'nonce', 'worker', 'phase', 'profile', 'max_output_tokens',
              'context_tokens', 'request_deadline', 'prompt_tokens', 'token_digest',
              'output_tokens', 'result_digest', 'slot_released', 'worker_resources_released'}
    if not isinstance(status, dict) or set(status) != fields:
        raise InferenceReplyError('invalid inference reservation response')
    worker_token(status['worker'])
    for field in ('nonce', 'worker', 'profile', 'max_output_tokens', 'context_tokens', 'request_deadline'):
        if status[field] != expected[field]:
            raise InferenceReplyError('inference reservation was substituted')
    if (status['kind'] != 'permit' or status['phase'] != phase
            or status['prompt_tokens'] != (None if prompt_tokens is None else str(prompt_tokens))
            or status['token_digest'] != token_digest
            or status['output_tokens'] != (None if output_tokens is None else str(output_tokens))
            or status['result_digest'] != result_digest
            or status['slot_released'] is not (phase == 'completed')
            or status['worker_resources_released'] is not False):
        raise InferenceReplyError('inference reservation phase or budget mismatch')
    return status


def runtime_post(opener, path, payload, token, timeout):
    if path not in ('/apply-template', '/tokenize', '/completion'):
        raise InferenceReplyError('unsupported local runtime method')
    encoded = json.dumps(payload, separators=(',', ':'), allow_nan=False).encode()
    if len(encoded) > 128 * 1024:
        raise InferenceReplyError('runtime input exceeds bound')
    request = urllib.request.Request('http://127.0.0.1:8081' + path, data=encoded,
        headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token}, method='POST')
    with opener.open(request, timeout=timeout) as response:
        if response.status != 200:
            raise InferenceReplyError('runtime request did not complete')
        raw = response.read(128 * 1024 + 1)
    if len(raw) > 128 * 1024:
        raise InferenceReplyError('runtime response exceeds bound')
    result = strict_json(raw)
    if not isinstance(result, dict):
        raise InferenceReplyError('invalid runtime object')
    return result


def native_completion(result, model, prompt_tokens, maximum):
    text = result.get('content')
    output = result.get('tokens_predicted')
    if (result.get('model') != model or result.get('stop') is not True
            or result.get('stop_type') not in ('eos', 'limit', 'word')
            or result.get('truncated') is not False
            or type(result.get('tokens_evaluated')) is not int
            or result['tokens_evaluated'] != prompt_tokens
            # b11100 tokens_cached is the final slot KV occupancy, not reused
            # prompt tokens. It remains inside the already reserved worker peak.
            or type(result.get('tokens_cached')) is not int
            or not 0 <= result['tokens_cached'] <= prompt_tokens + maximum
            or not isinstance(result.get('timings'), dict)
            or type(result['timings'].get('cache_n')) is not int or result['timings']['cache_n'] != 0
            or type(result['timings'].get('prompt_n')) is not int or result['timings']['prompt_n'] != prompt_tokens
            or type(result['timings'].get('predicted_n')) is not int or result['timings']['predicted_n'] != output
            or type(output) is not int or not 1 <= output <= maximum
            or not isinstance(text, str) or not text.strip()
            or len(text.encode()) > 64 * 1024):
        raise InferenceReplyError('runtime completion differs from accepted token budget')
    return text, {'prompt_tokens': prompt_tokens, 'completion_tokens': output,
                  'total_tokens': prompt_tokens + output}


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
    started = boot_ms()
    if os.geteuid()!=0:raise SystemExit('use the local administrator account with sudo')
    prompt=sys.stdin.buffer.read(8193)
    if not prompt or len(prompt)>8192:raise SystemExit('provide 1..8192 UTF-8 prompt bytes on stdin')
    try:
        prompt_text = prompt.decode('utf-8')
    except UnicodeError:
        raise InferenceReplyError('invalid UTF-8 prompt') from None
    with Path('/var/lib/luma-os/model-selection.json').open('rb') as selection_file:
        raw_selection = selection_file.read(16385)
    if len(raw_selection) > 16384:
        raise InferenceReplyError('selection exceeds bound')
    selection = strict_json(raw_selection)
    if (not isinstance(selection, dict) or not isinstance(selection.get('id'), str)
            or not 1 <= len(selection['id']) <= 128):
        raise InferenceReplyError('invalid selected model')
    with Path('/var/lib/luma-os/model-auth/api-key').open('rb') as key_file:
        raw_token = key_file.read(129)
    if len(raw_token) != 64 or any(c not in b'0123456789abcdefABCDEF' for c in raw_token):
        raise InferenceReplyError('invalid local runtime credential')
    token = raw_token.decode('ascii')
    info = broker_exchange({'operation': 'inspect'})
    if (set(info) != {'kind', 'worker', 'profile', 'context_tokens', 'max_output_tokens', 'slots'}
            or info['kind'] != 'worker' or info['profile'] != selection['id']
            or info['slots'] != '1' or decimal(info['max_output_tokens']) != 128
            or decimal(info['context_tokens']) != 2048):
        raise InferenceReplyError('selected runtime differs from broker inventory')
    worker = worker_token(info['worker'])
    nonce = secrets.token_hex(16)
    until = started + options.timeout_seconds * 1000
    expected = {'nonce': nonce, 'worker': worker, 'profile': selection['id'],
                'max_output_tokens': str(options.max_tokens), 'context_tokens': info['context_tokens'],
                'request_deadline': str(until)}
    finished = False
    try:
        # The preparing slot covers template/tokenization as well as inference.
        # A lost begin acknowledgement is cancelled by the preallocated nonce.
        permit(broker_exchange({'operation': 'begin', 'nonce': nonce, 'worker': worker,
               'profile': selection['id'], 'max_output_tokens': str(options.max_tokens),
               'request_deadline': str(until)}), expected, 'preparing')
        opener = local_opener()
        rendered = runtime_post(opener, '/apply-template',
            {'messages': [{'role': 'user', 'content': prompt_text + ' /no_think'}],
             'chat_template_kwargs': {'enable_thinking': False}}, token, options.timeout_seconds)
        if set(rendered) != {'prompt'} or not isinstance(rendered['prompt'], str) or not rendered['prompt']:
            raise InferenceReplyError('invalid rendered template')
        encoded = runtime_post(opener, '/tokenize', {'content': rendered['prompt'],
            'add_special': True, 'parse_special': True, 'with_pieces': False}, token, options.timeout_seconds)
        tokens = encoded.get('tokens')
        if (set(encoded) != {'tokens'} or not isinstance(tokens, list)
                or not 1 <= len(tokens) <= 2048
                or any(type(t) is not int or not 0 <= t <= 2147483647 for t in tokens)
                or len(tokens) + options.max_tokens > 2048):
            raise InferenceReplyError('rendered prompt and output exceed context or token contract')
        token_digest = hashlib.sha256(json.dumps(tokens, separators=(',', ':')).encode()).hexdigest()
        permit(broker_exchange({'operation': 'admit', 'nonce': nonce, 'worker': worker,
               'prompt_tokens': str(len(tokens)), 'token_digest': token_digest}), expected,
               'admitted', len(tokens), token_digest)
        # Pass the exact token array, not messages or a string that could be
        # templated/tokenized differently after admission. No cache or queue reuse.
        result = runtime_post(opener, '/completion', {'prompt': tokens, 'n_predict': options.max_tokens,
            'temperature': 0.7, 'stream': False, 'cache_prompt': False, 'n_cmpl': 1,
            'id_slot': 0, 'return_tokens': False}, token, options.timeout_seconds)
        text, usage = native_completion(result, selection['id'], len(tokens), options.max_tokens)
        result_digest = hashlib.sha256(json.dumps({'text': text, 'usage': usage},
            separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
        permit(broker_exchange({'operation': 'finish', 'nonce': nonce, 'worker': worker,
               'prompt_tokens': str(len(tokens)), 'output_tokens': str(usage['completion_tokens']),
               'result_digest': result_digest}), expected, 'completed', len(tokens), token_digest,
               usage['completion_tokens'], result_digest)
        finished = True
        return {'model': selection['id'], 'text': text, 'usage': usage,
                'effects_executed': False, 'certification_closing': False,
                'resource_worker': worker, 'resource_request': nonce}
    finally:
        if not finished:
            try:
                broker_exchange({'operation': 'cancel', 'nonce': nonce, 'worker': worker})
            except (OSError, ValueError, TimeoutError):
                # Owner death/request expiry still fences in the broker. A failed
                # cancellation acknowledgement is never called cleanup complete.
                pass


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
    except (OSError, TimeoutError, urllib.error.URLError):
        # Do not print request headers, credentials, response bodies or a false
        # result. The caller observes nonzero; no retry or authority escalation.
        raise SystemExit('local inference transport failed or exceeded its deadline; manual operation remains available')
    except InferenceReplyError:
        raise SystemExit('local inference response failed validation; manual operation remains available') from None


if __name__=='__main__':main()
