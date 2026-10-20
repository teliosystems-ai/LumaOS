"""Unprivileged terminal bridge to the existing native PAM/grant ceremony.

No password, private result, grant issuance or content authority enters WebKit.
Launching a terminal is not a successful authentication/publication receipt.
The terminal child owns a tiny inert staging file until its native command exits;
no GNOME Console early-return/DBus handoff is mistaken for command completion.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import hashlib
import importlib.util
import itertools
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
import types
import uuid

MAX_REQUEST = 16 * 1024 * 1024 + 32768
MAX_STAGE = MAX_REQUEST * 6 + 16384
HELPER = '/usr/libexec/luma-os/workspace_auth.py'
NATIVE = '/usr/libexec/luma-os/luma-platform'
PAGE_BYTES = 16384
MAX_ENVELOPE = 6 * 1024 * 1024 + 8192
MAX_QUERY_OUTPUT = 65536
MAX_ENVELOPE_OUTPUT = 2*MAX_ENVELOPE + 16384
MAX_RECOVERY_REQUEST = 96*1024
MAX_RECOVERY_OUTPUT = 96*1024
MAX_DISCOVERY_REQUEST = 65536
MAX_CONVERSATION_REQUEST = 16384
ENGINES = ('spreadsheet', 'document', 'diagram', 'animation')


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')


def same_data(left, right):
    tree = lambda value: json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
    return tree(left) == tree(right)


def strict_json(value):
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError('duplicate bridge field')
            result[key] = item
        return result
    return json.loads(value, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite bridge JSON')))


def proposal(value):
    fields = {'schema_version', 'operation', 'login', 'read_grant', 'effect_grant', 'approval', 'request'}
    if isinstance(value, dict) and value.get('operation') == 'office-export':
        fields.add('output_path')
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('closed terminal bridge fields required')
    if type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise ValueError('invalid terminal bridge version')
    if not isinstance(value['login'], str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', value['login']):
        raise ValueError('invalid native human login')
    for field in ('read_grant', 'effect_grant'):
        if not isinstance(value[field], str) or (value[field] and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value[field])):
            raise ValueError('invalid finite grant identifier')
    if not isinstance(value['approval'], str):
        raise ValueError('explicit approval text or an empty string required')
    operation = value['operation']
    if operation in ('inspection', 'office-proposal', 'paged-read', 'envelope-read', 'search-journey', 'conversation-journey', 'workflow-journey', 'collection-journey', 'speech-journey', 'capture-reference-journey', 'restore-journey', 'retire-journey', 'lifecycle-journey', 'editor-journey'):
        if any(value[field] for field in ('read_grant', 'effect_grant', 'approval')):
            raise ValueError('inspection cannot select effect authority')
    elif operation == 'review':
        if not value['read_grant'] or value['effect_grant'] or value['approval']:
            raise ValueError('review requires only its exact finite Read grant')
    elif operation == 'office-export':
        if not value['read_grant'] or not value['effect_grant'] or value['read_grant'] == value['effect_grant'] or value['approval']:
            raise ValueError('Office requires only exact independent Read and Export grants')
        path = value['output_path']
        if not isinstance(path, str) or not Path(path).is_absolute() or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,123}\.pdf', Path(path).name):
            raise ValueError('Office export requires an explicit new bounded PDF filename')
    elif operation == 'apply':
        if not value['read_grant'] or not value['effect_grant'] or not isinstance(value['approval'], str) or not re.fullmatch(r'(?:write|retain|recover|trash|untrash):[0-9a-f]{64}', value['approval']):
            raise ValueError('apply requires exact Read/effect grants and reviewed approval')
    else:
        raise ValueError('unsupported authenticated terminal operation')
    request = value['request']
    bound = (MAX_RECOVERY_REQUEST if operation in ('restore-journey', 'retire-journey')
             else MAX_DISCOVERY_REQUEST if operation == 'search-journey'
             else MAX_CONVERSATION_REQUEST if operation == 'conversation-journey' else MAX_REQUEST)
    if not isinstance(request, str) or not 0 < len(request.encode('utf-8')) <= bound:
        raise ValueError('native request exceeds bound')
    source = strict_json(request)
    identity = source.get('input') if isinstance(source, dict) and operation == 'retire-journey' else source
    if not isinstance(identity, dict) or identity.get('login') != value['login']:
        raise ValueError('request and original human login differ')
    if operation == 'paged-read':
        page_request(source)
    elif operation == 'envelope-read':
        envelope_request(source)
    elif operation == 'search-journey':
        discovery_request(source)
    elif operation == 'conversation-journey':
        conversation_request(source)
    elif operation == 'workflow-journey':
        workflow_request(source)
    elif operation == 'collection-journey':
        workspace_controller('collections').request(types.SimpleNamespace(**globals()), source)
    elif operation == 'speech-journey':
        workspace_controller('speech').transcription_request(source)
    elif operation == 'capture-reference-journey':
        workspace_controller('grounding').request(source)
    elif operation == 'lifecycle-journey':
        workspace_controller('lifecycle').request(types.SimpleNamespace(**globals()), source)
    elif operation == 'editor-journey':
        workspace_controller('editor').request(types.SimpleNamespace(**globals()), source)
    elif operation in ('restore-journey', 'retire-journey'):
        recovery_request(source, retirement=operation == 'retire-journey')
    return value


def owner_request(source):
    """Validate descriptive identity syntax without establishing an account."""
    if not isinstance(source, dict) or set(source) != {'schema_version', 'login', 'binding', 'operation'} or type(source['schema_version']) is not int or source['schema_version'] != 1:
        raise ValueError('exact native page request required')
    if not isinstance(source['login'], str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', source['login']):
        raise ValueError('explicit native human login required')
    binding = source['binding']
    if not isinstance(binding, dict) or set(binding) != {'installation', 'owner', 'owner_generation'}:
        raise ValueError('exact owner generation required')
    if any(not isinstance(binding[key], str) or not re.fullmatch(r'[0-9a-f]{64}', binding[key]) or binding[key] == '0'*64 for key in ('installation', 'owner')) or type(binding['owner_generation']) is not int or not 1 <= binding['owner_generation'] <= 2**64-1:
        raise ValueError('invalid owner binding')
    return source


def conversation_messages(messages):
    """Keep the existing native gateway bounds, without inventing history."""
    if not isinstance(messages, list) or not 1 <= len(messages) <= 15 or len(messages) % 2 != 1:
        raise ValueError('one to fifteen alternating messages ending with this human are required')
    total = 0
    for index, message in enumerate(messages):
        if not isinstance(message, dict) or set(message) != {'role', 'content'} or message['role'] != ('user' if index % 2 == 0 else 'assistant') or not isinstance(message['content'], str) or not message['content'].strip():
            raise ValueError('only explicit human text and observed model replies form conversation history')
        total += len(message['content'].encode('utf-8'))
    if total > 8192 or len(encoded(messages)) > 16384:
        raise ValueError('conversation exceeds native 8192-byte content / 16384-byte encoded input bounds; explicitly start afresh')
    return messages


def conversation_request(source):
    """An initial human prompt only, not a grant, model choice or receipt."""
    if not isinstance(source, dict) or set(source) != {'schema_version', 'login', 'messages', 'max_tokens'} or type(source['schema_version']) is not int or source['schema_version'] != 1:
        raise ValueError('closed initial conversation data required')
    if not isinstance(source['login'], str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', source['login']):
        raise ValueError('explicit native human login required')
    conversation_messages(source['messages'])
    if len(source['messages']) != 1 or len(source['messages'][0]['content'].encode('utf-8')) > 4096:
        raise ValueError('begin with one explicit human prompt, at most 4096 bytes; no imported assistant history')
    if type(source['max_tokens']) is not int or not 1 <= source['max_tokens'] <= 128:
        raise ValueError('native response limit must be one to 128 tokens')
    return source


def conversation_digest(messages):
    conversation_messages(messages)
    canonical = [dict(role=message['role'], content=message['content']) for message in messages]
    return hashlib.sha256(b'luma-native-gateway-messages-v1\0'+encoded(canonical)).hexdigest()


def conversation_decimal(value, maximum=2**64-1):
    if not isinstance(value, str) or not re.fullmatch(r'[1-9][0-9]{0,19}', value) or int(value) > maximum:
        raise ValueError('canonical positive native resource count required')
    return int(value)


def conversation_worker(value):
    if not isinstance(value, dict) or set(value) != {'lease_id', 'generation', 'manager_epoch'}:
        raise ValueError('exact current native worker generation required')
    if any(not isinstance(value[key], str) or not re.fullmatch(r'[0-9a-f]{32}', value[key]) for key in ('lease_id', 'manager_epoch')):
        raise ValueError('invalid native worker identity')
    conversation_decimal(value['generation'])
    return value


def conversation_review(messages, maximum, output):
    """Check the live native review pipe, never import an asserted grant."""
    if type(maximum) is not int or not 1 <= maximum <= 128:
        raise ValueError('explicit native token bound required')
    if not isinstance(output, bytes) or not 0 < len(output) < MAX_QUERY_OUTPUT:
        raise ValueError('native inference review exceeds its observation bound')
    value = strict_json(output)
    if not isinstance(value, dict) or set(value) != {'schema_version', 'usage', 'worker', 'input_sha256', 'authority_returned', 'gate_closing'} or type(value['schema_version']) is not int or value['schema_version'] != 1 or value['authority_returned'] is not False or value['gate_closing'] is not False or value['input_sha256'] != conversation_digest(messages):
        raise ValueError('native inference review substitutes input or claims authority')
    worker = conversation_worker(value['worker'])
    usage = value['usage']
    if not isinstance(usage, dict) or set(usage) != {'action', 'selector', 'input_bytes', 'output_bytes', 'units'} or usage['action'] != 'inference.execute' or type(usage['input_bytes']) is not int or usage['input_bytes'] != sum(len(item['content'].encode('utf-8')) for item in messages) or type(usage['output_bytes']) is not int or usage['output_bytes'] != 8192 or type(usage['units']) is not int or usage['units'] != maximum:
        raise ValueError('native inference scope changes its finite byte/token allowance')
    selector = usage['selector']
    if not isinstance(selector, dict) or set(selector) != {'kind', 'id', 'generation', 'digest'} or selector['kind'] != 'model' or not isinstance(selector['id'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', selector['id']) or type(selector['generation']) is not int or selector['generation'] != int(worker['generation']) or not exact_sha(selector['digest']):
        raise ValueError('native inference scope substitutes the current model or worker generation')
    return value


def conversation_result(review, grant, output):
    """Join an observed native result to this exact reviewed turn, not authority."""
    if not isinstance(output, bytes) or not 0 < len(output) < MAX_QUERY_OUTPUT:
        raise ValueError('native inference result exceeds its observation bound')
    value = strict_json(output)
    if not isinstance(value, dict) or set(value) != {'schema_version', 'result', 'output', 'receipt', 'gate_closing'} or type(value['schema_version']) is not int or value['schema_version'] != 1 or value['result'] != 'ok' or value['gate_closing'] is not False:
        raise ValueError('no exact native inference completion was observed')
    result, receipt = value['output'], value['receipt']
    if not isinstance(result, dict) or set(result) != {'text', 'prompt_tokens', 'output_tokens'} or not isinstance(result['text'], str) or not result['text'].strip() or len(result['text'].encode('utf-8')) > 8192:
        raise ValueError('native completion text is absent or exceeds its finite allowance')
    conversation_decimal(result['prompt_tokens'], 2048)
    conversation_decimal(result['output_tokens'], review['usage']['units'])
    fields = {'kind', 'nonce', 'worker', 'phase', 'profile', 'input_digest', 'max_output_tokens', 'context_tokens', 'request_deadline', 'prompt_tokens', 'token_digest', 'output_tokens', 'result_digest', 'slot_released', 'worker_resources_released', 'product'}
    if not isinstance(receipt, dict) or set(receipt) != fields or receipt['kind'] != 'permit' or receipt['phase'] != 'completed' or not isinstance(receipt['nonce'], str) or not re.fullmatch(r'[0-9a-f]{32}', receipt['nonce']) or not same_data(receipt['worker'], review['worker']) or receipt['profile'] != review['usage']['selector']['id'] or receipt['input_digest'] != review['input_sha256'] or receipt['max_output_tokens'] != str(review['usage']['units']) or receipt['context_tokens'] != '2048' or receipt['prompt_tokens'] != result['prompt_tokens'] or receipt['output_tokens'] != result['output_tokens'] or not exact_sha(receipt['token_digest']) or receipt['slot_released'] is not True or receipt['worker_resources_released'] is not False:
        raise ValueError('native completion receipt changes its input, worker, token allowance or release status')
    conversation_decimal(receipt['request_deadline'])
    digest = hashlib.sha256(b'luma-native-gateway-result-v1\0'+encoded(dict(text=result['text'], prompt_tokens=result['prompt_tokens'], output_tokens=result['output_tokens']))).hexdigest()
    if receipt['result_digest'] != digest:
        raise ValueError('native completion digest differs from delivered text/accounting')
    audit = receipt['product']
    if not isinstance(audit, dict) or set(audit) not in ({'subject', 'subject_generation', 'grant_id', 'grant_version', 'checkpoint_head', 'usage'}, {'subject', 'subject_generation', 'grant_id', 'grant_version', 'checkpoint_head', 'operation_id', 'usage'}) or not exact_sha(audit['subject']) or not exact_sha(audit['checkpoint_head']) or type(audit['subject_generation']) is not int or not 1 <= audit['subject_generation'] <= 2**64-1 or audit['grant_id'] != grant or type(audit['grant_version']) is not int or audit['grant_version'] != 1 or not same_data(audit['usage'], review['usage']) or ('operation_id' in audit and (not isinstance(audit['operation_id'], str) or not re.fullmatch(r'[0-9a-f]{32}', audit['operation_id']))):
        raise ValueError('native completion does not attribute this exact finite inference use')
    return result


def conversation_commitment(login, review):
    """Reproducible review DATA; native rechecks the tuple BEFORE dispatch."""
    if not isinstance(login, str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', login):
        raise ValueError('exact original human login required')
    value = dict(purpose='luma-native-reviewed-inference-v1', login=login,
        worker=review['worker'], usage=review['usage'], input_sha256=review['input_sha256'])
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')).hexdigest()


def conversation_capture(command, path, maximum, login=None, grant=None, review_sha256=None):
    """Closed genuine native inference endpoint, with PAM on the actual tty."""
    if type(maximum) is not int or not 1 <= maximum <= 128:
        raise ValueError('explicit native token bound required')
    arguments = ['/usr/bin/sudo', '--', NATIVE, 'granted-run']
    if command == 'review' and login is None and grant is None and review_sha256 is None:
        arguments += ['granted-infer-review', str(path), str(maximum)]
    elif command == 'infer' and isinstance(login, str) and re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', login) and isinstance(grant, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', grant) and exact_sha(review_sha256):
        arguments += ['granted-infer-reviewed', login, grant, str(path), str(maximum), review_sha256]
    else:
        raise ValueError('only exact native review/infer invocations are supported')
    protected(NATIVE, 128*1024*1024)
    return _capture_native(arguments, MAX_QUERY_OUTPUT)


def workspace_controller(name):
    if name not in ('draft', 'collections', 'speech', 'grounding', 'lifecycle', 'editor'):
        raise ValueError('fixed protected workspace controller required')
    path = Path('/usr/libexec/luma-os/workspace_'+name+'.py')
    protected(path, 128*1024)
    spec = importlib.util.spec_from_file_location('luma_terminal_'+name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def draft_controller():
    return workspace_controller('draft')


def conversation_manual_workflow(login, directory):
    """Human-authored handoff to the existing independently granted workflow."""
    return draft_controller().manual_workflow(types.SimpleNamespace(**globals()), login, directory)


def conversation_journey(value, directory):
    """Transient real conversation: fresh finite admission per turn, no effects."""
    proposal(value)
    if value['operation'] != 'conversation-journey':
        raise ValueError('explicit native conversation journey required')
    source = conversation_request(strict_json(value['request']))
    messages = source['messages']
    print('Native local conversation. Each turn obtains fresh original PAM and exact finite inference admission; native request deadline remains 25 seconds, not the separate Windows five-minute purpose. Text is untrusted DATA, not an OS instruction or a grounded citation. No content is attached automatically and no tool/effect is dispatched. History stays only in this terminal and bounded private /run staging; no durable history or grant is created. q stops before submission; Ctrl+C stops observation. Model unavailability never falls back to an ungoverned smoke endpoint.', flush=True)
    for round_number in range(8):
        submitted = False
        observed = False
        result = None
        try:
            conversation_messages(messages)
            print('Exact proposed conversation input (escaped DATA):\n'+json.dumps(messages, ensure_ascii=True, indent=2), flush=True)
            with request_stage(directory, encoded(messages).decode('utf-8')) as path:
                print('Checking the actual admitted local model and exact inference scope…', flush=True)
                review = conversation_review(messages, source['max_tokens'], conversation_capture('review', path, source['max_tokens']))
                commitment = conversation_commitment(source['login'], review)
                print('Actual native scope and input digest (DATA, not an issued grant):\n'+json.dumps(review, ensure_ascii=True, indent=2), flush=True)
                print('Exact login/model/worker/input/token review commitment (DATA; native rechecks before submission): '+commitment, flush=True)
                grant = grant_selection('Fresh finite inference grant ID for this exact turn, or q to stop: ')
                if grant is None:
                    print('CANCELLED before inference submission. No inference/effect requested by this turn.', flush=True)
                    return 0
                if terminal_line('Type infer:'+commitment+' to submit exactly this reviewed turn, or q to stop: ', 128) != 'infer:'+commitment:
                    print('CANCELLED before inference submission; exact prompt approval was not given.', flush=True)
                    return 0
                print('Running genuine native inference. Original PAM, current generation, grant/resource checks and revocation remain native. Ctrl+C interrupts observation; no terminal escape in model text is executed.', flush=True)
                submitted = True
                result = conversation_result(review, grant, conversation_capture('infer', path, source['max_tokens'], source['login'], grant, commitment))
                observed = True
            submitted = False
            print('OBSERVED actual native inference completion. Untrusted model text, escaped as DATA:\n'+json.dumps(result['text'], ensure_ascii=True), flush=True)
            print('This already-delivered text is not continuing permission, a workflow proposal, verified source, citation or production qualification.', flush=True)
            messages = messages + [dict(role='assistant', content=result['text'])]
        except (KeyboardInterrupt, EOFError):
            print('Actual native completion was validated before presentation stopped; it is not cancellation or rollback. No subsequent inference/effect was requested.' if observed else 'UNCERTAIN: submitted inference may have run; no complete validated delivery was observed. Native retains cancellation/drain obligations. No automatic retry, slot release or OS effect is inferred.' if submitted else 'Conversation stopped before inference submission. Previously delivered replies, if any, remain already observed.', file=sys.stderr, flush=True)
            return 130
        except Exception:
            print('Actual native completion was validated before presentation failed. Do not infer cancellation, rollback or a need to repeat this turn.' if observed else 'UNCERTAIN: inference was submitted but its exact result was not observed. Native effect/resource evidence must be inspected before retry; no automatic retry, success or release is claimed.' if submitted else 'Model unavailable or exact input/review refused. No inference submitted in this round. Use the independent manual workflow/read/discovery controls; no ungoverned fallback is attempted.', file=sys.stderr, flush=True)
            if submitted or observed:
                return 1
            messages = []
        try:
            if round_number == 7:
                print('Conversation reached its fixed eight-turn limit. No further inference is offered; the last observed reply may still be explicitly selected as draft DATA.', flush=True)
            choice = terminal_line(('Final turn: d document draft; k exact collection editor; w manual workflow; m manual help; q finish: ' if round_number == 7 else 'Type n follow-up; c CLEAR/new prompt; d document draft; k exact collection editor; w manual workflow; m manual help; q finish: '), 8)
            if choice == 'q':
                return 0
            if choice == 'm':
                print('Manual controls remain available in the native workspace: exact owner Read, semantic discovery, managed engine workflow, authenticated native owner operation and Admin encrypted recovery. These are separate reviewed/granted journeys; model text is never forwarded or applied automatically. Close this terminal with q, then choose the required native control.', flush=True)
                return 0
            if choice == 'w':
                return conversation_manual_workflow(source['login'], directory)
            if choice == 'd':
                if result is None:
                    raise ValueError('an editable draft requires a complete validated observed reply')
                return draft_controller().reply_draft(types.SimpleNamespace(**globals()), source['login'], result['text'], directory)
            if choice == 'k':
                return workspace_controller('collections').editor(types.SimpleNamespace(**globals()), source['login'],
                    result['text'] if result is not None else None, directory)
            if round_number == 7:
                raise ValueError('eight-turn inference bound reached; only explicit draft/manual/finish actions remain')
            if choice not in ('n', 'c') or (choice == 'n' and not messages):
                raise ValueError('a follow-up requires an observed native reply; choose explicit new input otherwise')
            prompt = terminal_line('Explicit human prompt (one line, at most 4096 UTF-8 bytes; q cancels): ', 4096)
            if prompt == 'q':
                return 0
            messages = ([] if choice == 'c' else messages) + [dict(role='user', content=prompt)]
            conversation_messages(messages)
        except (KeyboardInterrupt, EOFError):
            print('Conversation input stopped. No additional inference or OS effect was requested.', flush=True)
            return 130
        except Exception:
            print('Conversation input refused; no additional inference/effect requested. Start a new explicit conversation to reset history or limits.', file=sys.stderr, flush=True)
            return 1
    print('Conversation reached its fixed eight-turn limit. No history or grant was retained; start a new explicit journey for further requests.', flush=True)
    return 0


def reference_data(reference):
    if not isinstance(reference, dict) or set(reference) != {'artifact_id', 'version', 'content_sha256', 'receipt_sha256'} or not isinstance(reference['artifact_id'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', reference['artifact_id']) or type(reference['version']) is not int or not 1 <= reference['version'] <= 2**64-1:
        raise ValueError('exact grounded immutable reference required')
    if any(not isinstance(reference[key], str) or not re.fullmatch(r'[0-9a-f]{64}', reference[key]) or reference[key] == '0'*64 for key in ('content_sha256', 'receipt_sha256')):
        raise ValueError('immutable reference requires exact content and receipt digests')
    return reference


def page_request(source):
    """Closed data selector only; current owner/grant checks remain native."""
    owner_request(source)
    operation = source['operation']
    if not isinstance(operation, dict) or set(operation) != {'kind', 'expected', 'offset', 'bytes'} or operation['kind'] != 'page' or type(operation['offset']) is not int or operation['offset'] != 0 or type(operation['bytes']) is not int or operation['bytes'] != PAGE_BYTES:
        raise ValueError('paged journey starts at zero with the fixed 16-KiB page bound')
    reference_data(operation['expected'])
    return source


def envelope_request(source):
    owner_request(source)
    operation = source['operation']
    if not isinstance(operation, dict) or set(operation) != {'kind', 'expected'} or operation['kind'] != 'envelope':
        raise ValueError('exact complete-envelope selector required')
    reference_data(operation['expected'])
    return source


def discovery_query(query):
    """Match the native public term grammar; this does not search anything."""
    if not isinstance(query, str) or not query.isascii() or len(query) > 256:
        raise ValueError('discovery requires at most 256 ASCII query bytes')
    terms = re.findall(r'[^ \t\r\n\f]+', query)
    if not 1 <= len(terms) <= 8 or any(not re.fullmatch(r'[A-Za-z0-9]{1,64}', term) for term in terms):
        raise ValueError('discovery requires one to eight bounded alphanumeric terms')
    return ' '.join(sorted(set(term.lower() for term in terms)))


def discovery_request(source):
    """Exact owner-local selections; membership and similarity grant nothing."""
    owner_request(source)
    operation = source['operation']
    if not isinstance(operation, dict):
        raise ValueError('closed native semantic operation required')
    kind = operation.get('kind')
    selector = 'references' if kind == 'search-semantic-selected' else 'expected' if kind == 'collection-search-semantic' else None
    if selector is None or set(operation) != {'kind', selector, 'query', 'limit', 'dimensions'}:
        raise ValueError('select exact versions or one genuine typed collection')
    discovery_query(operation['query'])
    if type(operation['limit']) is not int or not 1 <= operation['limit'] <= 32 or type(operation['dimensions']) is not int or not 1 <= operation['dimensions'] <= 8:
        raise ValueError('native semantic result or dimension bound exceeded')
    if selector == 'expected':
        reference_data(operation['expected'])
    else:
        references = operation['references']
        if not isinstance(references, list) or not 1 <= len(references) <= 64:
            raise ValueError('select one to 64 exact versions')
        previous = None
        for reference in references:
            reference_data(reference)
            identifier = reference['artifact_id']
            if previous is not None and previous >= identifier:
                raise ValueError('selected versions require unique sorted artifact IDs')
            previous = identifier
    return source


def workflow_request(source):
    owner_request(source)
    operation = source['operation']
    if not isinstance(operation, dict) or set(operation) != {'kind', 'request'} or operation['kind'] != 'workflow':
        raise ValueError('only the fixed image managed workflow is supported')
    value = operation['request']
    if not isinstance(value, dict) or set(value) != {'schema_version', 'request_id', 'artifact_id', 'expected', 'engine', 'source'} or type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise ValueError('closed managed workflow request required')
    for field in ('request_id', 'artifact_id'):
        if not isinstance(value[field], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value[field]):
            raise ValueError('explicit bounded artifact and stable request identifiers required')
    if value['expected'] is not None:
        reference_data(value['expected'])
        if value['expected']['artifact_id'] != value['artifact_id']:
            raise ValueError('managed workflow base belongs to another artifact')
    if value['engine'] not in ENGINES or not isinstance(value['source'], str) or not 0 < len(value['source'].encode('utf-8')) <= 1024*1024:
        raise ValueError('bounded deterministic engine source required')
    if not isinstance(strict_json(value['source']), dict):
        raise ValueError('engine source must be a closed native JSON object')
    return source


def exact_sha(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None and value != '0'*64


def checked_envelope(data, source, commitment):
    """Self-consistent selected DATA, never fresh ownership or permission."""
    if len(data) != commitment[0] or hashlib.sha256(data).hexdigest() != commitment[1]:
        raise ValueError('assembled whole-envelope digest differs')
    envelope = strict_json(data)
    if not isinstance(envelope, dict) or set(envelope) != {'receipt', 'receipt_sha256', 'content'} or not isinstance(envelope['receipt'], dict):
        raise ValueError('complete envelope schema differs')
    receipt, reference = envelope['receipt'], source['operation']['expected']
    if not same_data(receipt.get('binding'), source['binding']) or receipt.get('artifact_id') != reference['artifact_id'] or type(receipt.get('version')) is not int or receipt['version'] != reference['version'] or receipt.get('content_sha256') != reference['content_sha256'] or envelope['receipt_sha256'] != reference['receipt_sha256'] or receipt.get('format') != commitment[2]:
        raise ValueError('whole-envelope owner/reference differs from the selected generation')
    content = envelope['content']
    if not isinstance(content, str) or len(content.encode('utf-8')) > 1024*1024 or type(receipt.get('content_bytes')) is not int or receipt['content_bytes'] != len(content.encode('utf-8')) or hashlib.sha256(content.encode('utf-8')).hexdigest() != reference['content_sha256'] or hashlib.sha256(encoded(receipt)).hexdigest() != reference['receipt_sha256']:
        raise ValueError('whole-envelope content or exact receipt digest differs')
    return data


class PagedEnvelope:
    """Bounded terminal-only assembly; a cursor/checksum never grants a read."""
    def __init__(self, source):
        self.source = strict_json(encoded(page_request(source)))
        self.data = bytearray()
        self.commitment = None
        self.eof = False
        self.failed = False

    def accept(self, output):
        try:
            if self.failed or self.eof or not isinstance(output, bytes) or not 0 < len(output) < MAX_QUERY_OUTPUT:
                raise ValueError('page journey is fenced or response exceeds bound')
            value = strict_json(output)
            fields = {'schema_version', 'reference', 'format', 'envelope_bytes', 'envelope_sha256',
                      'content_delivered', 'committed', 'authority_returned', 'provenance_authority',
                      'workflow_executed', 'production_qualified', 'encoding', 'offset', 'next_offset', 'eof', 'slice_hex'}
            if not isinstance(value, dict) or set(value) != fields or type(value['schema_version']) is not int or value['schema_version'] != 1:
                raise ValueError('page result schema differs')
            if any(value[key] is not False for key in ('committed', 'authority_returned', 'provenance_authority', 'workflow_executed', 'production_qualified')):
                raise ValueError('page data cannot claim effects or authority')
            if not same_data(value['reference'], self.source['operation']['expected']) or value['format'] not in ('utf8-text', 'csv', 'json') or value['encoding'] != 'hex':
                raise ValueError('page substituted its exact selected reference or encoding')
            total, offset, next_offset = value['envelope_bytes'], value['offset'], value['next_offset']
            if any(type(number) is not int for number in (total, offset, next_offset)) or not 1 <= total <= MAX_ENVELOPE or offset != len(self.data) or next_offset != min(offset + PAGE_BYTES, total) or next_offset <= offset:
                raise ValueError('page count, offset or progress differs')
            sha = value['envelope_sha256']
            if not isinstance(sha, str) or not re.fullmatch(r'[0-9a-f]{64}', sha) or not isinstance(value['slice_hex'], str) or not re.fullmatch(r'[0-9a-f]+', value['slice_hex']) or len(value['slice_hex']) != (next_offset-offset)*2:
                raise ValueError('page digest or exact byte slice differs')
            if value['eof'] is not (next_offset == total) or value['content_delivered'] is not True:
                raise ValueError('page EOF/delivery claim differs')
            commitment = total, sha, value['format']
            if self.commitment is not None and commitment != self.commitment:
                raise ValueError('page substituted the selected whole envelope')
            self.commitment = commitment
            self.data.extend(bytes.fromhex(value['slice_hex']))
            self.eof = value['eof']
            return next_offset, total
        except BaseException:
            self.failed = True
            self.data.clear()
            raise

    def complete(self):
        if self.failed or not self.eof or self.commitment is None:
            raise ValueError('no complete verified envelope')
        try:
            return checked_envelope(bytes(self.data), self.source, self.commitment)
        except BaseException:
            self.failed = True
            self.data.clear()
            raise


def capture_query(arguments, *, maximum=MAX_QUERY_OUTPUT, timeout=40):
    """Fixed native read/proposal only, private stdout pipe, real terminal PAM.

    Completion observes this child only; native leases/controllers retain their
    own cancellation/drain obligations. Never run an effect through this pipe.
    """
    prefix = ['/usr/bin/sudo', '--', NATIVE, 'granted-run']
    if arguments[:4] != prefix or len(arguments) not in (7, 8) or arguments[4] not in ('content-owned-inspection-review', 'content-owned-review') or (arguments[4] == 'content-owned-inspection-review') != (len(arguments) == 7) or maximum != MAX_QUERY_OUTPUT or type(timeout) not in (int, float) or not 0 < timeout <= 40:
        raise ValueError('only the closed native paged-read commands can be captured')
    return _capture_native(arguments, maximum, timeout)


def _capture_native(arguments, maximum, timeout=40):
    """Private transport; callers select closed native commands before entry."""
    if maximum not in (MAX_QUERY_OUTPUT, MAX_ENVELOPE_OUTPUT, MAX_RECOVERY_OUTPUT) or type(timeout) not in (int, float) or not 0 < timeout <= 40:
        raise ValueError('native response exceeds the fixed terminal observation budget')
    selector = selectors.DefaultSelector()
    process = None
    data = bytearray()
    try:
        process = subprocess.Popen(arguments, stdout=subprocess.PIPE, close_fds=True)
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise ValueError('native read exceeded its observation deadline')
            for key, _ in selector.select(min(.1, max(0, deadline-time.monotonic()))):
                try:
                    block = os.read(key.fd, min(8192, maximum-len(data)))
                except (BlockingIOError, InterruptedError):
                    continue
                if not block:
                    selector.unregister(key.fileobj)
                else:
                    data.extend(block)
                    if len(data) >= maximum:
                        raise ValueError('native read output exceeded its exact bound')
        if process.wait(timeout=max(.001, deadline-time.monotonic())) != 0 or not data:
            raise ValueError('native current owner/grant read did not complete')
        return bytes(data)
    finally:
        selector.close()
        if process is not None:
            process.stdout.close()
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def runtime():
    uid = os.getuid()
    if uid < 1000 or uid >= 65534 or os.geteuid() != uid:
        raise ValueError('ordinary installed interactive account required')
    base = Path('/run/user') / str(uid)
    if os.environ.get('XDG_RUNTIME_DIR') != str(base) or base.resolve(strict=True) != base:
        raise ValueError('fixed installed private runtime required')
    metadata = base.stat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValueError('unsafe interactive runtime metadata')
    path = base / 'luma-terminal-proposals'
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid or stat.S_IMODE(metadata.st_mode) != 0o700 or path.resolve(strict=True) != path:
        raise ValueError('unsafe terminal proposal directory')
    return path


def protected(path, maximum, *, sudo=False):
    path = Path(path)
    if path.resolve(strict=True) != path:
        raise ValueError('bridge dependency alias refused')
    for ancestor in path.parents:
        value = ancestor.stat()
        if value.st_uid != 0 or not stat.S_ISDIR(value.st_mode) or value.st_mode & 0o022:
            raise ValueError('unprotected bridge dependency ancestor')
    value = path.stat()
    forbidden = 0o3022 if sudo and str(path) == '/usr/bin/sudo' else 0o7022
    if not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_nlink != 1 or value.st_mode & forbidden or not 0 < value.st_size <= maximum:
        raise ValueError('unprotected or oversized bridge dependency')


def terminal_arguments(value, path):
    value = proposal(value)
    if value['operation'] in ('paged-read', 'envelope-read', 'search-journey', 'conversation-journey', 'workflow-journey', 'collection-journey', 'speech-journey', 'capture-reference-journey', 'restore-journey', 'retire-journey', 'lifecycle-journey', 'editor-journey'):
        raise ValueError('managed journeys require their explicit review and fresh grant steps')
    prefix = ['/usr/bin/sudo', '--', NATIVE, 'granted-run']
    if value['operation'] == 'office-proposal':
        return prefix + ['content-office-export-proposal', value['login'], str(path)]
    if value['operation'] == 'office-export':
        return prefix + ['content-office-export', value['login'], value['read_grant'], value['effect_grant'], str(path)]
    if value['operation'] == 'inspection':
        return prefix + ['content-owned-inspection-review', value['login'], str(path)]
    if value['operation'] == 'review':
        return prefix + ['content-owned-review', value['login'], value['read_grant'], str(path)]
    return prefix + ['content-owned-apply', value['login'], value['read_grant'], value['effect_grant'], value['approval'], str(path)]


def inspection_scope(output, source):
    value = strict_json(output)
    fields = {'schema_version', 'inspection_usage', 'query_only', 'private_content_read', 'grant_issued', 'committed'}
    if not isinstance(value, dict) or set(value) != fields or type(value['schema_version']) is not int or value['schema_version'] != 1 or value['query_only'] is not True or any(value[key] is not False for key in ('private_content_read', 'grant_issued', 'committed')):
        raise ValueError('native page inspection response differs')
    usage = value['inspection_usage']
    if not isinstance(usage, dict) or set(usage) != {'action', 'selector', 'input_bytes', 'output_bytes', 'units'} or usage['action'] != 'file.read' or type(usage['input_bytes']) is not int or usage['input_bytes'] != MAX_REQUEST or type(usage['output_bytes']) is not int or usage['output_bytes'] != MAX_QUERY_OUTPUT or type(usage['units']) is not int or usage['units'] != 1:
        raise ValueError('native page scope is not its finite Read allowance')
    selector = usage['selector']
    if not isinstance(selector, dict) or set(selector) != {'kind', 'id', 'generation', 'digest'} or selector['kind'] != 'file' or selector['id'] != 'native-content-query-v1' or type(selector['generation']) is not int or selector['generation'] != source['binding']['owner_generation'] or not isinstance(selector['digest'], str) or not re.fullmatch(r'[0-9a-f]{64}', selector['digest']) or selector['digest'] == '0'*64:
        raise ValueError('native page scope substitutes its owner generation or selector')
    return usage


def canonical_native_request(value):
    host_path = Path('/usr/libexec/luma-os/workspace_host.py')
    protected(host_path, 128 * 1024)
    spec = importlib.util.spec_from_file_location('luma_terminal_native_host', host_path)
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    binary = host.PinnedExecutable(Path(NATIVE))
    try:
        if value['operation'] in ('restore-journey', 'retire-journey'):
            command = 'content-restore-request' if value['operation'] == 'restore-journey' else 'content-restore-retire-request'
        else:
            command = 'content-office-request' if value['operation'].startswith('office-') else 'content-contract-native-request'
        state, output = host.run_process(binary, command, value['request'].encode('utf-8'),
                                         threading.Event(), lambda _: None, maximum=MAX_STAGE)
    finally:
        binary.close()
    if state != 'completed' or not output:
        raise ValueError('native canonical request did not complete')
    return (recovery_canonical_response(value, output) if value['operation'] in ('restore-journey', 'retire-journey') else canonical_response(value, output)), host


@contextmanager
def request_stage(directory, canonical):
    """One exact inert request, removed only if its inode was not substituted."""
    path = directory / (uuid.uuid4().hex + '.request')
    identity = None
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            data = canonical.encode('utf-8')
            if not 0 < len(data) <= MAX_REQUEST:
                raise ValueError('exact terminal request exceeds bound')
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
            item = os.fstat(output.fileno())
            identity = item.st_dev, item.st_ino
        yield path
    finally:
        try:
            item = path.lstat()
            if identity == (item.st_dev, item.st_ino):
                path.unlink()
        except FileNotFoundError:
            pass


def finite_scope(value, source, action, kind, identifier, output_bytes=MAX_QUERY_OUTPUT):
    if not isinstance(value, dict) or set(value) != {'action', 'selector', 'input_bytes', 'output_bytes', 'units'} or value['action'] != action or type(value['input_bytes']) is not int or value['input_bytes'] != MAX_REQUEST or type(value['output_bytes']) is not int or value['output_bytes'] != output_bytes or type(value['units']) is not int or value['units'] != 1:
        raise ValueError('native scope differs from the exact finite operation')
    selector = value['selector']
    if not isinstance(selector, dict) or set(selector) != {'kind', 'id', 'generation', 'digest'} or selector['kind'] != kind or selector['id'] != identifier or type(selector['generation']) is not int or selector['generation'] != source['binding']['owner_generation'] or not exact_sha(selector['digest']):
        raise ValueError('native scope substitutes its principal generation or selector')
    return value


def owner_inspection(output, source, *, envelope=False):
    value = strict_json(output)
    if not isinstance(value, dict) or set(value) != {'schema_version', 'inspection_usage', 'query_only', 'private_content_read', 'grant_issued', 'committed'} or type(value['schema_version']) is not int or value['schema_version'] != 1 or value['query_only'] is not envelope or any(value[key] is not False for key in ('private_content_read', 'grant_issued', 'committed')):
        raise ValueError('native owner inspection response differs')
    return finite_scope(value['inspection_usage'], source, 'file.read', 'file',
                        'native-content-envelope-v1' if envelope else 'native-content-inspect-v1',
                        MAX_ENVELOPE_OUTPUT if envelope else MAX_QUERY_OUTPUT)


def native_calculation(engine, source, host):
    """Actually run the pinned deterministic engine; never claim publication."""
    value = host.request(dict(schema_version=1, id='terminal-native-calculation', operation='preview', engine=engine, source=source))
    command, payload = host.invocation(value)
    binary = host.PinnedExecutable(Path(NATIVE))
    try:
        state, output = host.run_process(binary, command, payload, threading.Event(), lambda _: None)
    finally:
        binary.close()
    if state != 'completed' or not output:
        raise ValueError('actual deterministic recalculation did not complete')
    result = host.validate_result(value, output)
    rendered = result['calculation' if engine == 'spreadsheet' else 'rendering']
    if engine == 'animation':
        content = encoded([dict(index=frame['index'], canonical_svg=frame['canonical_svg'], svg_sha256=frame['svg_sha256']) for frame in rendered['frames']])
        digest = rendered['frames_sha256']
        media_type = 'application/vnd.luma.sampled-svg-frames+json'
    else:
        key, sha, media_type = {'spreadsheet': ('canonical_csv', 'csv_sha256', 'text/csv; charset=utf-8'),
            'document': ('canonical_html', 'html_sha256', 'text/html; charset=utf-8'),
            'diagram': ('canonical_svg', 'svg_sha256', 'image/svg+xml')}[engine]
        content, digest = rendered[key].encode('utf-8'), rendered[sha]
    derivation = dict(engine=engine, implementation=rendered['engine'], canonical_source_sha256=rendered['source_sha256'],
                      output_sha256=digest, output_bytes=len(content), media_type=media_type)
    return result, derivation


def reviewed_workflow(source, calculation, output):
    """Check DATA relationships from the actual live native review pipe."""
    value = strict_json(output)
    fields = {'schema_version', 'approval', 'review_sha256', 'decision', 'resulting', 'derivation', 'source_bytes', 'storage_bytes',
              'inspection_usage', 'effect_usage', 'committed', 'authority_returned', 'provenance_authority', 'workflow_executed'}
    if not isinstance(value, dict) or set(value) != fields or type(value['schema_version']) is not int or value['schema_version'] != 1 or any(value[key] is not False for key in ('committed', 'authority_returned', 'provenance_authority', 'workflow_executed')):
        raise ValueError('native workflow review schema or authority claims differ')
    decision = value['decision']
    if decision not in ('published', 'conflict-retained', 'no-change-retained') or not exact_sha(value['review_sha256']) or value['approval'] != ('write:' if decision == 'published' else 'retain:') + value['review_sha256'] or not same_data(value['derivation'], calculation):
        raise ValueError('workflow review differs from the actual engine or exact effect decision')
    request = source['operation']['request']
    reference = reference_data(value['resulting'])
    if reference['artifact_id'] != request['artifact_id'] or (decision == 'published' and reference['version'] != (1 if request['expected'] is None else request['expected']['version']+1)) or (decision == 'no-change-retained' and not same_data(reference, request['expected'])) or (decision == 'conflict-retained' and (request['expected'] is None or same_data(reference, request['expected']))):
        raise ValueError('workflow review substitutes its exact expected version or conflict')
    if type(value['source_bytes']) is not int or not 0 < value['source_bytes'] <= MAX_REQUEST or type(value['storage_bytes']) is not int or not 8192 <= value['storage_bytes'] <= 24*1024*1024:
        raise ValueError('workflow reviewed storage/source exceeds the native admission bound')
    finite_scope(value['inspection_usage'], source, 'file.read', 'file', 'native-content-inspect-v1')
    finite_scope(value['effect_usage'], source, 'artifact.write' if decision == 'published' else 'resource.retention', 'artifact', 'native-content-store-v1')
    if value['inspection_usage']['selector']['digest'] != value['effect_usage']['selector']['digest']:
        raise ValueError('workflow Read/effect pair binds different acquisitions')
    return value


def completed_workflow(source, review, output):
    """Validate a compact actual-command result, not a portable authority token."""
    value = strict_json(output)
    if not isinstance(value, dict) or set(value) != {'schema_version', 'outcome', 'derivation', 'workflow_checkpoint', 'committed', 'authority_returned', 'provenance_authority', 'workflow_executed'} or type(value['schema_version']) is not int or value['schema_version'] != 1 or value['committed'] is not True or value['workflow_executed'] is not True or value['authority_returned'] is not False or value['provenance_authority'] is not False:
        raise ValueError('no exact C-backed native workflow completion was observed')
    request, outcome, checkpoint = source['operation']['request'], value['outcome'], value['workflow_checkpoint']
    if not isinstance(outcome, dict) or set(outcome) != {'sequence', 'request_id', 'review_sha256', 'decision', 'resulting', 'source_sha256', 'source_kind', 'replayed'} or type(outcome['sequence']) is not int or not 1 <= outcome['sequence'] <= 256 or type(outcome['replayed']) is not bool or outcome['request_id'] != request['request_id'] or outcome['review_sha256'] != review['review_sha256'] or outcome['decision'] != review['decision'] or not same_data(outcome['resulting'], review['resulting']) or outcome['source_kind'] != 'managed-render-intent':
        raise ValueError('native workflow outcome substitutes the actual reviewed request')
    if outcome['sequence'] < review['resulting']['version'] + (0 if outcome['decision'] == 'published' else 1):
        raise ValueError('native workflow ordinal precedes its required published history')
    checkpoint_fields = {'schema_version', 'profile', 'workflow_sha256', 'binding', 'request_id', 'review_sha256',
                         'original_intent_sha256', 'derivation', 'record_sha256', 'protected_outcome', 'outcome'}
    if not isinstance(checkpoint, dict) or set(checkpoint) != checkpoint_fields or type(checkpoint['schema_version']) is not int or checkpoint['schema_version'] != 1 or checkpoint['profile'] != 'native-content-engine-v1' or not exact_sha(checkpoint['workflow_sha256']) or not exact_sha(checkpoint['record_sha256']) or not same_data(checkpoint['binding'], source['binding']) or checkpoint['request_id'] != request['request_id'] or checkpoint['review_sha256'] != review['review_sha256'] or not same_data(checkpoint['outcome'], outcome) or not same_data(checkpoint['derivation'], review['derivation']) or not same_data(value['derivation'], review['derivation']):
        raise ValueError('native compact checkpoint is not bound to its reviewed engine and outcome')
    intent = dict(binding=source['binding'], artifact_id=request['artifact_id'], expected=request['expected'],
                  metadata=dict(request_id=request['request_id'], workflow_sha256=checkpoint['workflow_sha256']),
                  engine=request['engine'], source=request['source'])
    intent_sha = hashlib.sha256(encoded(intent)).hexdigest()
    if checkpoint['original_intent_sha256'] != intent_sha or outcome['source_sha256'] != intent_sha:
        raise ValueError('native checkpoint substitutes exact original workflow source')
    protected = checkpoint['protected_outcome']
    if not isinstance(protected, dict) or set(protected) != {'binding', 'outcome_count', 'head_sha256', 'quarantine_sha256'} or not same_data(protected['binding'], source['binding']) or type(protected['outcome_count']) is not int or not outcome['sequence'] <= protected['outcome_count'] <= 256 or not exact_sha(protected['head_sha256']) or not exact_sha(protected['quarantine_sha256']):
        raise ValueError('native checkpoint substitutes protected owner/history/retirement data')
    return value


def capture_workflow(value, path):
    value = proposal(value)
    if value['operation'] != 'apply' or value['read_grant'] == value['effect_grant']:
        raise ValueError('workflow effect requires independent explicit Read and effect grants')
    workflow_request(strict_json(value['request']))
    return _capture_native(terminal_arguments(value, path), MAX_QUERY_OUTPUT)


def capture_envelope(value, path):
    value = proposal(value)
    if value['operation'] != 'review':
        raise ValueError('complete envelope requires original finite Read only')
    envelope_request(strict_json(value['request']))
    return _capture_native(terminal_arguments(value, path), MAX_ENVELOPE_OUTPUT)


def whole_envelope_response(source, output):
    if not isinstance(output, bytes) or not 0 < len(output) < MAX_ENVELOPE_OUTPUT:
        raise ValueError('whole-envelope response exceeds its finite native allowance')
    value = strict_json(output)
    fields = {'schema_version', 'reference', 'format', 'envelope_bytes', 'envelope_sha256', 'canonical_envelope',
              'content_delivered', 'committed', 'authority_returned', 'provenance_authority', 'workflow_executed', 'production_qualified'}
    if not isinstance(value, dict) or set(value) != fields or type(value['schema_version']) is not int or value['schema_version'] != 1 or value['content_delivered'] is not True or any(value[key] is not False for key in ('committed', 'authority_returned', 'provenance_authority', 'workflow_executed', 'production_qualified')) or not same_data(value['reference'], source['operation']['expected']):
        raise ValueError('whole-envelope response substitutes the exact reference or claims authority')
    if type(value['envelope_bytes']) is not int or not 0 < value['envelope_bytes'] <= MAX_ENVELOPE or value['format'] not in ('utf8-text', 'csv', 'json') or not exact_sha(value['envelope_sha256']) or not isinstance(value['canonical_envelope'], str):
        raise ValueError('whole-envelope metadata exceeds its exact bound')
    return checked_envelope(value['canonical_envelope'].encode('utf-8'), source,
                            (value['envelope_bytes'], value['envelope_sha256'], value['format']))


def native_reopen(envelope, host):
    value = dict(schema_version=1, id='owner-terminal-reopen', operation='reopen', source=envelope.decode('utf-8'),
                 expected_envelope_sha256=hashlib.sha256(envelope).hexdigest())
    command, payload = host.invocation(host.request(value))
    binary = host.PinnedExecutable(Path(NATIVE))
    try:
        state, output = host.run_process(binary, command, payload, threading.Event(), lambda _: None)
    finally:
        binary.close()
    if state != 'completed' or not output:
        raise ValueError('complete native envelope reopen did not finish')
    return host.validate_result(value, output)


def terminal_line(prompt, maximum=128):
    """Bound human control input; passwords remain entirely with native PAM."""
    print(prompt, end='', flush=True)
    text = sys.stdin.readline(maximum+1)
    if not text:
        raise EOFError()
    if len(text.encode('utf-8')) > maximum or not text.endswith('\n'):
        raise ValueError('terminal selection exceeds its explicit byte bound')
    return text[:-1].removesuffix('\r').strip()


def grant_selection(prompt):
    value = terminal_line(prompt)
    if value == 'q':
        return None
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value):
        raise ValueError('explicit finite grant ID required; no grant is inferred or cached')
    return value


def discovery_response(source, output):
    """Validate data from the actual native Read pipe, not a portable grant.

    A collection's complete membership is resolved inside the verified native
    snapshot. This controller never expands it, substitutes current versions,
    or treats the subset of returned hits as a new authenticated collection.
    """
    discovery_request(source)
    if not isinstance(output, bytes) or not 0 < len(output) < MAX_QUERY_OUTPUT:
        raise ValueError('discovery output exceeds its finite native allowance')
    value = strict_json(output)
    operation = source['operation']
    selected = operation['kind'] == 'search-semantic-selected'
    key = 'semantic_search' if selected else 'semantic_collection_search'
    flags = ('content_delivered', 'committed', 'authority_returned', 'selection_is_authority',
             'similarity_is_authority', 'provenance_authority', 'workflow_executed', 'production_qualified')
    if not isinstance(value, dict) or set(value) != {'schema_version', key, *flags} or type(value['schema_version']) is not int or value['schema_version'] != 1 or any(value[flag] is not False for flag in flags):
        raise ValueError('discovery result substitutes its operation or claims authority')
    result = value[key]
    if not selected:
        if not isinstance(result, dict) or set(result) != {'collection', 'search'} or not same_data(result['collection'], operation['expected']):
            raise ValueError('discovery substituted its exact typed collection')
        result = result['search']
    fields = {'algorithm', 'canonical_query', 'selection_sha256', 'index_descriptor_sha256', 'selected_versions',
              'vocabulary_terms', 'indexed_features', 'requested_dimensions', 'effective_dimensions',
              'matches', 'total_matches', 'truncated'}
    if not isinstance(result, dict) or set(result) != fields or result['algorithm'] != 'tfidf-lsa-jacobi-v1' or result['canonical_query'] != discovery_query(operation['query']):
        raise ValueError('discovery result substitutes its algorithm or canonical query')
    bounds = {'selected_versions': (0, 64), 'vocabulary_terms': (0, 4096), 'indexed_features': (0, 512),
              'requested_dimensions': (1, 8), 'effective_dimensions': (0, 8), 'total_matches': (0, 64)}
    if any(type(result[name]) is not int or not low <= result[name] <= high for name, (low, high) in bounds.items()):
        raise ValueError('discovery counters exceed their native bounds')
    if (result['requested_dimensions'] != operation['dimensions']
            or result['indexed_features'] != min(result['vocabulary_terms'], 512)
            or result['effective_dimensions'] > min(result['selected_versions'], result['indexed_features'], operation['dimensions'])
            or result['total_matches'] > result['selected_versions']
            or (result['selected_versions'] == 0 and result['vocabulary_terms'] != 0)
            or (result['effective_dimensions'] == 0 and result['total_matches'] != 0)
            or not exact_sha(result['selection_sha256']) or not exact_sha(result['index_descriptor_sha256'])):
        raise ValueError('discovery result changes its selection, projection or descriptor')
    references = operation['references'] if selected else [] if result['selected_versions'] == 0 else None
    if references is not None:
        canonical_selection = json.dumps(references, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
        descriptor = dict(schema_version=1, algorithm='tfidf-lsa-jacobi-v1', binding=source['binding'], references=references,
                          dimensions=operation['dimensions'], maximum_vocabulary=4096, maximum_features=512)
        canonical_descriptor = json.dumps(descriptor, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
        if (result['selected_versions'] != len(references) or result['selection_sha256'] != hashlib.sha256(canonical_selection).hexdigest()
                or result['index_descriptor_sha256'] != hashlib.sha256(canonical_descriptor).hexdigest()):
            raise ValueError('discovery result substitutes the complete exact selection or owner generation')
    matches = result['matches']
    if not isinstance(matches, list) or len(matches) > min(operation['limit'], result['total_matches']) or result['truncated'] is not (len(matches) < result['total_matches']):
        raise ValueError('discovery result count or truncation differs')
    previous, identifiers = None, set()
    for hit in matches:
        if not isinstance(hit, dict) or set(hit) != {'reference', 'format', 'cosine_millionths'}:
            raise ValueError('discovery hit is not a closed native reference result')
        reference = reference_data(hit['reference'])
        score = hit['cosine_millionths']
        if hit['format'] not in ('utf8-text', 'csv', 'json') or type(score) is not int or not 1 <= score <= 1000000:
            raise ValueError('discovery hit has an invalid format or bounded similarity')
        order = (-score, reference['artifact_id'])
        if reference['artifact_id'] in identifiers or (previous is not None and previous >= order):
            raise ValueError('discovery duplicated or reordered a native hit')
        if selected and not any(same_data(reference, item) for item in references):
            raise ValueError('discovery hit enlarges or substitutes the exact selected versions')
        identifiers.add(reference['artifact_id'])
        previous = order
    return result


def discovery_journey(value, directory):
    """One exact semantic query, then explicitly selected fresh native reads."""
    value = proposal(value)
    if value['operation'] != 'search-journey':
        raise ValueError('the original native discovery journey must be selected')
    canonical, _ = canonical_native_request(value)
    value = dict(value, request=canonical)
    source = discovery_request(strict_json(canonical))
    inspect = dict(value, operation='inspection')
    with request_stage(directory, canonical) as path:
        protected(NATIVE, 128*1024*1024)
        scope = inspection_scope(capture_query(terminal_arguments(inspect, path)), source)
        print('Exact owner-generation semantic Read scope (DATA, not an issued grant):\n'+json.dumps(scope, ensure_ascii=True, indent=2), flush=True)
        grant = grant_selection('Finite Read grant ID for this exact query, or q to stop: ')
        if grant is None:
            print('Discovery stopped before private query delivery. No content read or effect requested.', flush=True)
            return 0
        protected(NATIVE, 128*1024*1024)
        output = capture_query(terminal_arguments(dict(inspect, operation='review', read_grant=grant), path))
        result = discovery_response(source, output)
    print('Actual native semantic results observed. Similarity is not truth, permission, automatic classification or proof of a current version. Results are already delivered data; no content, publication or workflow effect was requested.', flush=True)
    print(json.dumps(result, ensure_ascii=True, indent=2), flush=True)
    if not result['matches']:
        print('No matching exact versions. No scope enlargement or automatic fallback was requested.', flush=True)
        return 0
    for _ in range(16):
        choice = terminal_line('Explicit result number 1-'+str(len(result['matches']))+' for a NEW exact-envelope Read, or q to finish: ', 8)
        if choice == 'q':
            return 0
        if not re.fullmatch(r'[1-9][0-9]?', choice) or int(choice) > len(result['matches']):
            raise ValueError('select one displayed exact result; no inferred reference')
        reference = result['matches'][int(choice)-1]['reference']
        read = dict(source, operation=dict(kind='envelope', expected=reference))
        print('Selected exact historical reference. This requires independent current PAM, owner/C/resource checks and its own finite Read; the search grant is not reused:\n'+json.dumps(reference, ensure_ascii=True, indent=2), flush=True)
        envelope_read(dict(value, operation='envelope-read', request=encoded(read).decode('utf-8')), directory)
    print('Discovery session reached its fixed 16-selection bound. Start a new explicit native journey for further reads.', flush=True)
    return 0


def envelope_read(value, directory):
    """Single exact native Read, including fresh current owner/C/output checks."""
    value = proposal(value)
    source = envelope_request(strict_json(value['request']))
    inspect = dict(value, operation='inspection')
    canonical, host = canonical_native_request(inspect)
    inspect['request'] = canonical
    source = envelope_request(strict_json(canonical))
    with request_stage(directory, canonical) as path:
        protected(NATIVE, 128*1024*1024)
        scope = owner_inspection(capture_query(terminal_arguments(inspect, path)), source, envelope=True)
        print('Exact immutable-envelope Read scope. The native command authenticates current owner and authority continuously during delivery:', flush=True)
        print(json.dumps(scope, ensure_ascii=True, indent=2), flush=True)
        grant = grant_selection('Finite Read grant ID for this exact envelope, or q to stop: ')
        if grant is None:
            print('Read stopped before private delivery. No publication or export requested.', flush=True)
            return None
        protected(NATIVE, 128*1024*1024)
        result = capture_envelope(dict(inspect, operation='review', read_grant=grant), path)
        envelope = whole_envelope_response(source, result)
    reopened = native_reopen(envelope, host)
    print('Fresh exact native read and complete-envelope reopen observed. The result is already delivered data, not permission for another read.', flush=True)
    print(json.dumps(dict(binding=source['binding'], reference=source['operation']['expected'],
        envelope_sha256=hashlib.sha256(envelope).hexdigest(), content=reopened['preview_content'],
        publication_requested=False, export_requested=False, authority_returned=False), ensure_ascii=True, indent=2), flush=True)
    return source, reopened, host


def recalculate_owner(reopened, host):
    if reopened['preview_format'] != 'json':
        raise ValueError('recalculation requires a typed managed-engine JSON wrapper')
    wrapper = strict_json(reopened['preview_content'])
    if not isinstance(wrapper, dict) or set(wrapper) != {'schema_version', 'engine', 'source'} or type(wrapper['schema_version']) is not int or wrapper['schema_version'] != 1 or wrapper['engine'] not in ENGINES or not isinstance(wrapper['source'], dict):
        raise ValueError('committed data is not an exact supported editable engine wrapper')
    result, derivation = native_calculation(wrapper['engine'], encoded(wrapper['source']).decode('utf-8'), host)
    print('Actual native deterministic recalculation from the freshly reopened source completed. This does not publish a version or execute another workflow.', flush=True)
    print(json.dumps(dict(derivation=derivation, result=result, publication_requested=False,
                         workflow_executed=False, authority_returned=False), ensure_ascii=True, indent=2), flush=True)
    return wrapper, derivation


def revised_source():
    print('Enter revised engine JSON in this terminal. Finish with a line containing only END; q alone before any source cancels. Maximum 1 MiB and 16,384 lines.', flush=True)
    lines, used = [], 0
    for _ in range(16384):
        line = sys.stdin.readline(1024*1024-used+1)
        if not line:
            raise EOFError()
        if line.rstrip('\r\n') == 'END':
            if not lines:
                raise ValueError('empty engine JSON is not a valid recalculation request')
            return ''.join(lines)
        if not lines and line.rstrip('\r\n') == 'q':
            return None
        used += len(line.encode('utf-8'))
        if used > 1024*1024:
            raise ValueError('revised engine source exceeds the fixed byte bound')
        lines.append(line)
    raise ValueError('revised source exceeds the fixed line bound')


def workflow_journey(value, directory):
    """Reachable original-PAM review/approval/apply/read/recalculation journey.

    Each command starts its own native session and finite grant checks. No
    receipt supplied by the GUI or a prior invocation is accepted as authority.
    """
    value = proposal(value)
    used_requests = set()
    completed = None
    effect_started = False
    try:
        for _ in range(16):
            effect_started, completed = False, None
            canonical, host = canonical_native_request(value)
            value = dict(value, request=canonical)
            source = workflow_request(strict_json(canonical))
            request = source['operation']['request']
            if request['request_id'] in used_requests:
                raise ValueError('each additional edit requires its own explicitly selected request ID')
            used_requests.add(request['request_id'])
            _, calculation = native_calculation(request['engine'], request['source'], host)
            print('Actual native engine preflight completed; no effect submitted. Source/output commitments:', flush=True)
            print(json.dumps(calculation, ensure_ascii=True, indent=2), flush=True)
            with request_stage(directory, canonical) as path:
                inspect = dict(value, operation='inspection')
                protected(NATIVE, 128*1024*1024)
                scope = owner_inspection(capture_query(terminal_arguments(inspect, path)), source)
                print('Initial finite Read scope for exact private workflow review:', flush=True)
                print(json.dumps(scope, ensure_ascii=True, indent=2), flush=True)
                grant = grant_selection('Review Read grant ID, or q before any effect: ')
                if grant is None:
                    print('Workflow round stopped before apply. No effect requested for this round; any earlier observed completions remain.', flush=True)
                    return 130
                protected(NATIVE, 128*1024*1024)
                review = reviewed_workflow(source, calculation,
                    capture_query(terminal_arguments(dict(inspect, operation='review', read_grant=grant), path)))
                print('Exact native review, decision, separate apply Read/effect scopes and approval:', flush=True)
                print(json.dumps(review, ensure_ascii=True, indent=2), flush=True)
                read_grant = grant_selection('Apply Read grant ID for this reviewed pair, or q: ')
                if read_grant is None:
                    print('Workflow round stopped before apply. No effect requested for this round; any earlier observed completions remain.', flush=True)
                    return 130
                effect_grant = grant_selection('Independent finite effect grant ID for this pair, or q: ')
                if effect_grant is None:
                    print('Workflow round stopped before apply. No effect requested for this round; any earlier observed completions remain.', flush=True)
                    return 130
                if read_grant == effect_grant:
                    raise ValueError('Read and effect grants must be explicitly independent')
                approval = terminal_line('Type the exact displayed write:/retain:SHA approval, or q: ')
                if approval == 'q':
                    print('Workflow round stopped before apply. No effect requested for this round; any earlier observed completions remain.', flush=True)
                    return 130
                if approval != review['approval']:
                    raise ValueError('approval differs from the actual exact native review')
                print('Applying the exact reviewed intent. Interruption from this point may leave an anchored or partially published checkpoint; never assume rollback or auto-retry.', flush=True)
                print(json.dumps(dict(request_id=request['request_id'], request_sha256=hashlib.sha256(canonical.encode('utf-8')).hexdigest(),
                                     review_sha256=review['review_sha256'], expected=request['expected']), ensure_ascii=True, indent=2), flush=True)
                apply = dict(inspect, operation='apply', read_grant=read_grant, effect_grant=effect_grant, approval=approval)
                protected(NATIVE, 128*1024*1024)
                effect_started = True
                completed = completed_workflow(source, review, capture_workflow(apply, path))
            decision = completed['outcome']['decision']
            messages = {'published': 'Published: the actual native C-backed workflow completed and its exact version was reopened by the native worker.',
                'conflict-retained': 'Conflict retained: the native workflow completed and retained the exact attempted intent. The current version was NOT replaced or automatically merged.',
                'no-change-retained': 'No version change: the native workflow completed and retained this exact no-change intent; the immutable artifact reference remains unchanged.'}
            print(messages[decision], flush=True)
            print(json.dumps(completed, ensure_ascii=True, indent=2), flush=True)
            choice = terminal_line('Type r for a separately granted fresh exact read/recalculation of the committed reference, or q to finish: ')
            if choice == 'q':
                return 0
            if choice != 'r':
                raise ValueError('explicit r or q selection required; no read inferred')
            read_source = dict(schema_version=1, login=source['login'], binding=source['binding'],
                               operation=dict(kind='envelope', expected=completed['outcome']['resulting']))
            read_value = dict(value, operation='envelope-read', request=encoded(read_source).decode('utf-8'))
            actual = envelope_read(read_value, directory)
            if actual is None:
                print('The workflow completion above remains observed; the separate private read was stopped.', flush=True)
                return 0
            actual_source, reopened, actual_host = actual
            wrapper, derivation = recalculate_owner(reopened, actual_host)
            if decision != 'conflict-retained' and not same_data(derivation, completed['derivation']):
                raise ValueError('fresh published/no-change source recalculation differs from its native workflow commitment')
            if decision == 'conflict-retained':
                print('This recalculation is of the genuinely committed reference, not the retained unpublished conflicting candidate.', flush=True)
            choice = terminal_line('Type e to enter a revised source for a NEW separately reviewed workflow, or q to finish: ')
            if choice == 'q':
                return 0
            if choice != 'e':
                raise ValueError('explicit e or q selection required; no edit inferred')
            content = revised_source()
            if content is None:
                return 0
            request_id = terminal_line('New stable request ID (retain it for reconciliation; never reuse a previous edit ID): ')
            updated = dict(schema_version=1, request_id=request_id, artifact_id=actual_source['operation']['expected']['artifact_id'],
                           expected=actual_source['operation']['expected'], engine=wrapper['engine'], source=content)
            next_source = dict(schema_version=1, login=source['login'], binding=source['binding'], operation=dict(kind='workflow', request=updated))
            value = dict(value, request=encoded(workflow_request(next_source)).decode('utf-8'))
        print('Sixteen explicitly reviewed workflow rounds completed. Open a new terminal journey for further edits; no session/grant was retained.', flush=True)
        return 0
    except (KeyboardInterrupt, EOFError):
        if completed is not None:
            print('\nNative workflow completion was already observed. Subsequent read/recalculation/edit input stopped; no additional effect is inferred.', file=sys.stderr, flush=True)
        elif effect_started:
            print('\nApply interrupted: effect outcome is UNCERTAIN, possibly partially or fully committed. Inspect the exact original request/checkpoint before retry; no rollback or completion is claimed.', file=sys.stderr, flush=True)
        else:
            print('\nWorkflow round stopped before apply. No effect requested for this round; any earlier observed completions remain.', file=sys.stderr, flush=True)
        return 130
    except Exception:
        if completed is not None:
            print('Native workflow completion was already observed, but subsequent read/recalculation/input failed. Do not reapply as a substitute for inspecting that exact checkpoint.', file=sys.stderr, flush=True)
        elif effect_started:
            print('Native apply did not produce a validated complete result: outcome is UNCERTAIN, possibly partially or fully committed. Inspect the exact original request/checkpoint; no auto-retry, rollback or success is claimed.', file=sys.stderr, flush=True)
        else:
            print('Workflow review/input refused before apply. No effect requested for this round; any earlier observed completions remain.', file=sys.stderr, flush=True)
        return 1


def owner_read_journey(value, directory):
    read_observed = False
    forwarded = False
    try:
        actual = envelope_read(value, directory)
        if actual is None:
            return 130
        read_observed = True
        _, reopened, host = actual
        recalculate = False
        if reopened['preview_format'] == 'json':
            wrapper = strict_json(reopened['preview_content'])
            if isinstance(wrapper, dict) and wrapper.get('engine') in ENGINES:
                recalculate = True
        choice = terminal_line('Type i to explicitly forward this historical snapshot into NEW inference; '+('r to recalculate delivered source without publication; ' if recalculate else '')+'q finish: ', 8)
        if choice == 'i':
            forwarded = True
            return draft_controller().forward_snapshot(types.SimpleNamespace(**globals()), actual, directory)
        if choice == 'r' and recalculate:
            recalculate_owner(reopened, host)
        elif choice != 'q':
            raise ValueError('explicit available action required; no read/inference/effect inferred')
        return 0
    except (KeyboardInterrupt, EOFError):
        print('Exact Read already observed. The separately selected inference/draft handoff was interrupted; inspect any submitted native inference/workflow checkpoint before retry. No rollback, release or further authority is inferred.' if forwarded else 'Read journey interrupted. No publication or export requested. Already observed delivery, if any, cannot be recalled.', file=sys.stderr, flush=True)
        return 130
    except Exception:
        print('Exact Read already observed. The separately selected inference/draft handoff did not return normally; inspect any submitted native inference/workflow checkpoint before retry. No success, rollback or release is inferred.' if forwarded else 'Read/recalculation refused. No publication or export requested. ' +
              ('The exact read was already observed; later calculation did not complete.' if read_observed else 'No complete verified read is claimed.'), file=sys.stderr, flush=True)
        return 1


def paged_read(value, directory):
    """Each page uses fresh original PAM/current finite Read authorization.

    No private bytes or claimed authority reach WebKit, no grant is inferred
    from a cursor, and no publication/export command is executed by this path.
    """
    value = proposal(value)
    source = page_request(strict_json(value['request']))
    assembled = PagedEnvelope(source)
    try:
        for _ in range((MAX_ENVELOPE + PAGE_BYTES-1)//PAGE_BYTES):
            current = strict_json(encoded(source))
            current['operation']['offset'] = len(assembled.data)
            inspect = dict(value, operation='inspection', request=encoded(current).decode('utf-8'))
            canonical, host = canonical_native_request(inspect)
            path = directory / (uuid.uuid4().hex + '.request')
            try:
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                with os.fdopen(descriptor, 'wb') as output:
                    output.write(canonical.encode('utf-8'))
                    output.flush()
                    os.fsync(output.fileno())
                protected(NATIVE, 128 * 1024 * 1024)
                usage = inspection_scope(capture_query(terminal_arguments(inspect, path)), source)
                print('Exact page at byte ' + str(len(assembled.data)) + '. Obtain a finite Read grant for this native scope:', flush=True)
                print(json.dumps(usage, ensure_ascii=True, indent=2), flush=True)
                grant = input('Finite Read grant ID for this page, or q to stop: ').strip()
                if grant == 'q':
                    print('Read stopped. No publication or export was requested; partial assembly discarded.', flush=True)
                    return 130
                if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', grant):
                    raise ValueError('explicit bounded finite Read grant ID required')
                review = dict(inspect, operation='review', read_grant=grant)
                protected(NATIVE, 128 * 1024 * 1024)
                received, total = assembled.accept(capture_query(terminal_arguments(review, path)))
                print(f'Observed native delivery: {received} / {total} envelope bytes. Whole content is not displayed before complete verification.', flush=True)
            finally:
                path.unlink(missing_ok=True)
            if assembled.eof:
                envelope = assembled.complete()
                request = dict(schema_version=1, id='owner-terminal-reopen', operation='reopen', source=envelope.decode('utf-8'),
                               expected_envelope_sha256=hashlib.sha256(envelope).hexdigest())
                binary = host.PinnedExecutable(Path(NATIVE))
                try:
                    command, payload = host.invocation(host.request(request))
                    state, output = host.run_process(binary, command, payload, threading.Event(), lambda _: None)
                finally:
                    binary.close()
                if state != 'completed' or not output:
                    raise ValueError('complete native envelope reopen did not finish')
                result = host.validate_result(request, output)
                print('Complete immutable envelope verified. Prior page authorization does not grant another read; already delivered data cannot be recalled.', flush=True)
                print(json.dumps(dict(binding=source['binding'], reference=source['operation']['expected'],
                    envelope_sha256=request['expected_envelope_sha256'], content=result['preview_content'],
                    publication_requested=False, export_requested=False, authority_returned=False), ensure_ascii=True, indent=2), flush=True)
                return 0
        raise ValueError('page journey exceeded its finite page count')
    except (KeyboardInterrupt, EOFError):
        print('\nRead interrupted. No publication or export was requested; partial assembly discarded. Native outstanding leases retain their own drainage obligations.', file=sys.stderr, flush=True)
        return 130
    finally:
        assembled.data.clear()


def recovery_request(source, *, retirement=False):
    """Bound public recovery DATA only; actual native canonicalization follows."""
    if retirement:
        if not isinstance(source, dict) or set(source) != {'input', 'expected_review_sha256'} or source['expected_review_sha256'] is not None:
            raise ValueError('retirement journey starts with a fresh protected inspection, not a supplied approval')
        source = source['input']
    fields = {'schema_version', 'login', 'admin', 'target_login', 'target',
        'independently_selected_origin_spki_sha256', 'request_namespace', 'key_role',
        'capsule_path', 'capsule_bytes', 'capsule_sha256', 'review'}
    if not isinstance(source, dict) or set(source) != fields or type(source['schema_version']) is not int or source['schema_version'] != 1:
        raise ValueError('exact native restore data required; no key, password or grant fields')
    for login, binding in (('login', 'admin'), ('target_login', 'target')):
        owner_request(dict(schema_version=1, login=source[login], binding=source[binding], operation={}))
    if source['admin']['installation'] != source['target']['installation']:
        raise ValueError('receiving Admin and target must select the same installation')
    if any(not exact_sha(source[key]) for key in ('capsule_sha256', 'independently_selected_origin_spki_sha256')):
        raise ValueError('independently selected origin and exact encrypted capsule digests required')
    if not isinstance(source['request_namespace'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', source['request_namespace']) or source['key_role'] not in ('owner', 'offline-admin'):
        raise ValueError('explicit restore namespace and decryption role required')
    if not isinstance(source['capsule_path'], str) or not source['capsule_path'].startswith('/') or '\0' in source['capsule_path'] or len(source['capsule_path'].encode()) > 4096 or type(source['capsule_bytes']) is not int or not 20 < source['capsule_bytes'] <= 128*1024*1024:
        raise ValueError('bounded absolute native capsule path and exact byte count required')
    if source['review'] is not None:
        restore_review(source['review'], source)
    if retirement and source['review'] is None:
        raise ValueError('retirement requires the original retained batch review')
    if len(encoded(source)) > MAX_RECOVERY_REQUEST:
        raise ValueError('restore data exceeds native bound')
    return source


def restore_review(review, source):
    fields = ('schema_version', 'profile', 'origin', 'target', 'archive_sha256', 'archive_bytes',
        'manifest_sha256', 'origin_head_sha256', 'workflow_sha256', 'request_namespace',
        'published_outcomes', 'inert_committed_outcomes', 'inert_pending_directories',
        'inert_quarantined_directories', 'planned_storage_bytes', 'mappings_sha256', 'steps', 'review_sha256')
    if not isinstance(review, dict) or set(review) != set(fields) or type(review['schema_version']) is not int or (review['schema_version'], review['profile']) not in ((1, 'luma-fresh-owner-content-restore-v1'), (2, 'luma-fresh-owner-content-restore-v2')):
        raise ValueError('closed native restore review required')
    owner_request(dict(schema_version=1, login=source['target_login'], binding=review['origin'], operation={}))
    if not same_data(review['target'], source['target']) or review['origin']['installation'] == source['target']['installation'] or review['origin']['owner'] == source['target']['owner'] or review['request_namespace'] != source['request_namespace']:
        raise ValueError('restore review substitutes origin, fresh target or request namespace')
    for name in ('archive_sha256', 'manifest_sha256', 'origin_head_sha256', 'workflow_sha256', 'mappings_sha256', 'review_sha256'):
        if not exact_sha(review[name]):
            raise ValueError('restore review contains invalid digest')
    limits = {'archive_bytes': (21, 128*1024*1024), 'published_outcomes': (1, 256),
        'inert_committed_outcomes': (0, 256), 'inert_pending_directories': (0, 16),
        'inert_quarantined_directories': (0, 16), 'planned_storage_bytes': (8192, 64*1024*1024)}
    if any(type(review[key]) is not int or not low <= review[key] <= high for key, (low, high) in limits.items()) or review['published_outcomes']+review['inert_committed_outcomes'] > 256 or review['planned_storage_bytes'] < review['published_outcomes']*8192:
        raise ValueError('restore review counts exceed fixed native bounds')
    if not isinstance(review['steps'], list) or len(review['steps']) != review['published_outcomes']:
        raise ValueError('restore review is missing exact chronological steps')
    previous = 0
    prefix = source['request_namespace']+'.'
    total = review['published_outcomes']+review['inert_committed_outcomes']
    for step in review['steps']:
        if not isinstance(step, dict) or set(step) != {'request_id', 'review_sha256'} or not isinstance(step['request_id'], str) or not step['request_id'].startswith(prefix) or not exact_sha(step['review_sha256']):
            raise ValueError('restore review substitutes a chronological request')
        suffix = step['request_id'][len(prefix):]
        if not re.fullmatch(r'[1-9][0-9]{0,2}', suffix):
            raise ValueError('restore outcome sequence is not canonical bounded decimal')
        sequence = int(suffix)
        if not previous < sequence <= total:
            raise ValueError('restore outcome sequences must increase within published plus inert history')
        previous = sequence
    canonical = {key: review[key] for key in fields}
    canonical['review_sha256'] = ''
    if len(encoded(review)) > 65536 or hashlib.sha256(encoded(canonical)).hexdigest() != review['review_sha256']:
        raise ValueError('restore review self-commitment differs; a matching checksum is not authority')
    return review


def recovery_canonical_response(value, output):
    if not isinstance(output, bytes) or not 0 < len(output) <= 6*MAX_RECOVERY_REQUEST+16384:
        raise ValueError('public native recovery response exceeds bound')
    result = strict_json(output)
    retirement = value['operation'] == 'retire-journey'
    flags = ('protected_review_authenticated', 'private_authority_read', 'admin_authenticated',
        'grant_issued', 'owner_marked_unavailable', 'authority_returned') if retirement else (
        'private_key_read', 'archive_decrypted', 'target_content_changed', 'grant_issued', 'authority_returned')
    fields = {'schema_version', 'canonical_request', *flags, *({'request_sha256', 'phase', 'usage'} if retirement else {'semantic_request_sha256'})}
    if not isinstance(result, dict) or set(result) != fields or type(result['schema_version']) is not int or result['schema_version'] != 1 or any(result[key] is not False for key in flags):
        raise ValueError('public recovery preparation claims authority or unknown fields')
    canonical = result['canonical_request']
    if not isinstance(canonical, str) or not 0 < len(canonical.encode()) <= MAX_RECOVERY_REQUEST or not same_data(strict_json(canonical), strict_json(value['request'])):
        raise ValueError('native recovery canonicalizer substituted original data')
    source = strict_json(canonical)
    if retirement:
        if result['request_sha256'] != hashlib.sha256(canonical.encode()).hexdigest():
            raise ValueError('retirement request digest differs')
        phase = 'inspect-protected-retirement' if source['expected_review_sha256'] is None else 'recover-exact-protected-review'
        if result['phase'] != phase:
            raise ValueError('retirement preparation changes review phase')
        retirement_scope(result['usage'], source)
    else:
        normalized = dict(source, capsule_path='/runtime-original-snapshot/content-restore.cms')
        if result['semantic_request_sha256'] != hashlib.sha256(encoded(normalized)).hexdigest():
            raise ValueError('restore semantic data commitment differs')
    return canonical


def recovery_scope(usage, source, *, effect=False):
    write = source['review'] is not None
    expected = dict(action=('artifact.write' if write else 'resource.recover') if effect else 'file.read',
        selector=dict(kind=('artifact' if write else 'resource') if effect else 'file',
            id=('native-content-restore-write-v1' if write else 'native-content-restore-review-v1') if effect else 'native-content-restore-read-v1',
            generation=source['admin']['owner_generation']), input_bytes=source['capsule_bytes'],
        output_bytes=64*1024*1024 if effect and write else MAX_RECOVERY_OUTPUT,
        units=source['review']['published_outcomes'] if effect and write else 1)
    if not isinstance(usage, dict) or set(usage) != set(expected) or not isinstance(usage.get('selector'), dict) or set(usage['selector']) != {'kind', 'id', 'generation', 'digest'} or not exact_sha(usage['selector']['digest']):
        raise ValueError('closed finite restore scope required')
    selected = dict(usage, selector={key: item for key, item in usage['selector'].items() if key != 'digest'})
    if not same_data(selected, expected):
        raise ValueError('restore scope exceeds or substitutes its exact finite use')
    return usage


def retirement_scope(usage, request):
    recover = request['expected_review_sha256'] is not None
    normalized = dict(request['input'], capsule_path='/runtime-original-snapshot/content-restore.cms')
    wanted = request['expected_review_sha256'] if recover else hashlib.sha256(encoded([
        'luma-content-restore-retirement-inspection-v1', normalized])).hexdigest()
    expected = dict(action='resource.recover' if recover else 'file.read', selector=dict(
        kind='resource' if recover else 'file', id='content-restore-retire-v1' if recover else 'content-restore-retire-read-v1',
        generation=request['input']['admin']['owner_generation'], digest=wanted), input_bytes=0, output_bytes=8192, units=1)
    if not same_data(usage, expected):
        raise ValueError('retirement scope differs from exact original reviewed data')
    return usage


def recovery_arguments(command, login, path, *grants):
    counts = {'content-restore-proposal': 0, 'content-restore-review': 2, 'content-restore-apply': 2,
        'content-restore-retire-proposal': 0, 'content-restore-retire-inspect': 1, 'content-restore-retire': 1}
    if command not in counts or len(grants) != counts[command] or not isinstance(login, str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', login) or any(not isinstance(g, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', g) for g in grants) or len(set(grants)) != len(grants):
        raise ValueError('only fixed recovery commands with independent exact finite grants are allowed')
    return ['/usr/bin/sudo', '--', NATIVE, 'granted-run', command, login, *grants, str(path)]


def capture_recovery(command, source, path, *grants):
    return _capture_native(recovery_arguments(command, source['login'], path, *grants), MAX_RECOVERY_OUTPUT)


def recovery_proposal(source, output):
    value = strict_json(output)
    flags = ('private_key_read', 'archive_decrypted', 'target_content_changed', 'grant_issued', 'authority_returned')
    if not isinstance(value, dict) or set(value) != {'schema_version', 'request_sha256', 'read_usage', 'effect_usage', *flags} or type(value['schema_version']) is not int or value['schema_version'] != 1 or any(value[key] is not False for key in flags):
        raise ValueError('restore proposal claims unobserved authentication or mutation')
    if value['request_sha256'] != hashlib.sha256(encoded(dict(source, capsule_path='/runtime-original-snapshot/content-restore.cms'))).hexdigest():
        raise ValueError('restore proposal substitutes its canonical request')
    reader = recovery_scope(value['read_usage'], source)
    effect = recovery_scope(value['effect_usage'], source, effect=True)
    if reader['selector']['digest'] != effect['selector']['digest']:
        raise ValueError('restore Read and effect select different exact requests')
    return value


def recovery_reviewed(source, output):
    value = strict_json(output)
    flags = dict(origin_signature_valid=True, archive_validated=True, decrypted_data_delivered=False,
        target_content_changed=False, restore_permitted=False, authority_returned=False,
        credentials_restored=False, encrypted_evidence_must_be_retained=True)
    if not isinstance(value, dict) or set(value) != {'schema_version', 'restore_review', 'custody_capacity_policy', *flags} or type(value['schema_version']) is not int or value['schema_version'] != 1 or any(value[key] is not expected for key, expected in flags.items()) or not isinstance(value['custody_capacity_policy'], dict):
        raise ValueError('actual native restore review differs or claims an effect')
    return restore_review(value['restore_review'], source)


def recovery_completed(source, output):
    value = strict_json(output)
    flags = dict(origin_signature_valid=True, credentials_restored=False, grants_restored=False,
        TPM_state_restored=False, original_encrypted_evidence_must_be_retained=True,
        authority_returned=False, production_qualified=False)
    if not isinstance(value, dict) or set(value) != {'schema_version', 'restore_review_sha256', 'published_outcomes',
        'custody_capacity_policy', 'current_state', 'encrypted_evidence_sha256', *flags} or type(value['schema_version']) is not int or value['schema_version'] != 1 or any(value[key] is not expected for key, expected in flags.items()):
        raise ValueError('native restore completion differs; do not infer rollback or success')
    review = source['review']
    state = value['current_state']
    if not isinstance(state, dict) or set(state) != {'binding', 'outcome_count', 'head_sha256', 'quarantine_sha256'} or not same_data(state['binding'], source['target']) or type(state['outcome_count']) is not int or state['outcome_count'] != review['published_outcomes'] or any(not exact_sha(state[key]) for key in ('head_sha256', 'quarantine_sha256')) or value['restore_review_sha256'] != review['review_sha256'] or type(value['published_outcomes']) is not int or value['published_outcomes'] != review['published_outcomes'] or value['encrypted_evidence_sha256'] != source['capsule_sha256'] or not isinstance(value['custody_capacity_policy'], dict):
        raise ValueError('native restore completion substitutes target, prefix, review or retained evidence')
    return value


def retain_recovery_request(path, canonical):
    """Durable ordinary-user DATA, no overwrite/secret/authority or auto-retry."""
    path = Path(path)
    data = canonical.encode('utf-8')
    if not path.is_absolute() or len(str(path).encode()) > 4096 or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,119}\.json', path.name) or not 0 < len(data) <= MAX_RECOVERY_REQUEST or path.parent.resolve(strict=True) != path.parent:
        raise ValueError('choose a new explicit canonical .json path for inert recovery data')
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(parent)
        if before.st_uid != os.getuid() or not stat.S_ISDIR(before.st_mode) or before.st_mode & 0o022:
            raise ValueError('resume data requires a private-owner non-writable-by-others directory')
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
            held = os.fstat(output.fileno())
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            identity = lambda m: (m.st_dev, m.st_ino, m.st_uid, m.st_nlink, m.st_mode, m.st_size, m.st_mtime_ns, m.st_ctime_ns)
            if held.st_uid != os.getuid() or held.st_nlink != 1 or stat.S_IMODE(held.st_mode) != 0o600 or held.st_size != len(data) or identity(held) != identity(named):
                raise ValueError('resume data changed while retaining it')
        os.fsync(parent)
        named_parent = path.parent.stat()
        if (before.st_dev, before.st_ino) != (named_parent.st_dev, named_parent.st_ino) or path.parent.resolve(strict=True) != path.parent:
            raise ValueError('resume parent changed; effect was not requested')
    finally:
        os.close(parent)
    return path


def recovery_grants():
    reader = grant_selection('Exact current Admin finite Read grant (q cancels): ')
    if reader is None:
        return None
    effect = grant_selection('Independent exact finite Recover/Write grant (q cancels): ')
    if effect is None:
        return None
    if reader == effect:
        raise ValueError('Read and effect grants must be independent')
    return reader, effect


def restore_journey(value, directory):
    """Original native Admin guards own decryption/C publication, never Python."""
    recovery_request(strict_json(value['request']))
    effect_started = False
    completion_observed = False
    retained = None
    try:
        print('Encrypted fresh-owner restore / exact-prefix resume. Standard native session remains 30 seconds; no Export or extended-session reuse. No credential, grant or TPM state is restored. Private PKCS8 entry belongs ONLY to native hidden /dev/tty; never paste it here or into the browser.', flush=True)
        canonical, _ = canonical_native_request(value)
        source = strict_json(canonical)
        if source['review'] is None:
            with request_stage(directory, canonical) as request:
                info = recovery_proposal(source, capture_recovery('content-restore-proposal', source, request))
                print('Fresh review requires these exact Admin Read + Recover scopes. They are DATA, not issued grants:\n'+json.dumps(info, ensure_ascii=True), flush=True)
                grants = recovery_grants()
                if grants is None:
                    print('CANCELLED before decryption review. No restore publication was requested.', flush=True)
                    return 0
                print('Review running in the original native PAM terminal. Native may request the explicitly selected recipient private key on its hidden terminal input. Ctrl+C stops observation; no publication is requested by this phase.', flush=True)
                review = recovery_reviewed(source, capture_recovery('content-restore-review', source, request, *grants))
            source = dict(source, review=review)
            value = dict(value, request=encoded(source).decode())
            canonical, _ = canonical_native_request(value)
            source = strict_json(canonical)
        else:
            print('Supplied review is inert resume DATA, not current permission or proof of an intact prefix. Native will rebuild the plan and independently verify the genuine current C-selected prefix before publishing.', flush=True)
        print('Exact reviewed batch; retained non-publication evidence stays in the original encrypted capsule:\n'+json.dumps(source['review'], ensure_ascii=True), flush=True)
        with request_stage(directory, canonical) as request:
            info = recovery_proposal(source, capture_recovery('content-restore-proposal', source, request))
            print('Apply/resume needs a NEW independently selected Read + exact batch Write pair:\n'+json.dumps(info, ensure_ascii=True), flush=True)
            grants = recovery_grants()
            if grants is None:
                print('CANCELLED before apply. No restore publication was requested by this journey.', flush=True)
                return 0
            wanted = 'restore:'+source['review']['review_sha256']
            if terminal_line('Type '+wanted+' to approve exactly this batch; q cancels: ', 128) != wanted:
                print('CANCELLED before apply; exact batch approval was not given.', flush=True)
                return 0
            save = terminal_line('NEW absolute .json path for durable inert resume/retirement data (q cancels): ', 4096)
            if save == 'q':
                print('CANCELLED before apply; no publication requested.', flush=True)
                return 0
            print('Saving inert resume DATA before any apply. A failed save may leave an incomplete inert file at the selected path; it is never overwritten or accepted as authority.', flush=True)
            retained = retain_recovery_request(save, canonical)
            print('Exact inert resume request synchronized at '+json.dumps(str(retained), ensure_ascii=True)+'. Keep it AND the original encrypted capsule. It contains no key, password, grant or current permission. Native validates every fresh retry; no automatic retry/reset occurs.', flush=True)
            effect_started = True
            output = capture_recovery('content-restore-apply', source, request, *grants)
            completed = recovery_completed(source, output)
            completion_observed = True
            effect_started = False
            print('COMPLETED: actual native C-backed fresh-owner restore/prefix resume observed. Independent native output delivery checked the live session, exact grants, resource receipt and selected C state. This is not ongoing authority or final installed qualification.\n'+json.dumps(completed, ensure_ascii=True), flush=True)
            return 0
    except (Exception, KeyboardInterrupt):
        if completion_observed:
            print('COMPLETED native restore result was validated before terminal presentation failed/interrupted. Do not reinterpret this as cancellation or rollback. Retain the exact request and encrypted evidence; a fresh separately granted native read is required for current access.', flush=True)
        elif effect_started:
            print('UNCERTAIN / POSSIBLY PARTIAL: restore apply started but no complete validated result was observed. Anchored published prefix or pending evidence may remain. Do not infer rollback, reset, or retry automatically. Retained inert request: '+json.dumps(str(retained), ensure_ascii=True)+'. Reopen it explicitly for genuine native exact-prefix resume, or use reviewed protected retirement for a damaged target.', flush=True)
        else:
            print('REFUSED / CANCELLED before restore apply. No publication was requested by this journey; pre-existing native state is not inferred or repaired.', flush=True)
        return 1


def retirement_reviewed(source, output):
    value = strict_json(output)
    flags = ('owner_marked_unavailable', 'content_bytes_changed', 'TPM_extended', 'authority_returned')
    fields = ('schema_version', 'purpose', 'installation', 'binding', 'batch_review_sha256',
        'capsule_sha256', 'origin_spki_sha256', 'start_sha256', 'checkpoint_head', 'state', 'disposition')
    if not isinstance(value, dict) or set(value) != {'schema_version', 'review', 'review_sha256', *flags} or type(value['schema_version']) is not int or value['schema_version'] != 1 or any(value[key] is not False for key in flags):
        raise ValueError('protected retirement inspection claims mutation')
    review = value['review']
    if not isinstance(review, dict) or set(review) != set(fields) or type(review['schema_version']) is not int or review['schema_version'] != 1 or review['purpose'] != 'luma-content-restore-terminal-disposition-v1' or review['installation'] != source['target']['installation'] or not same_data(review['binding'], source['target']) or review['batch_review_sha256'] != source['review']['review_sha256'] or review['capsule_sha256'] != source['capsule_sha256'] or review['origin_spki_sha256'] != source['independently_selected_origin_spki_sha256'] or review['disposition'] != 'mark-owner-generation-unavailable-preserve-all-published-pending-quarantine-bytes':
        raise ValueError('protected retirement substitutes the exact target or original batch')
    state = review['state']
    if not isinstance(state, dict) or set(state) != {'binding', 'outcome_count', 'head_sha256', 'quarantine_sha256'} or not same_data(state['binding'], source['target']) or type(state['outcome_count']) is not int or not 0 <= state['outcome_count'] <= source['review']['published_outcomes'] or any(not exact_sha(state[key]) for key in ('head_sha256', 'quarantine_sha256')) or any(not exact_sha(review[key]) for key in ('start_sha256', 'checkpoint_head')) or not exact_sha(value['review_sha256']):
        raise ValueError('protected retirement state or exact review commitment differs')
    canonical = {key: review[key] for key in fields}
    canonical['state'] = {key: state[key] for key in ('binding', 'outcome_count', 'head_sha256', 'quarantine_sha256')}
    if hashlib.sha256(encoded(canonical)).hexdigest() != value['review_sha256']:
        raise ValueError('protected retirement exact canonical commitment differs')
    return value


def retirement_completed(source, wanted, output):
    value = strict_json(output)
    flags = dict(owner_marked_unavailable=True, content_bytes_changed=False, published_records_rolled_back=False,
        pending_evidence_removed=False, damaged_data_healed=False,
        new_restore_requires_independently_provisioned_fresh_owner_binding=True, authority_returned=False, production_qualified=False)
    if not isinstance(value, dict) or set(value) != {'schema_version', 'binding', 'review_sha256', 'checkpoint_head', *flags} or type(value['schema_version']) is not int or value['schema_version'] != 1 or any(value[key] is not expected for key, expected in flags.items()) or not same_data(value['binding'], source['target']) or value['review_sha256'] != wanted or not exact_sha(value['checkpoint_head']):
        raise ValueError('retirement completion is not the exact preserved owner-generation disposition')
    return value


def retire_journey(value, directory):
    recovery_request(strict_json(value['request']), retirement=True)
    effect_started = False
    completion_observed = False
    retained = None
    try:
        print('Protected restore retirement. This marks ONLY the exact damaged owner-generation unavailable. It does not heal, reset, adopt, delete evidence, roll back published records or provision another account. Original Admin PAM and fresh finite grants remain mandatory.', flush=True)
        canonical, _ = canonical_native_request(value)
        request = strict_json(canonical)
        source = request['input']
        with request_stage(directory, canonical) as staged:
            print('Exact inspection scope DATA (not authority):\n'+json.dumps(retirement_scope_data(request), ensure_ascii=True), flush=True)
            reader = grant_selection('Exact current Admin retirement Read grant (q cancels): ')
            if reader is None:
                print('CANCELLED before protected retirement inspection; no disposition requested.', flush=True)
                return 0
            checked = retirement_reviewed(source, capture_recovery('content-restore-retire-inspect', source, staged, reader))
        wanted = checked['review_sha256']
        print('Actual protected target/prefix review:\n'+json.dumps(checked, ensure_ascii=True), flush=True)
        request = dict(request, expected_review_sha256=wanted)
        value = dict(value, request=encoded(request).decode())
        canonical, _ = canonical_native_request(value)
        request = strict_json(canonical)
        print('Separate exact Recover scope DATA:\n'+json.dumps(retirement_scope_data(request), ensure_ascii=True), flush=True)
        recover = grant_selection('Fresh exact Admin Recover grant (q cancels): ')
        if recover is None:
            print('CANCELLED before retirement; no disposition requested.', flush=True)
            return 0
        if recover == reader:
            raise ValueError('retirement Read and Recover grants must be independent')
        if terminal_line('Type retire:'+wanted+' to mark ONLY this owner-generation unavailable; q cancels: ', 128) != 'retire:'+wanted:
            print('CANCELLED before retirement; no disposition requested.', flush=True)
            return 0
        save = terminal_line('NEW absolute .json path for durable inert exact retirement review (q cancels): ', 4096)
        if save == 'q':
            print('CANCELLED before retirement; no disposition requested.', flush=True)
            return 0
        print('Saving inert exact retirement DATA before mutation. A failed save may leave an incomplete inert file; it is never overwritten or accepted as authority.', flush=True)
        retained = retain_recovery_request(save, canonical)
        with request_stage(directory, canonical) as staged:
            effect_started = True
            completed = retirement_completed(source, wanted, capture_recovery('content-restore-retire', source, staged, recover))
            completion_observed = True
            effect_started = False
        print('COMPLETED: genuine protected owner-generation retirement observed; all published/pending/quarantine bytes retained, not healed or rolled back. A new restore requires independently provisioned fresh binding and new grants.\n'+json.dumps(completed, ensure_ascii=True), flush=True)
        return 0
    except (Exception, KeyboardInterrupt):
        if completion_observed:
            print('COMPLETED protected retirement result was validated before terminal presentation failed/interrupted. The exact owner-generation remains unavailable; this is not cancellation, healing or rollback. All forensic evidence must remain retained.', flush=True)
        elif effect_started:
            print('UNCERTAIN: protected retirement started but its complete result was not observed. No automatic retry, reset, healing or evidence deletion. Retained exact inert request: '+json.dumps(str(retained), ensure_ascii=True)+'. Use genuine native protected status/review before further action.', flush=True)
        else:
            print('REFUSED / CANCELLED before protected retirement mutation. No disposition was requested by this journey.', flush=True)
        return 1


def retirement_scope_data(request):
    recover = request['expected_review_sha256'] is not None
    normalized = dict(request['input'], capsule_path='/runtime-original-snapshot/content-restore.cms')
    usage = dict(action='resource.recover' if recover else 'file.read', selector=dict(kind='resource' if recover else 'file',
        id='content-restore-retire-v1' if recover else 'content-restore-retire-read-v1',
        generation=request['input']['admin']['owner_generation'], digest=request['expected_review_sha256'] if recover else hashlib.sha256(encoded([
            'luma-content-restore-retirement-inspection-v1', normalized])).hexdigest()), input_bytes=0, output_bytes=8192, units=1)
    return retirement_scope(usage, request)


def launch(value):
    value = proposal(value)
    directory = runtime()
    for path, maximum in [(HELPER, 128 * 1024), (NATIVE, 128 * 1024 * 1024), ('/usr/bin/kgx', 16 * 1024 * 1024), ('/usr/bin/sudo', 16 * 1024 * 1024)]:
        protected(path, maximum, sudo=(path == '/usr/bin/sudo'))
    # A hard closed bound prevents an idle GUI from accumulating unbounded
    # unconsumed proposals; stale files require explicit user disposition.
    if len(list(itertools.islice(directory.iterdir(), 16))) >= 16:
        raise ValueError('terminal proposal capacity reached')
    path = directory / (uuid.uuid4().hex + '.json')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        data = encoded(value)
        if len(data) > MAX_STAGE:
            raise ValueError('terminal proposal transport bound exceeded')
        with os.fdopen(descriptor, 'wb') as output:
            descriptor = -1
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        # No shell, caller-selected executable, captured password or privileged
        # WebKit callback. Native command output remains in the real terminal.
        subprocess.Popen(['/usr/bin/kgx', '--', '/usr/bin/python3', '-I', HELPER, '--terminal', str(path)],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         close_fds=True, start_new_session=True)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return {'state': 'terminal-launched', 'authenticated': False, 'committed': False, 'completion_observed': False}


def held_read(path, directory):
    if path.parent != directory or not re.fullmatch(r'[0-9a-f]{32}\.json', path.name):
        raise ValueError('invalid exact terminal staging path')
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= MAX_STAGE:
            raise ValueError('unsafe bounded terminal staging file')
        data = bytearray()
        while len(data) <= MAX_STAGE:
            block = os.read(descriptor, min(65536, MAX_STAGE + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        identity = lambda m: (m.st_dev,m.st_ino,m.st_mode,m.st_uid,m.st_gid,m.st_nlink,m.st_size,m.st_mtime_ns,m.st_ctime_ns)
        if len(data) != before.st_size or identity(before) != identity(os.fstat(descriptor)) or identity(before) != identity(path.lstat()):
            raise ValueError('terminal staging changed during capture')
        return proposal(strict_json(data)), identity(before)
    finally:
        os.close(descriptor)


def canonical_response(value, output):
    if not isinstance(output, bytes) or not 0 < len(output) <= MAX_STAGE:
        raise ValueError('native canonical response exceeds bound')
    response = strict_json(output)
    flags = ('owner_authenticated', 'authority_returned', 'committed', 'certified', 'gate_closing')
    if not isinstance(response, dict) or set(response) != {'schema_version', 'result', *flags} or type(response['schema_version']) is not int or response['schema_version'] != 1 or any(response.get(flag) is not False for flag in flags):
        raise ValueError('canonical request response claims authority or unknown fields')
    result = response['result']
    expected = 'office-request' if value['operation'].startswith('office-') else 'native-request'
    if not isinstance(result, dict) or set(result) != {'operation', 'request_sha256', 'canonical_request', 'private_content_read'} or result['operation'] != expected or result['private_content_read'] is not False:
        raise ValueError('native canonical request response schema differs')
    canonical = result['canonical_request']
    if not isinstance(canonical, str) or not 0 < len(canonical.encode('utf-8')) <= MAX_REQUEST:
        raise ValueError('native canonicalizer response refused')
    # Sorted serialized trees distinguish true from 1, unlike Python ==, and
    # permit only field ordering/insignificant input whitespace to change.
    tree = lambda text: json.dumps(strict_json(text), sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
    if result['request_sha256'] != hashlib.sha256(canonical.encode('utf-8')).hexdigest() or tree(canonical) != tree(value['request']):
        raise ValueError('canonical native request substituted source or identity')
    return canonical


def export_pdf(value, arguments):
    """No-overwrite ordinary-user sink; errors retain an explicit partial file.

    Only the native original PAM/Read/Export channel authorizes/delivers bytes.
    A Python file/hash is not custody, publication or production qualification.
    """
    target = Path(value['output_path'])
    parent = target.parent
    if parent.resolve(strict=True) != parent:
        raise ValueError('PDF target parent must be canonical')
    uid = os.getuid()
    for ancestor in parent.parents:
        item = ancestor.stat()
        if not stat.S_ISDIR(item.st_mode) or item.st_uid not in (0, uid) or item.st_mode & 0o022:
            raise ValueError('PDF target ancestor is not protected')
    item = parent.stat()
    if not stat.S_ISDIR(item.st_mode) or item.st_uid != uid or item.st_mode & 0o022:
        raise ValueError('PDF target must be a protected directory owned by this human')
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    temporary = '.' + target.name + '.luma-export-' + uuid.uuid4().hex + '.partial'
    try:
        try:
            os.stat(target.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError('PDF target already exists; no export started')
        descriptor = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        with os.fdopen(descriptor, 'w+b') as output:
            result = subprocess.call(arguments, stdout=output, close_fds=True)
            if result != 0:
                print('Native Office export did not complete. Its ordinary-user .partial file is retained; inspect the actual native outcome before retry.', file=sys.stderr)
                return result
            output.flush()
            os.fsync(output.fileno())
            metadata = os.fstat(output.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600 or not 16 <= metadata.st_size <= 16*1024*1024:
                raise ValueError('actual exported PDF inode or size refused; partial retained')
            output.seek(0)
            if output.read(5) != b'%PDF-':
                raise ValueError('native export did not deliver PDF; partial retained')
            output.seek(max(0, metadata.st_size-1024))
            if b'%%EOF' not in output.read(1024):
                raise ValueError('native PDF framing incomplete; partial retained')
            current = parent.stat()
            if (current.st_dev,current.st_ino) != (os.fstat(directory).st_dev,os.fstat(directory).st_ino):
                raise ValueError('PDF target directory changed; partial retained')
            named = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
            if (named.st_dev,named.st_ino,named.st_size,named.st_mode,named.st_uid,named.st_nlink) != (metadata.st_dev,metadata.st_ino,metadata.st_size,metadata.st_mode,metadata.st_uid,metadata.st_nlink):
                raise ValueError('PDF partial was substituted before delivery')
            os.link(temporary,target.name,src_dir_fd=directory,dst_dir_fd=directory,follow_symlinks=False)
            os.fsync(directory)
            os.unlink(temporary,dir_fd=directory)
            os.fsync(directory)
        print('Native PDF export delivered to the explicitly selected new file and synchronized. No production qualification is inferred.', flush=True)
        return 0
    finally:
        os.close(directory)


def terminal(path):
    directory = runtime()
    value, identity = held_read(path, directory)
    # The native canonicalizer is unprivileged and authorizes nothing. It
    # selects the same exact typed Input encoding the root launcher captures.
    protected(NATIVE, 128 * 1024 * 1024)
    request_path = directory / (uuid.uuid4().hex + '.request')
    try:
        if value['operation'] == 'conversation-journey':
            return conversation_journey(value, directory)
        if value['operation'] == 'collection-journey':
            return workspace_controller('collections').journey(types.SimpleNamespace(**globals()), value, directory)
        if value['operation'] == 'speech-journey':
            return workspace_controller('speech').transcription_journey(types.SimpleNamespace(**globals()), value, directory)
        if value['operation'] == 'capture-reference-journey':
            return workspace_controller('grounding').journey(types.SimpleNamespace(**globals()), value, directory)
        if value['operation'] == 'lifecycle-journey':
            return workspace_controller('lifecycle').journey(types.SimpleNamespace(**globals()), value, directory)
        if value['operation'] == 'editor-journey':
            return workspace_controller('editor').journey(types.SimpleNamespace(**globals()), value, directory)
        if value['operation'] == 'restore-journey':
            return restore_journey(value, directory)
        if value['operation'] == 'retire-journey':
            return retire_journey(value, directory)
        if value['operation'] == 'workflow-journey':
            print('Luma native managed workflow. Passwords remain with original PAM in this terminal; no session, grant or supplied receipt is imported.', flush=True)
            return workflow_journey(value, directory)
        if value['operation'] == 'search-journey':
            print('Luma native discovery. Original PAM, current finite grants and private results remain only in this terminal; search hits never confer another Read.', flush=True)
            return discovery_journey(value, directory)
        if value['operation'] == 'envelope-read':
            return owner_read_journey(value, directory)
        if value['operation'] == 'paged-read':
            print('Luma exact owner read. Passwords belong only to original native PAM in this terminal. Each page needs its own exact finite Read grant; q stops before that page.', flush=True)
            return paged_read(value, directory)
        # Canonicalizer prints its closed contract response, not a bare Input.
        canonical, _ = canonical_native_request(value)
        value = dict(value, request=canonical)
        proposal(value)
        descriptor = os.open(request_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(canonical.encode('utf-8'))
            output.flush()
            os.fsync(output.fileno())
        print('Luma native owner operation. Enter passwords only in this terminal.\nSudo transports the fixed executor; original PAM and finite grants authorize the operation.\nIf interrupted, inspect the exact native checkpoint before any retry.', flush=True)
        arguments = terminal_arguments(value, request_path)
        return export_pdf(value, arguments) if value['operation'] == 'office-export' else subprocess.call(arguments, close_fds=True)
    finally:
        request_path.unlink(missing_ok=True)
        try:
            current = path.lstat()
            observed = (current.st_dev,current.st_ino,current.st_mode,current.st_uid,current.st_gid,current.st_nlink,current.st_size,current.st_mtime_ns,current.st_ctime_ns)
            if observed == identity:
                path.unlink()
        except FileNotFoundError:
            pass


if __name__ == '__main__':
    try:
        if not sys.flags.isolated or len(sys.argv) != 3 or sys.argv[1] != '--terminal':
            raise ValueError('fixed isolated terminal entry required')
        raise SystemExit(terminal(Path(sys.argv[2])))
    except Exception:
        print('Native owner ceremony refused; no completion or custody state is inferred.', file=sys.stderr)
        raise SystemExit(1)
