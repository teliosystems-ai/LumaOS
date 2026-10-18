"""Actual WebKit load observations for one inert, bounded native document.

This is presentation only: a FINISHED signal is neither successful pixel
layout nor a content/workflow/custody receipt. In particular WebKit emits
FINISHED after load-failed; a failure can never become successful completion.
https://webkitgtk.org/reference/webkit2gtk/stable/signal.WebView.load-changed.html
"""
import hashlib
import json
import re
import time

MAX_HTML = 1024 * 1024
SECONDS = 15


def runtime_manifest(data, version):
    if not isinstance(data, bytes) or not 0 < len(data) <= 65536:
        raise ValueError('browser image manifest bound refused')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate browser image manifest field')
            result[key] = value
        return result
    value = json.loads(data.decode('utf-8'), object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite browser manifest')))
    fields = {'schema_version','profile','api_version','package_version','runtime_version','library','max_html_bytes','timeout_seconds','native_qualified'}
    if not isinstance(value,dict) or set(value)!=fields or type(value['schema_version']) is not int or value['schema_version']!=1 or value['profile']!='webkitgtk-native-document-presentation-v1' or value['api_version']!='4.1':
        raise ValueError('browser image manifest closed profile refused')
    if not isinstance(version,tuple) or len(version)!=3 or any(type(item) is not int or not 0<=item<=65535 for item in version) or version[0]!=2:
        raise ValueError('actual WebKitGTK runtime version refused')
    expected=value['runtime_version']
    if not isinstance(expected,list) or any(type(item) is not int for item in expected) or expected!=list(version):
        raise ValueError('actual WebKit runtime differs from pinned installed image')
    if type(value['max_html_bytes']) is not int or value['max_html_bytes']!=MAX_HTML or type(value['timeout_seconds']) is not int or value['timeout_seconds']!=SECONDS or value['native_qualified'] is not False:
        raise ValueError('browser bound/qualification substitution')
    package=value['package_version']
    if not isinstance(package,str) or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~_-]{0,127}',package):
        raise ValueError('invalid actual browser package version')
    pin=value['library']
    if not isinstance(pin,dict) or set(pin)!={'path','bytes','sha256'} or not isinstance(pin['path'],str) or not re.fullmatch(r'/usr/lib/x86_64-linux-gnu/libwebkit2gtk-4\.1\.so\.0\.[0-9]+\.[0-9]+',pin['path']):
        raise ValueError('browser library path outside fixed versioned SONAME profile')
    if type(pin['bytes']) is not int or not 0<pin['bytes']<=256*1024*1024 or not isinstance(pin['sha256'],str) or not re.fullmatch(r'[0-9a-f]{64}',pin['sha256']):
        raise ValueError('browser library pin bounds refused')
    return pin


class Presentation:
    def __init__(self, html, expected_sha256, version, dependency_sha256, *, clock=time.monotonic):
        if not isinstance(html, str) or not 0 < len(html.encode('utf-8')) <= MAX_HTML:
            raise ValueError('browser document bound refused')
        if not isinstance(expected_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', expected_sha256) or hashlib.sha256(html.encode('utf-8')).hexdigest() != expected_sha256:
            raise ValueError('browser document hash substitution')
        if not isinstance(version, tuple) or len(version) != 3 or any(type(number) is not int or not 0 <= number <= 65535 for number in version) or version[0] != 2:
            raise ValueError('fixed WebKitGTK 4.1 runtime tuple required')
        self.sha256 = expected_sha256
        if not isinstance(dependency_sha256,str) or not re.fullmatch(r'[0-9a-f]{64}',dependency_sha256):
            raise ValueError('actual image-pinned browser dependency hash required')
        self.dependency_sha256 = dependency_sha256
        self.version = version
        self.clock = clock
        self.deadline = clock() + SECONDS
        self.state = 'prepared'
        self.reason = None
        self.committed = False
        self.finished = False
        self.stop_requested = False
        self.termination_observed = False

    def started(self):
        if self.state != 'prepared':
            self.failed('unexpected-navigation')
            return
        self.state = 'loading'

    def commit(self):
        if self.state != 'loading' or self.stop_requested:
            self.failed('unexpected-commit')
            return
        self.committed = True
        self.state = 'committed'

    def failed(self, reason):
        if reason not in ('load-failed', 'unexpected-navigation', 'unexpected-commit', 'web-process-terminated', 'resource-refused'):
            raise ValueError('unsupported observed browser failure')
        self.state = 'failed'
        self.reason = reason

    def finish(self):
        self.finished = True
        if self.state == 'committed' and self.committed and not self.stop_requested and self.clock() < self.deadline:
            self.state = 'loaded'
        elif self.state not in ('failed', 'terminated'):
            self.state = 'stopped-unconfirmed'

    def request_stop(self, reason):
        if reason not in ('human-cancel', 'deadline', 'window-close'):
            raise ValueError('unsupported browser stop request')
        self.stop_requested = True
        self.reason = reason
        # The UI must call actual WebKit stop_loading/terminate_web_process.
        # Requesting either API is NOT evidence of observed cancellation/drain.
        if self.state not in ('failed', 'terminated'):
            self.state = 'stop-requested'

    def terminated(self):
        self.termination_observed = True
        self.state = 'terminated'
        if self.reason is None:
            self.reason = 'web-process-terminated'

    def receipt(self):
        return dict(schema_version=1, profile='webkitgtk-native-document-presentation-v1',
                    api_version='4.1', runtime_version=list(self.version), html_sha256=self.sha256,
                    dependency_sha256=self.dependency_sha256,
                    state=self.state, reason=self.reason, load_committed_observed=self.committed,
                    load_finished_observed=self.finished, stop_requested=self.stop_requested,
                    web_process_termination_observed=self.termination_observed,
                    pixels_verified=False, namespace_drained=False, owner_authenticated=False,
                    content_committed=False, workflow_completed=False, authority_returned=False,
                    native_qualified=False)
