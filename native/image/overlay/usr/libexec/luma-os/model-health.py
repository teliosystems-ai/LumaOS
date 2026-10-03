#!/usr/bin/python3
"""Bounded installed-model listener readiness check; no inference or effects."""

import json
import os
import signal
import time
import urllib.error
import urllib.request


URL = 'http://127.0.0.1:8081/health'
DEADLINE_SECONDS = 300
MAX_REPLY = 4096


class HealthDeadline(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('model health redirect refused')


def parse_health(raw):
    if len(raw) > MAX_REPLY:
        return False

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate model health field')
            result[key] = value
        return result

    def nonfinite(value):
        raise ValueError('nonfinite model health field')

    try:
        result = json.loads(raw, object_pairs_hook=unique_object,
                            parse_constant=nonfinite)
    except (ValueError, UnicodeError, RecursionError):
        return False
    return isinstance(result, dict) and result.get('status') == 'ok'


def probe(timeout, opener):
    request = urllib.request.Request(URL, method='GET')
    with opener.open(request, timeout=timeout) as response:
        if response.status != 200:
            return False
        return parse_health(response.read(MAX_REPLY + 1))


def wait_ready(probe_once, seconds=DEADLINE_SECONDS, now=time.monotonic, sleep=time.sleep):
    deadline = now() + seconds
    while True:
        remaining = deadline - now()
        if remaining <= 0:
            raise HealthDeadline('model listener did not become healthy')
        try:
            if probe_once(min(3, remaining)):
                return
        except (OSError, urllib.error.URLError, ValueError, TimeoutError):
            pass
        remaining = deadline - now()
        if remaining > 0:
            sleep(min(2, remaining))


def main():
    if os.geteuid() != 0:
        raise SystemExit('model health check requires installed-root operator')
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise SystemExit('model health check cannot replace an active deadline')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def expired(signum, frame):
        raise HealthDeadline('model listener deadline exceeded')

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, DEADLINE_SECONDS + 1)
    try:
        wait_ready(lambda timeout: probe(timeout, opener))
    except HealthDeadline:
        raise SystemExit('model listener not ready within 300 seconds; manual operation remains available') from None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


if __name__ == '__main__':
    main()
