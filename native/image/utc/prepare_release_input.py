#!/usr/bin/env python3
"""Retrieve the exact independently pinned UTC candidate without replacing inputs."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import urllib.parse
import urllib.request

_spec = importlib.util.spec_from_file_location('luma_fixed_utc_release_verifier',
                                               Path(__file__).resolve().with_name('verify_release.py'))
verifier = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verifier)

URL = 'https://chrony-project.org/releases/chrony-4.9.tar.gz'
SHA256 = '4924c6f530105bcd5b9e9e33c48a2ae1bfd889222c8480bc41601110efc864d0'
LIMIT = 4 * 1024 * 1024


class SameOriginHTTPS(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlparse(newurl)
        if target.scheme != 'https' or target.hostname != 'chrony-project.org' or target.port not in (None, 443):
            raise ValueError('UTC dependency redirect departed the approved HTTPS origin')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def prepare(output, cached=None):
    if not output.is_dir() or output.is_symlink():
        raise ValueError('UTC context must already be a protected build directory')
    output = output.resolve(strict=True)
    target = output / 'chrony-4.9.tar.gz'
    signature = output / 'chrony-4.9.tar.gz.asc'
    provenance = output / 'chrony-4.9.provenance.json'
    if any(path.exists() or path.is_symlink() for path in (target, signature, provenance)):
        raise ValueError('UTC dependency inputs must be new; preserve any existing evidence')
    if cached is not None:
        import io
        source = io.BytesIO(verifier.bounded(cached, LIMIT))
    else:
        opener = urllib.request.build_opener(SameOriginHTTPS())
        source = opener.open(urllib.request.Request(URL, headers={'User-Agent': 'LumaOS-reviewed-UTC-builder/1'}), timeout=30)
    digest = hashlib.sha256()
    size = 0
    # Failed/uncertain input is preserved under its exact name. Never silently
    # delete and retry a failed release acquisition into the same build context.
    with source, target.open('xb') as file:
        while True:
            data = source.read(64 * 1024)
            if not data:
                break
            size += len(data)
            if size > LIMIT:
                raise ValueError('UTC dependency download exceeds its bound')
            digest.update(data)
            file.write(data)
        file.flush()
        os.fsync(file.fileno())
    if size == 0 or digest.hexdigest() != SHA256:
        raise ValueError('UTC dependency archive differs from independently retained pin')
    detached = verifier.bounded(Path(__file__).resolve().with_name('chrony-4.9.tar.gz.asc'),
                                verifier.SIGNATURE_LIMIT)
    with signature.open('xb') as file:
        file.write(detached)
        file.flush()
        os.fsync(file.fileno())
    record = verifier.verify(target)
    with provenance.open('x', encoding='utf-8', newline='\n') as file:
        json.dump(record, file, sort_keys=True, indent=2)
        file.write('\n')
        file.flush()
        os.fsync(file.fileno())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--cached', type=Path)
    args = parser.parse_args()
    prepare(args.output, args.cached)
