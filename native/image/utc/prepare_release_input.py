#!/usr/bin/env python3
"""Retrieve the exact independently pinned UTC candidate without replacing inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import urllib.parse
import urllib.request

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
    output = output.resolve(strict=True)
    if not output.is_dir() or output.is_symlink():
        raise ValueError('UTC context must already be a protected build directory')
    target = output / 'chrony-4.9.tar.gz'
    provenance = output / 'chrony-4.9.provenance.json'
    if target.exists() or target.is_symlink() or provenance.exists() or provenance.is_symlink():
        raise ValueError('UTC dependency inputs must be new; preserve any existing evidence')
    if cached is not None:
        m = cached.lstat()
        if not stat.S_ISREG(m.st_mode) or not 0 < m.st_size <= LIMIT:
            raise ValueError('cached UTC dependency is not bounded regular data')
        source = cached.open('rb')
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
    record = {'schema_version': 1, 'upstream': 'chrony', 'version': '4.9', 'url': URL,
              'sha256': SHA256, 'bytes': size,
              'source_review': 'fixed-provider-NTS-good-sample-hook-and-closed-seccomp-candidate',
              'qualification': 'native-image-network-clock-and-confinement-testing-required',
              'signature_verified': False}
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
