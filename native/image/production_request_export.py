#!/usr/bin/env python3
"""Export only a verified public production signing-request group, never keys."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import production_release
from assembly_storage import export_headroom


def export_request(out, phase, destination):
    out, destination = Path(out), Path(destination)
    request, files, pin = production_release.read_request(out, phase)
    raw = production_release.canonical(request)
    if hashlib.sha256(raw).hexdigest() != pin:
        raise ValueError('public signing request pin differs')
    names = ['request.json', *files]
    source = out/('production-' + phase + '-request')
    export_headroom(source, destination, names)
    for name, data in [('request.json', raw), *files.items()]:
        with (destination/name).open('xb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        if (destination/name).read_bytes() != data:
            raise ValueError('public signing-request export readback differs')
    descriptor = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {'schema_version': 1, 'phase': phase, 'request_sha256': pin,
            'signing_performed': False, 'private_keys_exported': False,
            'custody_verified': False, 'gate_closing': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('pcr', 'pe', 'release'))
    parser.add_argument('--out', type=Path, default=Path('/work/artifacts'),
                        choices=(Path('/work/artifacts'),))
    parser.add_argument('--destination', type=Path, default=Path('/out'), choices=(Path('/out'),))
    args = parser.parse_args()
    print(json.dumps(export_request(args.out, args.phase, args.destination)), flush=True)
