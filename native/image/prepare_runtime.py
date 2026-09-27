#!/usr/bin/env python3
"""Prepare a digest-verified runtime build input; never execute downloaded code."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import ssl
import time
import urllib.request


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith('https://'):
            raise ValueError('runtime redirect must remain HTTPS')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--cached',type=Path)
    args=parser.parse_args()
    lock=json.loads(Path(__file__).with_name('runtime-lock.json').read_text())
    out=args.output.resolve()
    if out.exists():raise SystemExit('runtime context must be new')
    out.mkdir(parents=True)
    target=out/'llama-runtime.tar.gz'
    source=None
    try:
        if args.cached:
            if args.cached.is_symlink() or not args.cached.is_file():raise ValueError('cache must be a regular archive')
            source=args.cached.open('rb')
        else:
            opener=urllib.request.build_opener(HTTPSRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
            source=opener.open(lock['url'],timeout=30)
        digest=hashlib.sha256();total=0;deadline=time.monotonic()+300
        with source, target.open('xb') as destination:
            while block:=source.read(1024*1024):
                total+=len(block)
                if total>lock['bytes'] or time.monotonic()>deadline:raise ValueError('runtime size/time bound exceeded')
                digest.update(block);destination.write(block)
        if total!=lock['bytes'] or digest.hexdigest()!=lock['sha256']:raise ValueError('runtime identity mismatch')
        shutil.copyfile(Path(__file__).with_name('runtime-lock.json'),out/'runtime-lock.json')
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    print(json.dumps({'verified_runtime':lock['sha256'],'bytes':total,'context':str(out)}),flush=True)


if __name__=='__main__':main()
