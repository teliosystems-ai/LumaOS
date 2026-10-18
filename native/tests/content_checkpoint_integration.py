#!/usr/bin/env python3
"""Exercise real Admin/resource/content isolation on fresh disposable TPMs.

This runner reuses the existing named isolated TPM entry rather than adding
ignored unit tests. Every scenario actually executes that test exactly once;
absent emulator prerequisites fail instead of reporting a skipped success.
"""
import json
import os
from pathlib import Path

from resource_checkpoint_integration import run_case


CASE = 'tpm::tests::emulator_admin_and_resource_authorities_have_independent_handles_and_secrets'
MODES = ('normal', 'lost-publication', 'lost-parent')


def main():
    if (not Path('/.dockerenv').is_file() or os.geteuid() != 0
            or any(Path(p).exists() for p in ('/dev/tpm0', '/dev/tpmrm0', '/var/run/docker.sock'))):
        raise SystemExit('fresh isolated root container without host TPM/docker socket required')
    if not os.environ.get('CARGO_TARGET_DIR'):
        raise SystemExit('explicit external build/cache target required; no code-tree artifacts')
    os.umask(0o077)
    prior = os.environ.get('LUMA_CONTENT_TPM_MODE')
    results = []
    try:
        for mode in MODES:
            os.environ['LUMA_CONTENT_TPM_MODE'] = mode
            result = run_case(CASE)
            result['content_scenario'] = mode
            results.append(result)
    finally:
        if prior is None:
            os.environ.pop('LUMA_CONTENT_TPM_MODE', None)
        else:
            os.environ['LUMA_CONTENT_TPM_MODE'] = prior
    print(json.dumps({
        'schema_version': 1,
        'status': 'CONTENT_CHECKPOINT_SOFTWARE_TPM_PASSED',
        'physical_tpm_used': False,
        'physical_qualification': False,
        'production_publication_enabled': False,
        'cases': results,
    }, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
