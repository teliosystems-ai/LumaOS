#!/usr/bin/env python3
"""Mechanically prepare a new pinned chrony fixture; never modify a source checkout.

GPL-2.0-only hook/publisher code is linked into upstream GPL-2.0-only chrony.
This baseline is NOT a selected security-qualified production dependency.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import stat

COMMIT = '120dfb8b36b942c31ddfc0220ca1475159ac5031'
ARCHIVE_SHA256 = 'd168e1cc284c16941c114929bf015acee8d7993e2c705ce53f97304b7f5c01b8'
PINS = {
    'ntp_core.c': 'c67de6aaa2a0a0aa1edc4098e559e7889cbfc5864d896b07cb0071ffaa4e6644',
    'ntp_auth.c': 'ab413ce2b12e6c929edd06645580fab0768c9ad7e0c792b450178f68a7ecedb4',
    'nts_ntp_client.c': '6d9a45112d3fd9643b88316e708ca0738f88b702c5eb46e7823deea5888e2345',
    'nts_ke_session.c': 'c14550e4fc40c045f404ee9df7052809413555b651777ba211eff4e5ebc7abc0',
    'Makefile.in': '17224c3c9aca09ae665c8e389d81349b0dfca17e3c2791eb9fac3f1fbad2a820',
}


def once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('upstream anchor changed or duplicated: ' + before[:80])
    return text.replace(before, after, 1)


def prepare(source, output):
    source = source.resolve(strict=True)
    if output.exists() or output.is_symlink():
        raise ValueError('fixture destination must be new')
    output = output.resolve()
    if output.is_relative_to(source) or source.is_relative_to(output):
        raise ValueError('fixture must not overlap upstream source')
    # The archive digest must ALSO be verified by the caller before extraction.
    for name, expected in PINS.items():
        path = source / name
        if not stat.S_ISREG(path.lstat().st_mode) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('upstream source pin mismatch: ' + name)
    for path in source.rglob('*'):
        if not (path.is_file() or path.is_dir()) or path.is_symlink():
            raise ValueError('upstream fixture refuses special files or links')
    shutil.copytree(source, output)
    core = (output / 'ntp_core.c').read_text()
    core = once(core, '#include "ntp_auth.h"', '#include "ntp_auth.h"\n#include "chrony_hook.h"')
    core = once(core, 'struct NCR_Instance_Record {', 'struct NCR_Instance_Record {\n  unsigned luma_operator;')
    core = once(core, '  handle_slew(NULL, NULL, 0.0, 0.0, LCL_ChangeUnknownStep, NULL);',
                '  handle_slew(NULL, NULL, 0.0, 0.0, LCL_ChangeUnknownStep, NULL);\n  LUH_Initialise();')
    core = once(core, '  LCL_RemoveParameterChangeHandler(handle_slew, NULL);',
                '  LUH_Finalise();\n  LCL_RemoveParameterChangeHandler(handle_slew, NULL);')
    core = once(core, '  result->interleaved = params->interleaved;',
                '  result->luma_operator = LUH_Register(result, name, params->nts &&\n'
                '      result->mode == MODE_CLIENT && params->offset == 0.0 &&\n'
                '      params->cert_set == 0 && !params->copy && CNF_GetNoCertTimeCheck() == 0);\n'
                '  result->interleaved = params->interleaved;')
    core = once(core, 'NCR_DestroyInstance(NCR_Instance instance)\n{',
                'NCR_DestroyInstance(NCR_Instance instance)\n{\n'
                '  LUH_Destroy(instance, instance->luma_operator);')
    core = once(core, 'NCR_ResetInstance(NCR_Instance instance)\n{',
                'NCR_ResetInstance(NCR_Instance instance)\n{\n'
                '  LUH_Lose(instance->luma_operator);')
    core = once(core, '  NTP_Sample filtered_sample;\n',
                '  NTP_Sample filtered_sample;\n\n  if (!sample) LUH_Lose(inst->luma_operator);\n')
    core = once(core, '  if (valid_packet) {\n',
                '  if (valid_packet) {\n    LUH_Leap(inst->luma_operator, pkt_leap == LEAP_Normal);\n')
    core = once(core, '    if (good_packet) {\n      /* Adjust the polling interval, accumulate the sample, etc. */',
                '    if (good_packet) {\n'
                '      LUH_Good(inst->luma_operator, &sample, pkt_leap == LEAP_Normal);\n'
                '      /* Adjust the polling interval, accumulate the sample, etc. */')
    (output / 'ntp_core.c').write_text(core)
    makefile = (output / 'Makefile.in').read_text()
    makefile = once(makefile, 'OBJS = array.o cmdparse.o', 'OBJS = publisher.o chrony_hook.o array.o cmdparse.o')
    (output / 'Makefile.in').write_text(makefile)
    assets = Path(__file__).resolve().parent
    for name in ('publisher.c', 'publisher.h', 'chrony_hook.c', 'chrony_hook.h'):
        shutil.copyfile(assets / name, output / name)
    policy = (assets / 'approved-policy.json').read_bytes()
    digest = hashlib.sha256(b'luma-native-approved-utc-policy-v1\0' + policy).digest()
    (output / 'luma_policy_digest.h').write_text(
        '/* Generated fixed policy byte digest; not a signature. */\n'
        'static const unsigned char luma_policy_digest[32] = {' +
        ','.join(str(b) for b in digest) + '};\n')
    manifest = {'schema_version': 1, 'upstream_commit': COMMIT,
                'upstream_archive_sha256': ARCHIVE_SHA256, 'policy_digest': digest.hex(),
                'files': {name: hashlib.sha256((output / name).read_bytes()).hexdigest()
                          for name in (*PINS, 'publisher.c', 'publisher.h', 'chrony_hook.c',
                                       'chrony_hook.h', 'luma_policy_digest.h')}}
    (output / 'luma-hook-inputs.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    prepare(args.source, args.output)
