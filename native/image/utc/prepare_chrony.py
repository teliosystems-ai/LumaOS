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
RELEASE = '4.9'
RELEASE_ARCHIVE_SHA256 = '4924c6f530105bcd5b9e9e33c48a2ae1bfd889222c8480bc41601110efc864d0'
RELEASE_PINS = {
    'ntp_core.c': 'ca206410bddc03c56996bba2bddbca2ab01029f9c5b619d4a55025f37d8c4ac0',
    'ntp_auth.c': 'b22f29ec98a42c63917fbc985dff21d2151f2e95a7525b78c2baf13626392574',
    'nts_ntp_client.c': 'f4e51bf8f1115ff745a661dbd22e4665071764cbf6149481c859481e07fccae0',
    'nts_ke_session.c': '37cd0927b28798d71049c37896f6a9034505b77ea5ac0d5b5bbf902af686920d',
    'Makefile.in': 'ebda5a94d5cb8dee9b264dc270e8d1613763e1a5dc8e1b95a69e8cfd4d637a2e',
    'tls_gnutls.c': '558749987c98db10696dc133d0f6a748f20b531d5dd45a8422b7c77178a166b6',
    'sys_linux.c': '5ac89030226212a0d826b4d564fdee761735b332ee74dc3f184608598157c5ae',
    'local.c': 'af16a2e6f46716f5bd4e405bdeebaecacbf15ca62476e153323e3836e2c7d3ac',
}


def once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('upstream anchor changed or duplicated: ' + before[:80])
    return text.replace(before, after, 1)


def prepare(source, output, release=False):
    source = source.resolve(strict=True)
    if output.exists() or output.is_symlink():
        raise ValueError('fixture destination must be new')
    output = output.resolve()
    if output.is_relative_to(source) or source.is_relative_to(output):
        raise ValueError('fixture must not overlap upstream source')
    # The archive digest must ALSO be verified by the caller before extraction.
    pins = RELEASE_PINS if release else PINS
    if release and (source / 'version.txt').read_bytes() != b'4.9\n':
        raise ValueError('release version differs from selected candidate')
    for name, expected in pins.items():
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
    anchor = 'OBJS = addrfilt.o array.o' if release else 'OBJS = array.o cmdparse.o'
    makefile = once(makefile, anchor, 'OBJS = publisher.o chrony_hook.o ' + anchor[len('OBJS = '):])
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
    manifest = {'schema_version': 1,
                **({'upstream_version': RELEASE, 'qualification': 'native-image-qualification-required'}
                   if release else {'upstream_commit': COMMIT}),
                'upstream_archive_sha256': RELEASE_ARCHIVE_SHA256 if release else ARCHIVE_SHA256,
                'policy_digest': digest.hex(),
                'files': {name: hashlib.sha256((output / name).read_bytes()).hexdigest()
                          for name in (*pins, 'publisher.c', 'publisher.h', 'chrony_hook.c',
                                       'chrony_hook.h', 'luma_policy_digest.h')}}
    (output / 'luma-hook-inputs.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--release-candidate', action='store_true')
    args = parser.parse_args()
    prepare(args.source, args.output, release=args.release_candidate)
