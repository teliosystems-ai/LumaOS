"""Actual C# constructor -> Python policy -> built Rust CLI, without authority."""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess


def verify(cases_path,expected,binary):
    spec=importlib.util.spec_from_file_location('workspace_interop_profile',Path(__file__).parents[1]/'image/windows_workspace.py')
    profile=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(profile)
    raw=Path(cases_path).read_bytes()
    profile.digest(expected)
    if hashlib.sha256(raw).hexdigest()!=expected:
        raise ValueError('actual C# wire fixture artifact differs from its retained input pin')
    record=json.loads(raw)
    if record['schema_version']!=1 or record['status']!='workspace-data-contract-tests-passed' or record['assertions']<80 or len(record['cases'])!=3:
        raise ValueError('actual C# fixture run/case count differs')
    for key in ('actual_linux_account_created','actual_linux_pam_authenticated','new_console_launched','production_qualified'):
        if record[key] is not False:
            raise ValueError('data-only interoperability cannot acquire account/PAM/console authority')
    requests=[]
    for case in record['cases']:
        if set(case)!={'request_base64','request_sha256','profile_base64','profile_sha256'}:
            raise ValueError('actual C# wire case fields differ')
        def decode(key):
            value=base64.b64decode(case[key],validate=True)
            if base64.b64encode(value).decode('ascii')!=case[key]:
                raise ValueError('C# case Base64 is noncanonical')
            return value
        request_raw=decode('request_base64')
        request=profile.request(request_raw)
        if hashlib.sha256(request_raw).hexdigest()!=case['request_sha256'] or request['profile_sha256']!=case['profile_sha256']:
            raise ValueError('actual C# complete request/profile commitment differs')
        description=decode('profile_base64')
        profile.validate_profile(description,request['runtime_manifest_sha256'])
        if hashlib.sha256(description).hexdigest()!=case['profile_sha256']:
            raise ValueError('actual C#/Python profile complete bytes differ')
        result=subprocess.run([str(binary),'hosted-windows-workspace-contract'],input=request_raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              check=True,timeout=5,env={'PATH':'/usr/bin','LANG':'C','LC_ALL':'C'})
        if len(result.stdout)>8192 or len(result.stderr)>8192:
            raise ValueError('data-only native CLI output exceeds its bound')
        observation=json.loads(result.stdout)
        for key in ('account_created','pam_authenticated','health_qualified','authority_returned','production_qualified'):
            if observation[key] is not False:
                raise ValueError('native contract fabricated execution/authority/qualification')
        if observation['request_sha256']!=case['request_sha256'] or observation['profile']!=profile.PROFILE or observation['uid']!=1000 or observation['account_generation']!=1 or observation['purpose_seconds']!=30:
            raise ValueError('actual C# -> Rust request/account/resource binding differs')
        requests.append(case['request_sha256'])
    return dict(schema_version=1,status='actual-csharp-python-rust-workspace-wire-passed',input_sha256=expected,
                actual_constructor_cases=len(requests),request_sha256=requests,account_created=False,pam_authenticated=False,
                new_console_launched=False,guest_confinement_qualified=False,production_qualified=False)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--cases',required=True,type=Path)
    parser.add_argument('--expected-sha256',required=True)
    parser.add_argument('--binary',required=True,type=Path)
    args=parser.parse_args()
    print(json.dumps(verify(args.cases,args.expected_sha256,args.binary),sort_keys=True))


if __name__=='__main__':
    main()
