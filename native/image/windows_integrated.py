"""Compose one unsigned profile-W workspace and compact-inference package.

Run inside the isolated Ubuntu24.04 builder with real compiled platform/PAM
helper inputs, the pinned completion archive and Qwen model. This never imports
WSL, executes supplied programs, creates accounts or provisions signing custody.
Failed, partially written outputs are retained; select a fresh output name to
try again, never silently overwrite a previous build.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import re

HERE = Path(__file__).parent


def load(name):
    specification = importlib.util.spec_from_file_location('luma_integrated_'+name, HERE/(name+'.py'))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


stage = load('windows_stage')
workspace = load('windows_workspace')
inference = load('windows_inference')
package = stage.package


def compose(source_root, platform, auth_helper, runtime, model, work_root, output_name, release):
    """Fresh workspace base first, then both closed runtime descriptors/pins."""
    if os.geteuid() != 0:
        raise ValueError('isolated root-owned Linux build required')
    if not isinstance(output_name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,79}', output_name):
        raise ValueError('integrated output name must be one bounded new directory component')
    if not isinstance(release, str) or not re.fullmatch(r'luma-wsl-dev-[A-Za-z0-9][A-Za-z0-9.-]{0,63}', release):
        raise ValueError('exact development release identity required')
    work_root = Path(os.path.abspath(work_root))
    if work_root == Path('/') or work_root == Path('/mnt/c') or str(work_root).startswith('/mnt/c/'):
        raise ValueError('integrated build requires a narrow external work root, not root or C')
    stage_name, package_name = output_name+'-stage', output_name+'-package'
    tree = package.Tree(work_root)
    try:
        for name in (stage_name, package_name):
            try:
                with tree.opened(name):
                    raise ValueError('integrated destination already exists: '+name)
            except FileNotFoundError:
                pass
    finally:
        tree.close()
    # The workspace flag must be chosen at initial staging: its fixed NSS
    # policy differs from compute-only staging and cannot be overlaid later.
    staged = stage.stage(source_root, platform, work_root, stage_name, hosted_workspace=True)
    staged_root = work_root/stage_name/'rootfs'
    composed_workspace = workspace.compose(staged_root, source_root, auth_helper)
    composed_inference = inference.compose(staged_root, source_root, model, runtime)
    built = package.build(staged_root, platform, work_root/stage_name/'plan.json',
                          work_root/package_name, release, hosted_inference=True, hosted_workspace=True)
    report = dict(schema_version=1, status='unsigned-integrated-workspace-inference-package-built',
                  profile='W', runtime_profile=workspace.PROFILE, release_id=release,
                  stage_directory=stage_name, package_directory=package_name,
                  stage=staged, workspace=composed_workspace, inference=composed_inference, package=built,
                  initial_default_uid=65534, initial_wsl_flags=0,
                  bootstrap_session_seconds=30, inference_session_seconds=300,
                  package_authenticated=False, distribution_imported=False, account_created=False,
                  pam_authenticated=False, inference_executed=False, host_settings_changed=False,
                  production_qualified=False, gate_closing=False)
    tree = package.Tree(work_root/stage_name)
    try:
        inference.write_new(tree, 'integrated-stage.json', package.canonical(report), 0o600)
    finally:
        tree.close()
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source-root', 'platform', 'auth-helper', 'runtime', 'model', 'work-root'):
        parser.add_argument('--'+name, required=True, type=Path)
    parser.add_argument('--output-name', required=True)
    parser.add_argument('--release-id', required=True)
    arguments = parser.parse_args()
    result = compose(arguments.source_root, arguments.platform, arguments.auth_helper,
                     arguments.runtime, arguments.model, arguments.work_root,
                     arguments.output_name, arguments.release_id)
    print(package.canonical(result).decode(), end='')
