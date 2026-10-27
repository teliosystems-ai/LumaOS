#!/bin/bash
# Serialized, disposable diagnostic boot of the fixed optical discovery script
# against the unchanged sequence-17 kernel, initrd and ISO. Not image evidence.
set -euo pipefail
source /etc/luma-build/environment.sh
build_id=20261027T132536Z-desktop
iso_sha256=58bf1cb3b518ad2f9dfeb8cd881c85bf48a4768d0baca1ef5204bc618e07b760
initrd_sha256=2c323e9d53bc6792bd79b6c498e3cf0565d97f99076ed4b026da942d22c9d992
volume=luma-native-build-$build_id
data=/mnt/luma-build/docker/volumes/$volume/_data
harness=/mnt/c/Users/hakim/LumaOS/.luma/candidate17-optical-diagnostic-20261027.py
fixed=/mnt/c/Users/hakim/LumaOS/native/image/overlay/usr/lib/dracut/modules.d/91luma/luma-optical.sh
python3 -B - "$volume" "$harness" "$fixed" <<'PY'
import hashlib,importlib.util,json,os,pathlib,sys,tomllib
source=pathlib.Path('/mnt/luma-build/work/candidate17-source-20261027-b')
raw=(source/'build-inputs.json').read_bytes()
assert hashlib.sha256(raw).hexdigest()=='f4198f999a3cf75a51b753b02c22a2324bc85001a17c53f4ceec0db7b6f4b756'
records=json.loads(raw)['files']
assert len(records)==877
for row in records:
    data=(source/row['path']).read_bytes()
    assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256'],row['path']
spec=importlib.util.spec_from_file_location('candidate_storage',source/'native/image/build_storage.py')
storage=importlib.util.module_from_spec(spec);spec.loader.exec_module(storage)
assert os.environ.get('DOCKER_HOST')==storage.ENDPOINT and not os.environ.get('DOCKER_CONTEXT')
storage.verify_store()
storage.validate_daemon(json.loads(storage.command('docker','info','--format','{{json .}}')))
storage.validate_runtime(tomllib.loads(storage.command('containerd','--config','/etc/luma-build/containerd.toml','config','dump')))
name=sys.argv[1]
volume=json.loads(storage.command('docker','volume','inspect',name))
assert len(volume)==1 and volume[0]['Name']==name and volume[0]['Driver']=='local' and not volume[0].get('Options')
assert volume[0]['Mountpoint']==str(storage.STORE/'docker/volumes'/name/'_data')
assert not storage.command('docker','ps','--format','{{.ID}}'),'serialized: no other container may run'
storage.check_space(storage.STORE,2)
fixed=pathlib.Path(sys.argv[3]).read_bytes()
assert b'\r' not in fixed and b'dracut-lib' not in fixed.split(b'\nset -eu\n',1)[1]
print(json.dumps(dict(harness_sha256=hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest(),
                      fixed_script_sha256=hashlib.sha256(fixed).hexdigest())),flush=True)
print('Isolated software-only optical discovery diagnostic; no physical devices, no Secure Boot claim.',flush=True)
PY
kernel_sha256=$(sha256sum "$data/root/boot/vmlinuz-6.8.0-142-generic" | cut -d' ' -f1)
test "$(sha256sum "$data/root/boot/luma-initrd" | cut -d' ' -f1)" = "$initrd_sha256"
fixed_sha256=$(sha256sum "$fixed" | cut -d' ' -f1)
echo "kernel_sha256=$kernel_sha256 initrd_sha256=$initrd_sha256 fixed_script_sha256=$fixed_sha256"
log=/mnt/d/LumaOS-builds/candidate17-optical-diagnostic-fixed-$build_id.log
test ! -e "$log"
docker run --rm --network none --memory 6g --memory-swap 6g --cpus 2 --pids-limit 128 \
  --mount "type=volume,src=$volume,dst=/work" \
  --mount type=bind,src=/mnt/luma-build/work/candidate17-source-20261027-b,dst=/repo,readonly \
  --mount "type=bind,src=$harness,dst=/optical-diagnostic.py,readonly" \
  --mount "type=bind,src=$fixed,dst=/fixed/luma-optical.sh,readonly" \
  --env PYTHONDONTWRITEBYTECODE=1 \
  sha256:819dfe7772da1e3c76ffdc8f9ea4a1fa44c7c549bd4fa988e35d9397d87924b2 \
  python3 -B /optical-diagnostic.py \
  --iso /work/artifacts/luma-native-lab-20260927-desktop-17.iso \
  --iso-sha256 "$iso_sha256" \
  --kernel-sha256 "$kernel_sha256" --initrd-sha256 "$initrd_sha256" \
  --fixed-script /fixed/luma-optical.sh --fixed-script-sha256 "$fixed_sha256" \
  --work /work/vm-candidate17-20261027-optical-diagnostic-fixed-tcg 2>&1 | tee "$log"
