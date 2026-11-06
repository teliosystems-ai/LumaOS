# Native acceptance from a download: sequences 19 and 20 (owner handoff, 2026-11-03)

This is the owner's procedure for testing the profile N native desktop images,
sequences 19 and 20, together. No optical drive is needed. Every image is
installed from a downloaded file: written to a USB stick for a physical
machine, or attached to a virtual machine as a file. Sequence 20 contains the
sequence-19 components, so the two sequences are tested as one run: install
19, update it to 20, recover, then install 20 fresh.

## 1. Status

- **Sequence 19 is built.** Build `20261028T162354Z-desktop`, source commit
  `6528ea1411b2dc0057bbc1ecdbaad538df21b4f3`, release
  `luma-native-lab-20260927-desktop-19`, kernel `6.8.0-142-generic`. Its record
  is [G2_NATIVE_DESKTOP_CANDIDATE_19_2026-10-28.md](G2_NATIVE_DESKTOP_CANDIDATE_19_2026-10-28.md).
- **Sequence 20 is built.** Build `20261103T215655Z-desktop`, source commit
  `e9a11aac64ce6da55dd706cd3a22ebd64fb0ed4c`, release
  `luma-native-lab-20260927-desktop-20`, kernel `6.8.0-142-generic`. Its record
  is [candidate20_execution_2026-11-03.json](candidate20_execution_2026-11-03.json).
  The offline image and export verification passed all 14 checks. A static
  check found that `luma-platform update` would accept 20 over 19: the same
  geometry, edition and environment, a higher sequence, and the same
  laboratory certificate. No update was run.
- **Both download sets are produced on the build host and not uploaded.** They
  are `D:\LumaOS-builds\downloads\candidate19-20261028T162354Z-desktop-a` and
  `D:\LumaOS-builds\downloads\candidate20-20261103T215655Z-desktop-a`. Each has
  15 files, `SHA256SUMS` pinned in section 3, and a raw image that was
  decompressed from the `.img.zst` and hashed. Agents never upload. The owner
  chooses the HTTPS location and uploads the folders.
  **Update 2026-11-05:** the build drive moved to E:. Upload from
  `E:\LumaOS-builds\downloads\candidate19-20261028T162354Z-desktop-a` and
  `E:\LumaOS-builds\downloads\candidate20-20261103T215655Z-desktop-a`. On
  2026-11-05 all 14 on-disk files in each folder matched `SHA256SUMS`. The
  15th entry is the raw `.img`, which is checked after decompression and was
  never stored in these folders, on D: or E:. See the
  [relocation record](NATIVE_E_BUILD_DRIVE_2026-11-05.md).
- **None of the steps below has been run by an agent** on a physical machine,
  on a USB stick, from a download, or as an install or update of these two
  sequences. Agents have run only live VM smokes under QEMU with Secure Boot:
  for sequence 19, the disk image and the ISO (named in its record); for
  sequence 20, the raw disk image as a removable USB mass-storage device on
  xHCI and as a virtio disk. No smoke installed anything.
- The sequence-20 USB smoke passed on its second attempt. The first attempt
  reached a root shell under Secure Boot, then failed the harness's own check
  that the guest sees only the live disk: QEMU's q35 machine adds an empty DVD
  drive, which the guest listed as `sr0`. The harness now starts disk media
  with `-nodefaults -vga std` (commit `d3372cb`); the image was unchanged. The
  failed attempt is kept in the record.
- Nothing here is production-signed. The images and `secureboot.cer` are signed
  with the laboratory key.

## 2. Media and trust anchors

### Which file to use

| Medium | File | Use |
| --- | --- | --- |
| USB stick, physical machine | `<release>.img`, decompressed from `<release>.img.zst` | Write the whole image to a stick of 32 GB or more |
| VM, raw disk | `<release>.img` | Attach as a read-only raw disk (USB or virtio) |
| VM, DVD (optional) | `<release>.iso` | Attach as a DVD file only. The ISO is not hybrid and cannot be written to a USB stick. It is not needed for this acceptance. |
| Hyper-V (profile V) | `<release>.vhdx`, only if the set includes one | Secure Boot with the laboratory certificate is blocked (W030, W032); see below |

`<release>` is `luma-native-lab-20260927-desktop-19` or
`luma-native-lab-20260927-desktop-20`.

The sequence-19 `.img` is 16,190,013,440 bytes. It holds a GPT disk with four
partitions:

| # | Partition name | Content |
| --- | --- | --- |
| 1 | `LUMA-LIVE-ESP` | FAT EFI system partition: signed systemd-boot `EFI/BOOT/BOOTX64.EFI`, signed `EFI/Linux/luma-live.efi`, and a copy of `secureboot.cer` at its root |
| 2 | `luma-live-root` | dm-verity protected live root |
| 3 | `luma-live-hash` | its verity hash tree |
| 4 | `luma-payload` | ext4; the signed install and update payload, mounted read-only at `/media/luma` in the live session |

The backup GPT header sits at the end of the image, about 16 GB in. On a larger
stick, tools report that the alternate GPT header is not at the end of the
disk. **Do not let any tool fix the GPT, and never format the stick.** Windows
offers to format partitions it cannot read: always choose Cancel. Booting from
a stick larger than the image has not been tested.

### How the trust anchors reach the firmware

The chain is: firmware `db` holds the laboratory certificate, which verifies
signed systemd-boot, which verifies the signed UKI, whose command line carries
the dm-verity root hash, and `luma-platform verify` checks the payload against
the signed `release.json` and `release.sig`. There is no shim and no MOK. MOK
enrollment is not a substitute. Secure Boot stays on in every path.

| Path | How `secureboot.cer` reaches the firmware `db` |
| --- | --- |
| Physical machine | The owner appends it to `db` in the firmware setup (section 7). The file comes from the download set, or from the root of the stick's `LUMA-LIVE-ESP` partition through the firmware file browser. Both copies are covered by a checksum: the downloaded file by its `SHA256SUMS` row, the ESP copy by the image hash. |
| QEMU with OVMF | `virt-fw-vars` writes it into a private copy of the OVMF variable store as PK, KEK and db, with Secure Boot enabled (section 6). The copy is disposable; this is not done to real firmware. |
| Hyper-V | Not possible. Hyper-V templates cannot take a custom `db` entry, so W030 and W032 stay blocked. The owner options are: A, a distribution-signed shim plus MOK; B, an own shim through shim review; C, another hypervisor with custom NVRAM (QEMU/OVMF as here, or VirtualBox, which is untested). |

`secureboot.cer`: DER, 1,073 bytes, SHA-256
`2637785a3cb4798db902bf62732324984d3f2475d7f2eecc318442772d9c06c8`. The same
certificate signs sequences 19 and 20; the sequence-20 build checks this before
the set is made.

## 3. Pins

The SHA-256 of each set's `SHA256SUMS` file is the only origin check, because
nothing is signed with an owner key. Take the pin from this repository, never
from the download folder or the download location.

| Set | `SHA256SUMS` pin | Status |
| --- | --- | --- |
| Sequence-19 download set (`candidate19-20261028T162354Z-desktop-a`) | `261a47f218dbc08f24eba7591203f84a21c2a2a64f48a5213d057149cf71008a` (1,312 bytes, 15 rows) | produced on the build host, not uploaded |
| Sequence-20 download set (`candidate20-20261103T215655Z-desktop-a`) | `1c2c4af2242366462a11df5f1a1516647f5c30487f38ca071874f77bcb99a802` (1,312 bytes, 15 rows) | produced on the build host, not uploaded |
| Sequence-19 export folder itself | `d440805f8c8aabe69a7dfc852acabadbbdb57eb04ff19e587d59847ce85492bf` (1,069 bytes, 12 rows) | exists on the build host |

A download set holds the export files, `build.json`, `VERIFY.txt`,
`download-manifest.json` and its own `SHA256SUMS`. That `SHA256SUMS` lists the
raw `.img` too, although by default only the `.img.zst` is shipped. The files
copied from the export keep their export hashes, so the sequence-19 rows below
must match whichever `SHA256SUMS` you check.

**Sequence 19** (`luma-native-lab-20260927-desktop-19`):

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `.img` | 16,190,013,440 | `082337e4d206f1edd31bdfb44912f93e1b10726d02b5d60a150267674a101756` |
| `.img.zst` | 3,690,965,526 | `bc74f083a7b5a22a5106da8b79dcd906197daf77a9a17a8a3c926a37fc249276` |
| `.iso` (optional) | 7,225,784,320 | `a4fbfec8eb760ffae246eb85567c15e47314e89e300836cc0c7422fedef11ca5` |
| `secureboot.cer` | 1,073 | `2637785a3cb4798db902bf62732324984d3f2475d7f2eecc318442772d9c06c8` |
| `release.json` | 995 | `f90c15768389ea13e114263480d98e5747376f4126d815af44a15ea39894e131` |
| `release.sig` | 64 | `4f29b5d2d15fd8dcfc5977446ca32e93741eae74881e4af8bf58f600ff6a696e` |
| `boot-policy.json` | 2,166 | `0ef9bed827f4b2f11d3c6a58391d813a42cef12f689b828b424cefc92a2ebc05` |
| `optical-media.json` | 1,786 | `209ea557861b99dc24ee49d5866512c583596ebc22acffdda3ce4a4742005a9d` |
| `packages.lock` | 28,474 | `05b1dc02df7729570d2570dfce45e51e55305236ff493c21c4cf14dc613368e7` |
| `source-lock.json` | 131,645 | `f452c120e3a883dbaf563d2894fb0d7df431a5bfe7a0248946393f3c04256578` |
| `toolchain-packages.lock` | 11,083 | `674dfe922b7eca733e893b85b9560a82e11d0a58235e87ac78fa1f7ef5e86668` |
| `native-source.tar.zst` | 2,797,540 | `d4d7e8a5c198ed6a2dd890fee771d49744bc20f153f0d9b84dc1e253791d1edf` |

`build.json` (22,415 bytes) is not in the export `SHA256SUMS`; the download
set's `SHA256SUMS` lists it.

**Sequence 20** (`luma-native-lab-20260927-desktop-20`, build
`20261103T215655Z-desktop`, kernel `6.8.0-142-generic`):

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `.img` | 16,190,013,440 | `573da1f61ef646c7c3bacf616a2c8bd6b6ca15eb8a3c39c7ea5042387d581519` |
| `.img.zst` | 3,690,817,887 | `9fee72c4b167e54697e23d50fa87c9b5e5a70a08ea64fa5d40b52d98ef7fb5ad` |
| `.iso` (optional) | 7,225,763,840 | `b10302ca335987ea09878228b79d6acdc6d857ac260ba66bb88dc17a1e80a363` |
| `secureboot.cer` | 1,073 | `2637785a3cb4798db902bf62732324984d3f2475d7f2eecc318442772d9c06c8` |
| `release.json` | 995 | `cf0ab7000d074078c74b62c596cf4386da0c28f2503b76c070eeb52b40c521d5` |
| `release.sig` | 64 | `9e5b8f9a52ec1a416dfb601325f028c1f51cc8e342d748cc19ddcb03ad058cee` |
| `boot-policy.json` | 2,166 | `3d37d7dcdf2ba99350dece527cc1e9fab9d37cd6043ecd86f7537d465459c287` |
| `optical-media.json` | 1,786 | `20040ba771cbaaf838b8f27c5576a11d39c40dbad367099f4d7ba772ee1185a7` |
| `packages.lock` | 28,474 | `05b1dc02df7729570d2570dfce45e51e55305236ff493c21c4cf14dc613368e7` |
| `source-lock.json` | 136,370 | `eb932cdc66f5cf80620ba0ed4a8550be0b04994fa0a7e22a10841f3d4bb89483` |
| `toolchain-packages.lock` | 11,083 | `674dfe922b7eca733e893b85b9560a82e11d0a58235e87ac78fa1f7ef5e86668` |
| `native-source.tar.zst` | 2,914,458 | `c7ea2cef16e47bf78c88bc11d4805ed5f5018a8c8e34822c66aa70dbd20c25b9` |

`build.json` is 22,415 bytes, SHA-256
`afe543ef281a845d5ff7092f72aa1be566389043340ca9fe785d4ec2bef75047`. The export
`SHA256SUMS` itself is 1,069 bytes with 12 rows, SHA-256
`8f83f708d4906f72e57ecb38c92d46aed4dfa4a0e4fed4f6f7719c8cdff280a8`. The
sequence-20 release keeps environment `lab`, edition `desktop`, `root_bytes`
6442450944 and `hash_bytes` 50733056, as the 19-to-20 update needs. The raw
image is the same size as sequence 19's, `packages.lock` and
`toolchain-packages.lock` are byte-identical to sequence 19's, and the kernel is
the same.

## 4. Download and verify

Use a new, empty folder on a fixed local NTFS or ext4 disk: not a network share,
a cloud-synchronized folder, an exFAT disk or a removable drive. Allow about
20 GB per sequence (the `.img.zst` plus the decompressed `.img`), or 27 GB with
the optional ISO. Download each sequence into its own folder.

Download `SHA256SUMS` first and check it against the pin. Only then use it as
the list of files to download: after the pin check, its names are the ones
recorded here. The loops skip the raw `.img` (you make it by decompressing the
`.img.zst`), the optional ISO and any Hyper-V files. To get the ISO as well,
download `<release>.iso` the same way.

### Windows (PowerShell)

```powershell
$base = 'https://<owner location>/<set folder>'   # the owner's own HTTPS location
$dl = 'C:\LumaTest\19'                             # new, empty folder
$release = 'luma-native-lab-20260927-desktop-19'
$pin = '<64-hex pin from section 3>'
New-Item -ItemType Directory -Path $dl | Out-Null
Set-Location -LiteralPath $dl
curl.exe --fail --location --proto =https --proto-redir =https --output "$dl\SHA256SUMS" "$base/SHA256SUMS"
(Get-FileHash -Algorithm SHA256 -LiteralPath .\SHA256SUMS).Hash.ToLowerInvariant() -ceq $pin
```

The last command must print `True`. If it prints `False`, stop: the list of
checksums is not the one recorded here. Then download the listed files:

```powershell
foreach ($line in Get-Content -LiteralPath .\SHA256SUMS) {
  $name = ($line -split '  ', 2)[1]
  if ($name -match '\.(img|iso|vhdx)$|\.vhdx\.') { continue }
  curl.exe --fail --location --proto =https --proto-redir =https --output "$dl\$name" "$base/$name"
  if ($LASTEXITCODE -ne 0) { throw "download failed: $name" }
}
```

Then check every file:

```powershell
function Test-LumaSums {
  Get-Content -LiteralPath .\SHA256SUMS | ForEach-Object {
    $hash, $name = $_ -split '  ', 2
    if (Test-Path -LiteralPath $name) {
      $ok = (Get-FileHash -Algorithm SHA256 -LiteralPath $name).Hash.ToLowerInvariant() -ceq $hash
      '{0} {1}' -f $(if ($ok) { 'OK    ' } else { 'FAILED' }), $name
    } else { 'absent ' + $name }
  }
}
Test-LumaSums
```

Every downloaded file must print `OK`. Before decompression the `.img` prints
`absent`. Decompress with `zstd.exe` from the official zstd release, or with
`zstd` in WSL Ubuntu, then check again:

```powershell
zstd.exe -d --keep ".\$release.img.zst"
Test-LumaSums
```

The `.img` line must now print `OK`. This takes several minutes for 16 GB.

### Linux

```sh
base='https://<owner location>/<set folder>'
release=luma-native-lab-20260927-desktop-19
pin='<64-hex pin from section 3>'
mkdir -m 700 ~/luma-dl-19 && cd ~/luma-dl-19
curl --fail --location --proto =https --proto-redir =https --output SHA256SUMS "$base/SHA256SUMS"
printf '%s  SHA256SUMS\n' "$pin" | sha256sum --check -
```

This must print `SHA256SUMS: OK`; otherwise stop. Then:

```sh
cut -c67- SHA256SUMS | grep -Ev '\.(img|iso|vhdx)$|\.vhdx\.' | while IFS= read -r f; do
  curl --fail --location --proto =https --proto-redir =https --output "$f" "$base/$f" || echo "FAILED $f"
done
sha256sum --check --ignore-missing SHA256SUMS
zstd -d --keep "$release.img.zst"
sha256sum --check --ignore-missing SHA256SUMS
```

`--ignore-missing` skips files that are absent, so read the output: no line
may say `FAILED`, and the final check must print `OK` for every downloaded file
and for `luma-native-lab-20260927-desktop-19.img`.

Repeat for sequence 20 with its own folder, `release`, set folder and pin.

Record the certificate's fingerprints for the firmware screen:

```sh
openssl x509 -inform DER -in secureboot.cer -noout -subject -fingerprint -sha1
openssl x509 -inform DER -in secureboot.cer -noout -fingerprint -sha256
```

## 5. Write a USB stick (physical machine)

Use a separate stick for each sequence, 32 GB or more, whose contents may be
destroyed. Label them 19 and 20. **Insert only one Luma stick at a time**: both
carry a partition named `luma-payload`, and the live system and the update step
find the payload by that name.

### Windows

Neither tool below has been tested with these images.

- **Rufus:** select the stick, select the `.img` (not the `.zst`), and write it.
  Rufus writes a `.img` as a raw disk image. Accept no offer to add files,
  change the partition scheme or "fix" anything.
- **Win32 Disk Imager:** select the `.img` and the stick's drive letter, then
  choose Write.

After writing, Windows may say a drive must be formatted before use. Choose
**Cancel** every time. Windows can read only the FAT EFI partition. That is
not a problem: the firmware checks the signatures of the files on it, not the
partition.

Windows offers no simple read-back hash of a raw stick. If you have a Linux
machine, use the read-back check below. Otherwise rely on the boot: Secure Boot
rejects a damaged bootloader or UKI, dm-verity rejects a damaged root, and
`luma-platform verify /media/luma` rejects a damaged payload.

### Linux

```sh
lsblk -o NAME,PATH,MODEL,SERIAL,TRAN,SIZE,RM,MOUNTPOINTS
ls -l /dev/disk/by-id/ | grep usb-
stick=/dev/disk/by-id/usb-EXACT-STICK-ID       # the whole stick, not a -partN link
for p in "$stick"-part*; do sudo umount "$p" 2>/dev/null; done
sudo dd if=luma-native-lab-20260927-desktop-19.img of="$stick" bs=4M conv=fsync oflag=direct status=progress
sudo blockdev --flushbufs "$stick"
sudo head -c 16190013440 "$stick" | sha256sum
```

Replace `EXACT-STICK-ID` with the stick's real name, checked against its model,
serial and size. The last command must print the `.img` hash from section 3.
For sequence 20, use its image size and hash.

A desktop may mount the stick's partitions when it appears. A read-write mount
of `luma-live-root` changes its ext4 superblock, and dm-verity then refuses to
boot that stick. Before removing the stick, run `lsblk` again; if any of its
partitions is mounted, unmount it (`udisksctl unmount -b /dev/sdX2`) and repeat
the read-back hash. If the hash differs, write the stick again.

## 6. Virtual machine (QEMU, OVMF, software TPM)

This needs a Linux host (Ubuntu 24.04 or similar) with these packages:

```sh
sudo apt install qemu-system-x86 qemu-utils ovmf swtpm python3-virt-firmware openssl zstd mtools sbsigntool gdisk
```

The commands use software emulation (TCG) with emulated Secure Boot, as the
agents' smokes did. This is slow: the sequence-19 `luma-platform verify` took
381.9 s under TCG. KVM acceleration with Secure Boot has not been exercised
here; changing `accel=tcg` to `accel=kvm` is an owner option.

### One-time setup of the VM folder

```sh
mkdir -m 700 ~/luma-vm-19-20 && cd ~/luma-vm-19-20
IMG19=~/luma-dl-19/luma-native-lab-20260927-desktop-19.img
IMG20=~/luma-dl-20/luma-native-lab-20260927-desktop-20.img
cp /usr/share/OVMF/OVMF_VARS_4M.fd vars.fd
openssl x509 -inform DER -in ~/luma-dl-19/secureboot.cer -out cert.pem
OWNER=d89f6f4e-6249-4fc4-ad4e-4d10f21e83ef
virt-fw-vars --inplace vars.fd --set-pk $OWNER cert.pem --add-kek $OWNER cert.pem --add-db $OWNER cert.pem --sb
mkdir -m 700 tpm
qemu-img create -f qcow2 target.qcow2 64G
```

`vars.fd`, the `tpm` folder and `target.qcow2` belong together: the installed
system seals its data key to this TPM and to the Secure Boot state in
`vars.fd`. Keep all three, and restore all three together.

### The run function

Define this in the shell, in the VM folder. The first argument names the serial
log; the rest are added to the QEMU command.

```sh
run_vm() {
    local log=$1; shift
    local sock="$PWD/tpm.sock"
    rm -f "$sock"
    (umask 077; exec swtpm socket --tpm2 --tpmstate dir="$PWD/tpm",mode=0600 \
        --ctrl type=unixio,path="$sock" --flags not-need-init) &
    local tpm=$!
    while [ ! -S "$sock" ]; do sleep 0.2; done
    qemu-system-x86_64 -machine q35,accel=tcg -m 8192 -smp 2 -cpu max \
        -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
        -drive if=pflash,format=raw,file="$PWD/vars.fd" \
        -chardev socket,id=luma-tpm,path="$sock" \
        -tpmdev emulator,id=luma-tpm,chardev=luma-tpm -device tpm-tis,tpmdev=luma-tpm \
        -nic user,model=virtio-net-pci \
        -chardev stdio,id=con,mux=on,signal=off,logfile="$PWD/$log",logappend=on \
        -serial chardev:con -mon chardev=con,mode=readline \
        "$@"
    kill "$tpm" 2>/dev/null; wait "$tpm" 2>/dev/null; rm -f "$sock"
}
```

The serial console is in the terminal; the graphical console opens in a
window (add `-display none` on a host without a display). `signal=off` keeps
Ctrl-C inside the guest. Ctrl-A then X quits QEMU at once, like pulling the
power. The guest needs 8 GiB: the live system stages the payload in a `/var`
held in RAM and refuses with less than 6732 MiB for it.

### Attachments

| Purpose | Arguments |
| --- | --- |
| Live boot, stick as USB (closest to physical) | `-device qemu-xhci,id=xhci -drive if=none,id=usbstick,format=raw,readonly=on,file="$IMG19" -device usb-storage,bus=xhci.0,drive=usbstick,removable=on,bootindex=1` |
| Live boot, stick as virtio disk | `-drive if=none,id=media,format=raw,readonly=on,file="$IMG19" -device virtio-blk-pci,drive=media,serial=LUMA-LIVE,bootindex=1` |
| Target disk while booting a live medium | `-drive if=none,id=target,format=qcow2,discard=unmap,detect-zeroes=unmap,file=target.qcow2 -device virtio-blk-pci,drive=target,serial=LUMA-VM-TARGET,bootindex=2` |
| Installed boot | the same target arguments with `bootindex=1`, and no live medium |
| Update medium on the installed system | `-drive if=none,id=media20,format=raw,readonly=on,file="$IMG20" -device virtio-blk-pci,drive=media20,serial=LUMA-MEDIA-20` |
| Export disk for recovery | `-drive if=none,id=export,format=qcow2,file=export.qcow2 -device virtio-blk-pci,drive=export,serial=LUMA-EXPORT` (create it with `qemu-img create -f qcow2 export.qcow2 8G`) |

In the guest the target is `/dev/disk/by-id/virtio-LUMA-VM-TARGET`. Every
medium is attached read-only, so the VM cannot change a downloaded image.
The q35 machine also adds an empty DVD drive, which the guest shows as `sr0`.
It holds nothing and can be ignored; the agents' disk smokes remove it with
`-nodefaults -vga std`.

Example, the first live boot of sequence 19 from a USB stick:

```sh
run_vm serial-S1-live19.log \
  -device qemu-xhci,id=xhci \
  -drive if=none,id=usbstick,format=raw,readonly=on,file="$IMG19" \
  -device usb-storage,bus=xhci.0,drive=usbstick,removable=on,bootindex=1 \
  -drive if=none,id=target,format=qcow2,discard=unmap,detect-zeroes=unmap,file=target.qcow2 \
  -device virtio-blk-pci,drive=target,serial=LUMA-VM-TARGET,bootindex=2
```

**Checkpoints (optional).** With the VM off, `cp -a --sparse=always
~/luma-vm-19-20 ~/luma-vm-19-20-after-S3` saves the disk, `vars.fd` and TPM
state together. To go back, restore the whole folder; never mix the disk of
one checkpoint with the TPM or `vars.fd` of another.

## 7. Physical firmware: keep Secure Boot on, enroll the certificate

Use an amd64 UEFI machine with TPM 2.0, at least 8 GiB of RAM (16 GiB is
practical), wired network for model staging, and a **disposable target disk**
of at least 32 GiB (64 GiB recommended). Legacy BIOS and dual boot are not
supported. Disconnect other disks where possible and back up their data.

1. **Record** the machine vendor, model, firmware version and Secure Boot state.
2. **Back up the current keys.**
   Windows, in an administrator PowerShell:
   ```powershell
   Confirm-SecureBootUEFI
   $kb = 'C:\LumaTest\firmware-keys-before'
   New-Item -ItemType Directory -Path $kb | Out-Null
   foreach ($v in 'PK', 'KEK', 'db', 'dbx') { Get-SecureBootUEFI -Name $v -OutputFilePath "$kb\$v.bin" }
   ```
   Linux (efitools): `for v in PK KEK db dbx; do efi-readvar -v $v -o $v.esl; done`.
3. **BitLocker.** If the machine runs Windows with BitLocker, a `db` change
   alters PCR 7 and Windows will ask for its recovery key. Have the key ready
   (`manage-bde -protectors -get C:`) or suspend BitLocker for the test.
4. **Enroll.** In the firmware setup, find the Secure Boot key management and
   **append** `secureboot.cer` to `db`. Take the file from a FAT USB stick or
   from the root of the Luma stick's `LUMA-LIVE-ESP` partition. Compare the
   fingerprint the firmware shows with the one recorded in section 4. Some
   firmware needs Secure Boot mode "Custom" to edit `db`; that is acceptable.
   **Never** delete all keys, enter setup mode, replace PK or disable Secure
   Boot.
5. **Do not change `db` again until the test is finished.** The installed
   system seals its data key to PCR 7; a later `db` change makes it ask for the
   recovery passphrase.
6. **If the certificate cannot be enrolled,** record every Secure Boot row as
   `blocked`. A test with Secure Boot off is a separate owner decision. It does
   not count for A104 or FR05.

Boot the stick from the firmware boot menu, choosing its UEFI entry. The live
recovery console is the installer interface; it is not a graphical desktop.

Restoring the firmware keys is step S14.

## 8. The combined test, step by step

Run the steps in order. A step that cannot be run is recorded `blocked`, never
`pass`. Keep the output of every command; section 10 lists what to return. In
the VM, the live console is the serial terminal; physically it is the screen.

**Do not commission product Admin before step S9.** A Unix sudo account is not
product Admin. Once product Admin is bootstrapped, `luma-platform update` needs
Admin to publish release trust and admit the exact update, and refuses
otherwise with "Admin must publish release trust and admit this exact update".
Slot repair then needs the governed Admin path too. Neither path is covered
here. Admin ceremonies, if wanted, come after S9 or on the fresh install in
S12. Never run `apt upgrade`.

### S1. Live session, sequence 19

Boot the sequence-19 stick (VM: the example in section 6). In the live console:

```sh
grep -qw luma.mode=live /proc/cmdline && grep -qw luma.slot=live /proc/cmdline && ! grep -q luma.media= /proc/cmdline && echo LIVE-CMDLINE-OK
test "$(findmnt -n -o FSTYPE /)" = ext4 && veritysetup status root
systemctl --no-pager is-active media-luma.mount
findmnt -n -o SOURCE,FSTYPE,OPTIONS /media/luma
readlink -f /dev/disk/by-partlabel/luma-payload
luma-platform inventory
luma-platform status
systemctl --no-pager is-active luma-broker.service luma-reference.service
grep -Fx "luma-reference (enforce)" /sys/kernel/security/apparmor/profiles
od -An -tu1 -j4 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
stat -c "%F %u %g %a" /dev/tpmrm0 && luma-platform tpm-probe
systemctl --no-pager --failed
systemctl --no-pager is-active luma-utc-recovery-keeper.service luma-utc-recovery-producer.path
luma-platform admin-install-check
uname -r; grep VERSION_ID /etc/os-release
time luma-platform verify /media/luma
```

Expected: `LIVE-CMDLINE-OK`; `veritysetup` reports the root verified; the mount
is active, ext4, with `ro` in its options, and its source is the device that
`readlink` prints; `od` prints `1` (Secure Boot on); the TPM probe passes; no
failed unit; keeper and producer active; kernel `6.8.0-142-generic`;
`VERSION_ID="24.04"`; `verify` exits 0 and names release
`luma-native-lab-20260927-desktop-19`. A refusal for "insufficient snapshot
storage" means too little RAM. Record any failed unit with
`journalctl -b -u <unit>`.

### S2. Install sequence 19

Pick the target's whole-disk name from `luma-platform inventory`. Replace
`EXACT-TARGET-DISK-ID` with it (VM: `virtio-LUMA-VM-TARGET`). Never use an
assumed `/dev/sdX` name.

```sh
luma-platform install /dev/disk/by-id/EXACT-TARGET-DISK-ID /media/luma --stage-model qwen3-4b-q4-k-m
```

It prints the disk identity (model, serial, WWN, size). Check it, then type
the exact `ERASE <token>` it shows; the token is the disk's WWN, or its serial
if it has no WWN. Every later confirmation (`UPDATE`, `RECOVER`, `REPAIR`,
`REPAIR-DATA`) works the same way. Then it asks for:

- a first-user login name and a separate administrator login name;
- four credentials, each at least 16 characters and entered twice: user
  password, administrator password, data unlock passphrase, and an independent
  recovery passphrase that must differ from the data passphrase.

Finally it prints a NEW offline Admin recovery credential (hexadecimal) and asks
you to type it back. Luma keeps no copy, and it is not the disk recovery
passphrase. Write it down and keep it apart from the other credentials. Keep
every credential off the machine. Typed credentials are not echoed, but the
printed Admin recovery credential is: if you ran the installer on the VM's
serial console, delete that line from the serial log of that boot. Do not
photograph it on a physical screen.

Model staging downloads the model, so the machine needs network. The choices:

| `--stage-model` | Download bytes | Total RAM floor | Available RAM for serving |
| --- | ---: | ---: | ---: |
| `qwen3-4b-q4-k-m` | 2,497,280,256 | 6,100,000,000 bytes | 4.5 GiB |
| `qwen3-1-7b-q4-k-m` | 1,107,408,544 | 4,000,000,000 bytes | 2.5 GiB |
| `manual-only` | none | | |

Each model needs two CPUs and its download size plus 2 GiB of free encrypted
storage; inert staging needs 1 GiB of available RAM. Staging keeps model
serving off. When the install finishes, power off and remove the stick
(VM: start the next boot without the live medium).

### S3. First boot, sequence 19

Boot the target (VM: `run_vm serial-S3-first19.log` with the target at
`bootindex=1`). Enter the data passphrase, log in as the administrator, and run:

```sh
sudo luma-platform boot-health
sudo systemctl --no-pager --failed
sudo systemctl --no-pager status luma-broker luma-reference luma-boot-health
sudo veritysetup status root
sudo cryptsetup status luma-data
grep -o 'luma.slot=[ab]' /proc/cmdline
cat /usr/share/luma-os/release-id
od -An -tu1 -j4 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
sudo awk -F: '$2 == "" {print $1}' /etc/shadow
```

Expected: `LUMA_BOOT_HEALTH_OK`; no failed unit; `luma.slot=a`; release
`luma-native-lab-20260927-desktop-19`; `cryptsetup` shows type LUKS2; Secure
Boot `1`; the `awk` line prints nothing (no account without a password). Also
check the GNOME Wayland login, logout and login, screen lock, reboot and
shutdown.

### S4. Before the update: record slot A

```sh
sudo cat /var/lib/luma-os/installed.json
sudo ls -l /efi/EFI/Linux
sudo cat /efi/loader/loader.conf
sudo sha256sum /dev/disk/by-partlabel/luma-root-a /dev/disk/by-partlabel/luma-hash-a
```

Keep the two partition hashes; S6 compares them (A105).

### S5. Update 19 to 20

Physical: insert the sequence-20 stick into the running sequence-19 system. VM:
power off, then boot the target with the update medium attached (section 6).

```sh
lsblk -o NAME,PATH,PARTLABEL,TRAN,SIZE,RO,MOUNTPOINTS
```

If the desktop mounted any partition of the stick, unmount it with
`udisksctl unmount -b /dev/sdX4` (use the path `lsblk` shows). Then:

```sh
readlink -f /dev/disk/by-partlabel/luma-payload
sudo mount -o ro,nodev,nosuid,noexec /dev/disk/by-partlabel/luma-payload /media/luma
sudo luma-platform update /media/luma
sudo umount /media/luma
```

`readlink` must print the stick's (VM: the update disk's) fourth partition. The
update prints `Update luma-native-lab-20260927-desktop-19 to
luma-native-lab-20260927-desktop-20 on inactive slot b.`, asks for the exact
`UPDATE <identity>`, and ends with `Inactive slot staged for at most three
trial boots. Reboot when ready.` It needs about 3.3 GiB free on the encrypted
`/var`; otherwise it refuses with "insufficient snapshot storage". Remove the
stick (VM: drop the update disk), then reboot.

If the desktop had mounted `luma-live-root` of the sequence-20 stick read-write,
that stick will no longer boot; write it again before S8 and S12.

**S5b, optional, VM only: three failed trials.** Instead of a normal reboot,
let the guest reboot and quit QEMU (Ctrl-A, X) as soon as the serial console
shows a kernel command line containing `luma.slot=b`, before
`LUMA_BOOT_HEALTH_OK` (for example at the data passphrase prompt). Start the VM
again with `run_vm` each time. After three such boots, the fourth boot must
come up on `luma.slot=a`. There, check:

```sh
grep -o 'luma.slot=[ab]' /proc/cmdline
sudo cat /var/lib/luma-os/failed-update.json
sudo cat /var/lib/luma-os/installed.json
sudo ls -l /efi/EFI/Linux
```

Expected: slot a, `failed-update.json` names sequence 20, `installed.json`
still sequence 19, and the slot-b UKI's counter shows no tries left. Then
repeat S5 normally: the same update can be staged again. This fallback has
never been run for sequences 19 and 20.

### S6. After the update

Boot normally; systemd-boot tries slot b first. Then:

```sh
grep -o 'luma.slot=[ab]' /proc/cmdline
cat /usr/share/luma-os/release-id
sudo luma-platform boot-health
sudo cat /var/lib/luma-os/installed.json
sudo test ! -e /var/lib/luma-os/pending.json && echo NO-PENDING
sudo ls -l /efi/EFI/Linux
sudo cat /efi/loader/loader.conf
uname -r
sudo veritysetup status root
sudo cryptsetup status luma-data
sudo systemctl --no-pager --failed
od -An -tu1 -j4 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
sudo sha256sum /dev/disk/by-partlabel/luma-root-a /dev/disk/by-partlabel/luma-hash-a
```

Expected: `luma.slot=b`; release `luma-native-lab-20260927-desktop-20`;
`LUMA_BOOT_HEALTH_OK`; `installed.json` at sequence 20; `NO-PENDING`; kernel
`6.8.0-142-generic`; Secure Boot `1`; the slot-A
hashes equal to S4. The user's files and settings from S3 are still there.
Check the GNOME login and session again.

### S7. Refusals on the updated system

Mount each stick as in S5, run the update, and unmount it.

- Sequence-19 stick: refused with `update sequence must increase`.
- Sequence-20 stick again: refused with the same message.

No `UPDATE` confirmation may be requested in either case.

### S8. Recovery from the sequence-20 stick

Boot the sequence-20 stick with the installed disk attached but not mounted.
Run S1's checks once more on this stick (expect release
`luma-native-lab-20260927-desktop-20`). Then, with the installed disk's
by-id name:

```sh
luma-platform recover unlock /dev/disk/by-id/EXACT-TARGET-DISK-ID
luma-platform recover repair-data /dev/disk/by-id/EXACT-TARGET-DISK-ID
```

For the export, use separate storage formatted ext4: physically a second
stick or disk, in the VM the export disk from section 6.

```sh
mkfs.ext4 -L luma-export /dev/disk/by-id/EXACT-EXPORT-DISK-ID    # VM: virtio-LUMA-EXPORT
mkdir -p /mnt/export && mount /dev/disk/by-id/EXACT-EXPORT-DISK-ID /mnt/export
mkdir -m 700 /mnt/export/luma-export
luma-platform recover export /dev/disk/by-id/EXACT-TARGET-DISK-ID /mnt/export/luma-export
ls -l /mnt/export/luma-export
umount /mnt/export
luma-platform recover disable-model /dev/disk/by-id/EXACT-TARGET-DISK-ID
luma-platform recover repair-b /dev/disk/by-id/EXACT-TARGET-DISK-ID /media/luma
```

Each command shows the disk identity and asks for an exact word (`RECOVER`,
`REPAIR-DATA` or `REPAIR`, with the identity). Use the independent recovery
passphrase. The export writes `luma-user-data.tar`, which is **unencrypted**:
keep it private and never return it. `repair-b` rewrites only slot b's root,
hash and UKI; it does not format the data.

**S8b, optional: older-stick repair refusal.** Boot the sequence-19 stick and
run `luma-platform recover repair-b /dev/disk/by-id/EXACT-TARGET-DISK-ID /media/luma`.
Expected: refused with "laboratory repair cannot lower target release
sequence…", before any confirmation.

### S9. Without the model (A004)

Boot the installed disk after S8 (the model is now disabled):

```sh
sudo luma-platform boot-health
sudo test -e /var/lib/luma-os/model-disabled && echo MODEL-DISABLED
sudo systemctl --no-pager --failed
```

Expected: `LUMA_BOOT_HEALTH_OK`, `MODEL-DISABLED`, and the desktop and manual
workspace still work. To undo the disablement, remove the marker. Starting the
service is only meaningful if a model was activated:

```sh
sudo rm -- /var/lib/luma-os/model-disabled
sudo systemctl start luma-model.service
```

NF13 (the interface survives a killed model) needs an activated model, which
inert staging does not provide. Run it only if the model was activated through
the reviewed flows: `sudo systemctl kill --signal=KILL luma-model.service`, and
the desktop must keep working. Otherwise record NF13 `blocked`.

### S10. Power (physical machine)

```sh
sudo systemctl hibernate
```

Expected: refused; the machine does not hibernate (`hibernate.target` refuses
manual start).

Suspend, 100 cycles (A008, row R0):

```sh
for i in $(seq 1 100); do sudo rtcwake -m mem -s 30 || break; echo "cycle $i"; done
journalctl -b -g 'PM: suspend exit' | wc -l
sudo systemctl --no-pager --failed
sudo systemctl --no-pager is-active luma-broker luma-reference
```

Expected: 100 cycles, 100 `PM: suspend exit` lines, no failed unit, the
services active again. In a VM this row is `not_applicable`.

### S11. Admin (optional, after S9)

Product Admin ceremonies are outside this procedure. See the sequence-19
record, section "First installed boot and governed setup".

### S12. Fresh install of sequence 20

Use the same target (it is erased) or a second disposable disk. VM: a new
folder with fresh `vars.fd`, `tpm` and `target.qcow2` (section 6, with
`$IMG20`). Boot the sequence-20 stick, run S1, then S2 with
`--stage-model manual-only`, then S3. Expected: the same results with release
`luma-native-lab-20260927-desktop-20`, and boot health with no model staged.

### S13. Tamper tests (VM only)

Run each in a **new** folder with fresh enrolled `vars.fd` and `tpm` (section
6), and add `-no-reboot` so the VM stops instead of rebooting. Neither test
changes the downloaded image.

Corrupted root (dm-verity):

```sh
sgdisk --info=2 "$IMG20" | grep "Partition name: 'luma-live-root'"
first=$(sgdisk --info=2 "$IMG20" | awk '/^First sector:/ {print $3}')
qemu-img create -f qcow2 -F raw -b "$IMG20" corrupt.qcow2
qemu-io -f qcow2 -c "write -P 85 $((first*512)) 4096" corrupt.qcow2
run_vm serial-S13-verity.log -no-reboot \
  -drive if=none,id=media,format=qcow2,readonly=on,file=corrupt.qcow2 \
  -device virtio-blk-pci,drive=media,serial=LUMA-LIVE,bootindex=1
```

Expected on the serial console: `device-mapper: verity: … data block 0 is
corrupted`, then `Kernel panic`.

Unsigned bootloader (Secure Boot):

```sh
sgdisk --info=1 "$IMG20" | grep "Partition name: 'LUMA-LIVE-ESP'"
first=$(sgdisk --info=1 "$IMG20" | awk '/^First sector:/ {print $3}')
last=$(sgdisk --info=1 "$IMG20" | awk '/^Last sector:/ {print $3}')
dd if="$IMG20" of=esp.fat bs=512 skip="$first" count=$((last - first + 1)) status=progress
mcopy -i esp.fat ::/EFI/BOOT/BOOTX64.EFI unsigned.efi
sbattach --remove unsigned.efi
mcopy -o -i esp.fat unsigned.efi ::/EFI/BOOT/BOOTX64.EFI
run_vm serial-S13-unsigned.log -no-reboot \
  -drive if=none,id=media,format=raw,readonly=on,file=esp.fat \
  -device virtio-blk-pci,drive=media,serial=LUMA-LIVE,bootindex=1
```

Expected: `BdsDxe: failed to load/start …` with `Access Denied` or `Security
Violation`, and no Luma boot. The repository's `secure_boot_negative.py` and
`verity_negative.py` automate the same two tests in the tools container
([image guide](../image/README.md#testing-a-transferred-image-without-rebuilding-it)).

### S14. Restore the firmware keys (physical)

In the firmware setup, delete only the laboratory entry from `db`. Then compare
the keys with the backup from section 7:

```powershell
$ka = 'C:\LumaTest\firmware-keys-after'
New-Item -ItemType Directory -Path $ka | Out-Null
foreach ($v in 'PK', 'KEK', 'db', 'dbx') {
  Get-SecureBootUEFI -Name $v -OutputFilePath "$ka\$v.bin"
  '{0} {1}' -f $v, ((Get-FileHash "$kb\$v.bin").Hash -eq (Get-FileHash "$ka\$v.bin").Hash)
}
```

Every line should print `True`. Avoid a "restore factory keys" action: it can
roll `dbx` back to an older revocation list. If one was used, compare `dbx`
with the backup and record the difference. Resume BitLocker if it was
suspended.

## 9. Acceptance checklist

Results are `pass`, `fail`, `blocked` or `not_applicable`. Rows follow the
[physical qualification runbook](../../docs/gates/g2/PHYSICAL_QUALIFICATION_RUNBOOK.md).

| # | Check | Step | Requirement IDs | Row | Expected | Result |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Both sets verify against the repository pins | §4 | A097, FR05 | P3 | pin `True`/`OK`; every file `OK`, including `.img` | |
| 2 | Stick read-back hash (Linux writer only) | §5 | FR05 | P3 | equals the `.img` hash | |
| 3 | Firmware keys backed up, cert appended to `db`, Secure Boot on | §7 | A104 | P3 | backup files present; `od` prints `1` in S1 | |
| 4 | Live command line, verity root, read-only payload mount | S1 | A104, A005 | P3 | as listed in S1 | |
| 5 | Inventory before install | S1 | A001, A108 | P0 | lists the target with serial, WWN and size | |
| 6 | TPM probe, AppArmor enforce, no failed unit, keeper and producer active | S1 | A104 | P3 | all pass | |
| 7 | Ubuntu 24.04 and kernel track | S1, S3, S6 | A101, A103 | P3 | `24.04`; 19 and 20: `6.8.0-142-generic` | |
| 8 | Payload verify (signed release record) | S1 | A097, FR05 | P3 | exit 0, release named | |
| 9 | Exact destination disk, `ERASE <identity>` | S2 | A002, A108 | P0, P1 | identity shown; nothing written before confirmation | |
| 10 | Explicit accounts, four credentials, no empty password | S2, S3 | A006 | P1 | prompts as described; `awk` prints nothing | |
| 11 | Model staged at install, not in the base image | S2 | A003 | P1 | known gap: the model is downloaded, not in the image; record `fail` with that note | |
| 12 | First boot health, LUKS2, desktop session | S3 | A104, A107, A108 | P1, P5 | `LUMA_BOOT_HEALTH_OK`; LUKS2; GNOME login, lock, reboot, shutdown work | |
| 13 | Update 19 to 20 staged on slot b only | S5 | A110, A095 | P4 | messages as in S5 | |
| 14 | Slot A unchanged by the update | S4, S6 | A105 | P4 | partition hashes equal | |
| 15 | Healthy promotion to 20, data kept | S6 | A005, A110 | P4 | slot b, sequence 20, no pending, data present | |
| 16 | Three failed trials, then the previous release | S5b | A106, NF18 | P4 | slot a, `failed-update.json`, sequence 19; re-stage works | |
| 17 | Older and equal sequence refused | S7 | A095 | P4 | `update sequence must increase` | |
| 18 | Recovery unlock, repair-data, export, disable-model, repair-b | S8 | A007, A107, A005 | P2, P5 | each succeeds with the recovery passphrase | |
| 19 | Older-stick repair refused | S8b | A095, A005 | P4 | refused before confirmation | |
| 20 | Boot, desktop and recovery without the model | S9, S12 | A004 | P2 | boot health OK; desktop works | |
| 21 | UI survives a killed model | S9 | NF13 | none | `blocked` unless a model was activated | |
| 22 | Hibernation refused | S10 | A008 | R0 | refused | |
| 23 | 100 suspend cycles | S10 | A008 | R0 | 100 cycles, services back | |
| 24 | Fresh sequence-20 install, manual-only | S12 | A001-A004, A006, A104, A107 | P1, P3 | as S1-S3 | |
| 25 | Corrupted root refused | S13 | A104, FR05 | P3 | verity error, panic | |
| 26 | Unsigned bootloader refused | S13 | A104, FR05 | P3 | `Access Denied` or `Security Violation` | |
| 27 | Firmware keys restored | S14 | none | | every key matches the backup | |
| 28 | Pinned rebuild | none | A109 | P6 | `not_applicable` here: an agent-side check | |
| 29 | Desktop and headless share APIs | none | A102 | | `not_applicable`: desktop only | |
| 30 | Thermal | none | FR53 | | not covered | |
| 31 | Hyper-V boot with Secure Boot | none | W030, W032 | | `blocked`: lab certificate cannot be enrolled | |

Test IDs per row, from the runbook: P0 T01; P1 T01, T02, T48; P2 T03; P3 T04,
T45, T46; P4 T04, T47, Q15; P5 T48; P6 T49; R0 T05. Kernel track is T51.

## 10. Evidence to return

Return one folder per machine (or VM), for example
`luma-acceptance-19-20-<machine>-<date>`:

- `machine.txt`: vendor, model, firmware version, CPU, RAM, disks and stick
  models (physical); or the host OS, `qemu-system-x86_64 --version`, the
  `ovmf` and `swtpm` package versions and the `run_vm` function as used (VM).
- `pins.txt`: the output of the section-4 checks for both sets, and the stick
  read-back hashes if made.
- `firmware-keys-before/` and `firmware-keys-after/` (public keys only), and
  the certificate fingerprints you compared.
- One log per step: the serial logs (VM) or the console output (physical,
  copied from a terminal or photographed), with every command and its output.
- `journalctl -b -o short-iso` for each installed boot, and
  `journalctl -b -u <unit>` for every failed unit.
- `installed.json`, `failed-update.json` (S5b), `loader.conf` and the
  `ls -l /efi/EFI/Linux` listings from S4, S5b and S6.
- The slot-A partition hashes from S4 and S6.
- The checklist of section 9 with results, and one line for every deviation.

**Never return** passwords, passphrases, the recovery passphrase, the offline
Admin recovery credential (check the S2 serial log; see S2), the export archive
`luma-user-data.tar`, the TPM state folder, `vars.fd`, or any private key.

## 11. What sequence 20 changes

Sequence 20 is cut from the G3 functional branch at `e9a11aa`, 57 commits after
sequence 19's commit `6528ea1` (904 captured files, build inputs
`39b77ac6…`). They change:

- NF08 content search and custody code (content index, v2 publication, the
  content store, content checkpoint, credential observer, independent
  checkpoint and publication fixture) and development-only Cargo profiles. The
  release profile is unchanged.
- Windows packaging and Hyper-V tooling (GWIN0), which is not in the image.
- CI, test runners, build-storage sizing, documentation and evidence.

`platform.rs`, `main.rs`, `bundle.rs` and `staging.rs` in `luma-platform` are
unchanged, so install, update, boot health and recovery run the same code as
sequence 19.

## 12. Not tested and known risks

- The update path has not been tested since 2026-09-27 (sequence 1 to 2,
  headless, KVM, Secure Boot off). It has never run under Secure Boot or for
  sequences 19 and 20. The fallback (S5b) has never run for these sequences.
  `update_powercut_test.py` has never been run.
- Mounting the update stick by hand on the installed system (S5) has not been
  exercised. Whether the installed desktop mounts the stick by itself is not
  known.
- A USB-class boot has been tested only in a VM: the sequence-20 live smoke
  attached the image as a removable USB mass-storage device on QEMU's xHCI
  controller. Sequence 19 has not been booted as a USB device, and no physical
  USB controller or stick has been used.
- No physical machine, physical stick, Rufus or Win32 Disk Imager has been
  used with these images.
- A stick larger than the image (backup GPT not at the end) has not been booted.
- KVM with Secure Boot, and a GNOME session in a VM, have not been exercised.
- `luma-platform update` needs about 3.3 GiB free on the encrypted `/var`, and
  the live session needs 8 GiB of RAM.
- The sequence-20 ISO has been verified offline but not booted.
