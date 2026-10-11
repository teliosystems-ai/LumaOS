#!/bin/bash
# Build the selected NTS+seccomp+capability release candidate without running it.
set -euo pipefail
if [ "$#" -ne 3 ]; then
  echo 'usage: build_release.sh VERIFIED_ARCHIVE NEW_BUILD_DIRECTORY NEW_PACKAGE_DIRECTORY' >&2
  exit 2
fi
if ! command -v pkg-config >/dev/null 2>&1; then
  echo 'protected UTC release build requires pkg-config for NTS and seccomp detection' >&2
  exit 1
fi
archive=$(realpath "$1")
build=$2
package=$3
assets=$(dirname "$(realpath "$0")")
test ! -e "$build"
test ! -e "$package"
test "$(sha256sum "$archive" | cut -d ' ' -f 1)" = 4924c6f530105bcd5b9e9e33c48a2ae1bfd889222c8480bc41601110efc864d0
# A flag in caller JSON cannot authenticate source. Reverify exact signature
# against only the committed reviewed upstream key before source extraction.
mkdir "$build" "$package"
build=$(realpath "$build")
package=$(realpath "$package")
python3 "$assets/verify_release.py" --archive "$archive" --work "$build" \
  --snapshot "$build/authenticated"
# From this point onwards all source, signature and retained provenance reads
# use only the actual authenticated private snapshot, never caller input paths.
archive="$build/authenticated/chrony-4.9.tar.gz"
mkdir "$build/upstream"
tar --no-same-owner --no-same-permissions -xzf "$archive" -C "$build/upstream"
python3 "$assets/prepare_chrony.py" --release-candidate \
  --source "$build/upstream/chrony-4.9" --output "$build/patched"
cd "$build/patched"
export SOURCE_DATE_EPOCH=1787839200
export LC_ALL=C TZ=UTC
export CFLAGS='-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE -ffile-prefix-map='"$build"'=/luma-utc-source'
export LDFLAGS='-Wl,-z,relro,-z,now -pie'
./configure --disable-readline --without-editline --enable-scfilter --with-user=luma-utc-producer \
  --sysconfdir=/usr/share/luma-os/utc --localstatedir=/run
grep -qx '#define FEAT_NTS 1' config.h
grep -qx '#define FEAT_PRIVDROP 1' config.h
grep -qx '#define FEAT_SCFILTER 1' config.h
timeout 300 make -j1 chronyd
./chronyd -v > "$package/version.txt"
grep -q 'chronyd (chrony) version 4.9' "$package/version.txt"
grep -q '+NTS' "$package/version.txt"
grep -q '+SCFILTER' "$package/version.txt"
install -m 0755 chronyd "$package/chronyd"
install -m 0644 COPYING "$package/COPYING.chrony"
install -m 0644 luma-hook-inputs.json "$package/source-inputs.json"
python3 "$assets/verify_release.py" --archive "$archive" --work "$build" > "$package/upstream-provenance.json"
install -m 0644 "$archive.asc" "$package/chrony-4.9.tar.gz.asc"
install -m 0644 "$archive" "$package/chrony-4.9.tar.gz"
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' \
  gcc libc6-dev pkg-config libgnutls28-dev libnettle8t64 libcap-dev libseccomp-dev > "$package/build-packages.tsv"
sha256sum "$package/chronyd" "$package/source-inputs.json" "$package/build-packages.tsv" \
  "$package/upstream-provenance.json" "$package/chrony-4.9.tar.gz.asc" \
  "$package/chrony-4.9.tar.gz" > "$package/SHA256SUMS"
echo LUMA_UTC_RELEASE_CANDIDATE_BUILT_NOT_QUALIFIED
