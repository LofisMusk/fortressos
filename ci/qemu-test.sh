#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Runtime test of the Fortress LSM: build vanilla Linux 5.4.254 (arm64)
# with fortress integrated, boot it in QEMU "virt" with tests/kernel/
# fortress_test.c as /init, and require "FORTRESS-TESTS: PASS".
#
# The device kernel (Samsung sm7325) is only compile-tested in CI; the
# guard itself uses nothing but upstream LSM/netfilter APIs, so its
# behaviour is exercised here on the same kernel version.
#
# Host requirements: see ci/packages.txt (Ubuntu 22.04).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
work="${WORK:-$root/out/qemu}"
kver=5.4.254
ksha256=51608da961b5e34d6a9452a7b302699e109633f769a4253c74b1048abba8d9c7
cross="${CROSS_COMPILE:-aarch64-linux-gnu-}"
jobs="$(nproc)"

mkdir -p "$work"
cd "$work"

# 1. Pinned, checksummed kernel source.
tarball="linux-$kver.tar.xz"
if [ ! -f "$tarball" ]; then
	curl -fsSL -o "$tarball.tmp" \
		"https://cdn.kernel.org/pub/linux/kernel/v5.x/$tarball"
	mv "$tarball.tmp" "$tarball"
fi
echo "$ksha256  $tarball" | sha256sum -c -

rm -rf "linux-$kver"
tar -xf "$tarball"
ksrc="$work/linux-$kver"
"$root/kernel/integrate.sh" "$ksrc"

# 2. Configure and build.
make -C "$ksrc" ARCH=arm64 CROSS_COMPILE="$cross" \
	KCONFIG_ALLCONFIG="$root/kernel/configs/qemu-arm64.fragment" allnoconfig
# Every fragment line must have survived Kconfig dependency resolution.
missing=0
while IFS= read -r line; do
	case "$line" in ''|'#'*) continue ;; esac
	grep -qxF "$line" "$ksrc/.config" || { echo "missing: $line"; missing=1; }
done < "$root/kernel/configs/qemu-arm64.fragment"
grep -qx '# CONFIG_SECURITY_FORTRESS_DEVELOP is not set' "$ksrc/.config" || missing=1
[ "$missing" = 0 ] || { echo "qemu-test: config fragment not applied" >&2; exit 1; }

make -C "$ksrc" ARCH=arm64 CROSS_COMPILE="$cross" -j"$jobs" Image

# 3. Initramfs: static test init + compiled test policies.
"${cross}gcc" -static -O2 -Wall -Wextra -Werror \
	-o fortress_test "$root/tests/kernel/fortress_test.c"
python3 "$root/tools/fortress-policy/fpol.py" compile \
	"$root/tests/kernel/policy/good.json" -o good.bin
python3 "$root/tools/fortress-policy/fpol.py" compile \
	"$root/tests/kernel/policy/reload.json" -o reload.bin

cc -O2 -o gen_init_cpio "$ksrc/usr/gen_init_cpio.c"
cat > initramfs.list <<EOF
dir /dev 0755 0 0
nod /dev/console 0600 0 0 c 5 1
dir /proc 0755 0 0
dir /sys 0755 0 0
dir /policy 0755 0 0
file /init $work/fortress_test 0755 0 0
file /policy/good.bin $work/good.bin 0644 0 0
file /policy/reload.bin $work/reload.bin 0644 0 0
EOF
./gen_init_cpio initramfs.list > initramfs.cpio

# 4. Boot. The test powers the VM off; panic=-1 + -no-reboot covers crashes.
timeout 600 qemu-system-aarch64 -M virt -cpu cortex-a57 -smp 2 -m 512 \
	-nographic -no-reboot -nic none \
	-kernel "$ksrc/arch/arm64/boot/Image" -initrd initramfs.cpio \
	-append "console=ttyAMA0 panic=-1" | tee qemu.log

grep -q 'fortress: initialized, enforcing' qemu.log ||
	{ echo "qemu-test: fortress did not initialize" >&2; exit 1; }
grep -q 'FORTRESS-TESTS: PASS' qemu.log ||
	{ echo "qemu-test: runtime tests failed" >&2; exit 1; }
echo "qemu-test: PASS"
