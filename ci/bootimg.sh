#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Build a flashable boot.img that puts the Fortress kernel on the phone
# without building a whole ROM: take the official LineageOS boot.img for
# a52sxq, swap in our kernel built from the very revision that build used,
# and repack. Everything else (ramdisk, vendor partitions, modules, the
# signed system image) stays exactly as LineageOS shipped it.
#
#   ci/bootimg.sh            build against the newest official build
#   SKIP_BUILD=1 ci/bootimg.sh   repack with the stock kernel (self-test)
#
# Output in $WORK: boot-fortress.img, boot-stock.img (for rollback),
# SHA256SUMS and FLASH.md.
#
# The module ABI is the constraint: Samsung's drivers only load when the
# kernel release string matches, so the script fails unless our kernel
# reports exactly the same "Linux version" as the official one.
set -euo pipefail

# macOS has shasum, Linux has sha256sum.
if ! command -v sha256sum >/dev/null; then
	sha256sum() { shasum -a 256 "$@"; }
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
work="${WORK:-$root/out/bootimg}"
device="${DEVICE:-a52sxq}"
variant="${VARIANT:-develop}"
api="https://download.lineageos.org/api/v2/devices/$device/builds"

mkdir -p "$work"
cd "$work"

# 1. Newest official build: boot.img + the manifest that pins every revision.
curl -fsSL --max-time 120 "$api" -o builds.json
eval "$(python3 - "$device" <<'PY'
import json, sys
builds = json.load(open('builds.json'))
build = builds[-1]
files = {f['filename']: f for f in build['files'] if 'filename' in f}
boot = files['boot.img']
manifest = files['build-manifest.xml']
print(f"boot_url={boot['url']}")
print(f"boot_sha256={boot['sha256']}")
print(f"manifest_url={manifest['url']}")
print(f"build_date={build['date']}")
PY
)"
echo "bootimg: official build $build_date"

[ -f boot-stock.img ] || curl -fsSL --max-time 900 "$boot_url" -o boot-stock.img
echo "$boot_sha256  boot-stock.img" | sha256sum -c -
curl -fsSL --max-time 300 "$manifest_url" -o build-manifest.xml

kernel_ref=$(python3 - <<'PY'
import re
xml = open('build-manifest.xml', encoding='utf-8').read()
m = re.search(r'<project[^>]*android_kernel_samsung_sm7325[^>]*>', xml)
print(re.search(r'revision="([0-9a-f]{40})"', m.group(0)).group(1))
PY
)
echo "bootimg: kernel revision $kernel_ref"

# 2. AOSP boot image tools.
[ -d mkbootimg ] || git clone -q --depth 1 \
	https://android.googlesource.com/platform/system/tools/mkbootimg

rm -rf stock
python3 mkbootimg/unpack_bootimg.py \
	--boot_img boot-stock.img --out stock --format mkbootimg > mkbootimg.args
release=$(strings -a stock/kernel | sed -n 's/^Linux version \([^ ]*\) .*/\1/p' | head -1)
echo "bootimg: stock kernel $release"

# 3. Our kernel, same revision, same version string (module ABI).
if [ "${SKIP_BUILD:-0}" = 1 ]; then
	cp stock/kernel fortress-kernel
else
	localversion=$(curl -fsSL --max-time 60 \
		"https://raw.githubusercontent.com/LineageOS/android_kernel_samsung_sm7325/$kernel_ref/arch/arm64/configs/vendor/lineage-${device}_defconfig" |
		sed -n 's/^CONFIG_LOCALVERSION="\(.*\)"$/\1/p')
	base=${release%%-*}
	scmversion=${release#"$base$localversion"}
	[ "$scmversion" != "$release" ] ||
		{ echo "bootimg: cannot derive scmversion from $release" >&2; exit 1; }
	echo "bootimg: base=$base localversion=$localversion scmversion=$scmversion"

	KERNEL_REF="$kernel_ref" SCMVERSION="$scmversion" VARIANT="$variant" \
		WORK="$work/device-kernel" "$root/ci/kernel-build.sh"
	cp "$work/device-kernel/out/arch/arm64/boot/Image" fortress-kernel
	cp "$work/device-kernel/out/.config" kernel.config
fi

ours=$(strings -a fortress-kernel | sed -n 's/^Linux version \([^ ]*\) .*/\1/p' | head -1)
if [ "$ours" != "$release" ]; then
	echo "bootimg: version mismatch, vendor modules would not load" >&2
	echo "         stock: $release" >&2
	echo "         ours:  $ours" >&2
	exit 1
fi

# 4. Repack with the stock header, ramdisk and arguments.
rm -f boot-fortress.img
cp fortress-kernel stock/kernel
# Parsed with shlex, not by word splitting: the stock cmdline is empty and
# "--cmdline ''" would otherwise land in the image as two quote characters.
python3 - <<'REPACK'
import shlex, subprocess, sys
args = shlex.split(open('mkbootimg.args').read())
subprocess.run([sys.executable, 'mkbootimg/mkbootimg.py', *args,
                '--output', 'boot-fortress.img'], check=True)
REPACK

stock_size=$(wc -c < boot-stock.img)
new_size=$(wc -c < boot-fortress.img)
[ "$new_size" -le "$stock_size" ] ||
	{ echo "bootimg: repacked image larger than the boot partition" >&2; exit 1; }

sha256sum boot-fortress.img boot-stock.img > SHA256SUMS

cat > FLASH.md <<EOF
# Fortress kernel on stock LineageOS ($device, build $build_date)

Kernel $release, Fortress LSM ($variant). Everything else is LineageOS's
official signed build, so install that ROM first and check it boots.

In $variant builds the guard starts permissive: it only logs what it would
deny, so the phone keeps working while we collect evidence.

## Flash A: from LineageOS Recovery (needs only adb)

    adb push boot-fortress.img /tmp/
    adb shell 'dd if=/tmp/boot-fortress.img of=/dev/block/by-name/boot bs=4M'
    adb shell sync

## Flash B: from Download mode with samloader-rs

Samsung has no fastboot. samloader-rs is what the LineageOS wiki uses for
these devices, and it runs on macOS, Linux and Windows:
https://github.com/topjohnwu/samloader-rs/releases/latest

Power the phone off, hold Volume Up + Volume Down, plug in USB, confirm
"Continue", then:

    samloader print-pit                                  # connection test
    samloader flash --partition BOOT boot-fortress.img

Reboot. If anything misbehaves, flash the stock kernel back the same way;
download it from LineageOS if you no longer have boot-stock.img:

    $boot_url
    sha256: $boot_sha256

## Check the guard

    adb shell cat /sys/kernel/security/lsm            # must list fortress
    adb shell cat /sys/kernel/security/fortress/status
    adb shell dmesg | grep fortress                   # needs root

Report back: does Wi-Fi work (vendor modules loaded), does the phone boot,
and what "would deny" lines appear.
EOF

echo "bootimg: ready"
ls -la boot-fortress.img boot-stock.img
