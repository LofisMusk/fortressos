#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# UNTESTED SO FAR - first real run is Phase 1 (see docs/BUILD.md).
#
# Full Fortress OS build: produces UNSIGNED target-files and otatools that
# are then signed offline (signing/). Needs Linux x86_64, ~300 GB disk and
# 32-64 GB RAM: a crave.io workspace or an own machine, not a free runner.
#
#   SRC=~/lineage VARIANT=develop ci/rom/build.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
src="${SRC:-$HOME/lineage}"
variant="${VARIANT:-develop}"
device=a52sxq
kdefconfig=kernel/samsung/sm7325/arch/arm64/configs/vendor/lineage-a52sxq_defconfig

mkdir -p "$src"
cd "$src"

if [ ! -d .repo ]; then
	repo init -u https://github.com/LineageOS/android.git -b lineage-23.2 \
		--git-lfs --no-clone-bundle
fi
mkdir -p .repo/local_manifests
cp "$root/manifests/fortress.xml" .repo/local_manifests/fortress.xml
repo sync -c -j"$(nproc)" --force-sync --no-clone-bundle --no-tags

# Start every build from the pristine kernel tree, then add Fortress.
git -C kernel/samsung/sm7325 checkout -- .
git -C kernel/samsung/sm7325 clean -qfd
"$root/kernel/integrate.sh" kernel/samsung/sm7325
# Later assignments override the defconfig's (kconfig "reassigning" rule).
cat "$root/kernel/configs/fortress.fragment" \
    "$root/kernel/configs/$variant.fragment" >> "$kdefconfig"

set +u	# envsetup.sh is not nounset-clean
# shellcheck disable=SC1091
source build/envsetup.sh
breakfast "$device"
m target-files-package otatools-package
set -u

echo "rom-build: unsigned target-files and otatools are in $OUT and out/host"
