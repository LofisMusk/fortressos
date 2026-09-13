#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Compile the real a52sxq kernel (LineageOS sm7325 tree, pinned) with the
# Fortress LSM, using the same AOSP clang the LineageOS 23.2 build uses.
#
#   VARIANT=develop|release ci/kernel-build.sh
#
# Output: $WORK/out/arch/arm64/boot/Image and $WORK/out/.config
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
work="${WORK:-$root/out/device-kernel}"
variant="${VARIANT:-develop}"
jobs="$(nproc)"

# Pins: bump deliberately, together with docs/DEVICE_A52SXQ.md.
kernel_repo=https://github.com/LineageOS/android_kernel_samsung_sm7325.git
kernel_ref="${KERNEL_REF:-12334aaea98147c1739de857b4f36f8949a3f095}" # lineage-23.2
clang_repo=https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86
aosp_tag=android-16.0.0_r4           # LineageOS 23.2 "aosp" remote revision
clang_version=clang-r563880c         # soong ClangDefaultVersion at that tag
defconfig=vendor/lineage-a52sxq_defconfig

case "$variant" in develop|release) ;; *)
	echo "kernel-build: VARIANT must be develop or release" >&2; exit 1 ;;
esac

mkdir -p "$work"
cd "$work"

# 1. Kernel source at the pinned commit.
if [ ! -d kernel/.git ]; then
	git init -q kernel
	git -C kernel remote add origin "$kernel_repo"
fi
git -C kernel fetch -q --depth 1 origin "$kernel_ref"
git -C kernel checkout -q --force FETCH_HEAD
git -C kernel clean -qfdx

# 2. Only the one clang directory from AOSP prebuilts (partial clone).
if [ ! -x "clang/$clang_version/bin/clang" ]; then
	rm -rf clang
	git clone -q --depth 1 --filter=blob:none --no-checkout \
		--branch "$aosp_tag" "$clang_repo" clang
	git -C clang sparse-checkout set --no-cone "/$clang_version/"
	git -C clang checkout -q
fi
export PATH="$work/clang/$clang_version/bin:$PATH"
clang --version | head -1

# 3. Fortress + config.
"$root/kernel/integrate.sh" "$work/kernel"

kmake() {
	make -C "$work/kernel" O="$work/out" ARCH=arm64 LLVM=1 LLVM_IAS=1 \
		CROSS_COMPILE=aarch64-linux-gnu- -j"$jobs" "$@"
}

rm -rf "$work/out"
kmake "$defconfig"
"$work/kernel/scripts/kconfig/merge_config.sh" -m -O "$work/out" \
	"$work/out/.config" \
	"$root/kernel/configs/fortress.fragment" \
	"$root/kernel/configs/$variant.fragment"
kmake olddefconfig

grep -qx 'CONFIG_SECURITY_FORTRESS=y' out/.config
grep -q '^CONFIG_LSM=".*fortress' out/.config
if [ "$variant" = release ]; then
	grep -qx '# CONFIG_SECURITY_FORTRESS_DEVELOP is not set' out/.config
else
	grep -qx 'CONFIG_SECURITY_FORTRESS_DEVELOP_PERMISSIVE=y' out/.config
fi

# 4. Build. Not W=1: it applies tree-wide and trips Samsung's
# forbidden-warning check in vDSO code. security/fortress/Makefile adds
# its own extra warnings, and any warning there fails the job.
kmake Image 2>&1 | tee build.log
if grep -E 'security/fortress/[^ ]*: (warning|error):' build.log; then
	echo "kernel-build: warnings in security/fortress" >&2
	exit 1
fi

echo "kernel-build: $work/out/arch/arm64/boot/Image ($variant)"
