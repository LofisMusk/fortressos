#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Prepare a Linux x86_64 machine for full ROM builds. Works on any Ubuntu
# 22.04/24.04 host: a cloud VM, a rented dedicated server, or your own box.
#
#   sudo ci/rom/setup-host.sh [build-user]
#
# LineageOS 23.2 wants 64 GB RAM and 400 GB of storage (plus ccache), so
# check those before starting a build.
set -euo pipefail

user="${1:-${SUDO_USER:-$USER}}"
srcdir="${SRC:-/mnt/src}"
ccache_size="${CCACHE_SIZE:-50G}"

[ "$(id -u)" = 0 ] || { echo "setup-host: run with sudo" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update
# Package list from the LineageOS build guide, plus ccache and git-lfs.
apt-get install -y --no-install-recommends \
	bc bison build-essential ca-certificates ccache curl flex git git-lfs \
	gnupg gperf imagemagick libelf-dev liblz4-tool libncurses-dev \
	libsdl1.2-dev libssl-dev libxml2 libxml2-utils lzop openssh-client \
	pngcrush python3 python-is-python3 rsync schedtool squashfs-tools \
	unzip xsltproc zip zlib1g-dev

install -d -m 0755 /usr/local/bin
curl -fsSL https://storage.googleapis.com/git-repo-downloads/repo \
	-o /usr/local/bin/repo
chmod 0755 /usr/local/bin/repo

# Soong and the linker are memory hungry; swap keeps a big build alive.
if [ ! -e /swapfile ] && [ "$(free -g | awk '/^Mem:/{print $2}')" -lt 96 ]; then
	fallocate -l 16G /swapfile
	chmod 600 /swapfile
	mkswap -q /swapfile
	swapon /swapfile
	grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

install -d -o "$user" -g "$user" "$srcdir" "$srcdir/ccache"
su - "$user" -c "ccache --set-config=cache_dir=$srcdir/ccache \
	--set-config=max_size=$ccache_size --set-config=compression=true"

echo "setup-host: ready. Source dir: $srcdir, ccache: $ccache_size"
free -h | head -2
df -h "$srcdir" | tail -1
