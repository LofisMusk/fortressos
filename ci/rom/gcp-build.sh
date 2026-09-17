#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Build Fortress OS on a Google Cloud VM, sized for LineageOS 23.2
# (64 GB RAM, 500 GB disk) and paid for out of the free trial credits.
#
#   ci/rom/gcp-build.sh up        create the VM (data disk is reused)
#   ci/rom/gcp-build.sh setup     install toolchain on the VM
#   ci/rom/gcp-build.sh build     start the build in the background
#   ci/rom/gcp-build.sh status    tail the build log
#   ci/rom/gcp-build.sh fetch     copy target-files + otatools here
#   ci/rom/gcp-build.sh down      delete the VM, KEEP the source disk
#   ci/rom/gcp-build.sh destroy   delete the VM and the source disk
#   ci/rom/gcp-build.sh all       up + setup + build (then watch status)
#
# Costs while running, order of magnitude: the VM is a few dollars per
# build, the 500 GB disk about $2 a day for as long as it exists. "down"
# stops the VM charge and keeps the synced sources and ccache, so the next
# build is much faster; "destroy" stops all charges.
#
# Requires the gcloud CLI, logged in, with a project selected:
#   gcloud auth login && gcloud config set project <project-id>
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
zone="${ZONE:-europe-west4-a}"
region="${zone%-*}"
vm="${VM:-fortress-build}"
disk="${DISK:-fortress-src}"
disk_size="${DISK_SIZE:-500GB}"
machine="${MACHINE:-c2d-standard-16}"      # 16 vCPU, 64 GB RAM
image_family="${IMAGE_FAMILY:-ubuntu-2404-lts-amd64}"
variant="${VARIANT:-develop}"
repo_url="${REPO_URL:-$(git -C "$root" remote get-url origin 2>/dev/null || echo https://github.com/LofisMusk/fortressos)}"
branch="${BRANCH:-main}"
remote_src=/mnt/src
remote_repo="$remote_src/fortressos"
log="$remote_src/build.log"

gssh() { gcloud compute ssh "$vm" --zone "$zone" --tunnel-through-iap=false --command "$1"; }

need_gcloud() {
	command -v gcloud >/dev/null ||
		{ echo "gcp-build: install the gcloud CLI first" >&2; exit 1; }
	gcloud config get-value project 2>/dev/null | grep -qv '^(unset)$' ||
		{ echo "gcp-build: run 'gcloud config set project <id>'" >&2; exit 1; }
}

check_quota() {
	local cpus
	cpus=$(gcloud compute regions describe "$region" \
		--format='value[](quotas.filter("metric=CPUS").extract(limit))' 2>/dev/null |
		tr -d '[]' | cut -d. -f1)
	local want="${machine##*-}"
	if [ -n "$cpus" ] && [ "$cpus" -lt "$want" ] 2>/dev/null; then
		echo "gcp-build: CPUS quota in $region is $cpus, $machine needs $want." >&2
		echo "           Request more quota, or use MACHINE=n2d-highmem-8 (8 vCPU, 64 GB)." >&2
		exit 1
	fi
}

cmd_up() {
	need_gcloud
	check_quota
	gcloud compute disks describe "$disk" --zone "$zone" >/dev/null 2>&1 ||
		gcloud compute disks create "$disk" --zone "$zone" \
			--size "$disk_size" --type pd-balanced
	if gcloud compute instances describe "$vm" --zone "$zone" >/dev/null 2>&1; then
		echo "gcp-build: $vm already exists"
	else
		gcloud compute instances create "$vm" --zone "$zone" \
			--machine-type "$machine" \
			--image-family "$image_family" --image-project ubuntu-os-cloud \
			--boot-disk-size 50GB --boot-disk-type pd-balanced \
			--disk "name=$disk,device-name=$disk,mode=rw,auto-delete=no" \
			--scopes storage-ro \
			--labels purpose=fortress-rom-build
	fi
	echo "gcp-build: waiting for ssh"
	until gssh true 2>/dev/null; do sleep 10; done
}

cmd_setup() {
	need_gcloud
	# Format the data disk on first use only; never touch an existing one.
	gssh "set -e
		dev=/dev/disk/by-id/google-$disk
		sudo blkid \$dev >/dev/null 2>&1 || sudo mkfs.ext4 -q -m0 \$dev
		sudo mkdir -p $remote_src
		mountpoint -q $remote_src || sudo mount \$dev $remote_src
		grep -q ' $remote_src ' /etc/fstab ||
			echo \"\$(sudo blkid -s UUID -o value \$dev) $remote_src ext4 defaults,nofail 0 2\" |
			sudo tee -a /etc/fstab >/dev/null
		sudo chown \$USER:\$USER $remote_src
		if [ -d $remote_repo/.git ]; then
			git -C $remote_repo fetch -q origin $branch && git -C $remote_repo checkout -q -f origin/$branch
		else
			git clone -q --branch $branch $repo_url $remote_repo
		fi
		sudo $remote_repo/ci/rom/setup-host.sh \$USER"
}

cmd_build() {
	need_gcloud
	gssh "cd $remote_repo && git log --oneline -1 &&
		setsid nohup env SRC=$remote_src/lineage VARIANT=$variant \
			ci/rom/build.sh > $log 2>&1 < /dev/null &
		sleep 2; echo 'gcp-build: started, log: $log'"
}

cmd_status() {
	need_gcloud
	gssh "tail -n 40 -f $log"
}

cmd_fetch() {
	need_gcloud
	mkdir -p "$root/out/rom"
	gcloud compute scp --zone "$zone" --recurse \
		"$vm:$remote_src/lineage/out/target/product/a52sxq/obj/PACKAGING/target_files_intermediates/*target_files*.zip" \
		"$vm:$remote_src/lineage/out/host/linux-x86/otatools.zip" \
		"$root/out/rom/"
	(cd "$root/out/rom" && shasum -a 256 ./*.zip | tee SHA256SUMS)
	echo "gcp-build: artifacts in $root/out/rom - sign them offline (docs/SIGNING.md)"
}

cmd_down() {
	need_gcloud
	gcloud compute instances delete "$vm" --zone "$zone" --quiet
	echo "gcp-build: VM deleted, disk $disk kept (about \$2/day)."
}

cmd_destroy() {
	need_gcloud
	gcloud compute instances delete "$vm" --zone "$zone" --quiet 2>/dev/null || true
	gcloud compute disks delete "$disk" --zone "$zone" --quiet
}

case "${1:-}" in
up)      cmd_up ;;
setup)   cmd_setup ;;
build)   cmd_build ;;
status)  cmd_status ;;
fetch)   cmd_fetch ;;
down)    cmd_down ;;
destroy) cmd_destroy ;;
ssh)     need_gcloud; gcloud compute ssh "$vm" --zone "$zone" ;;
all)     cmd_up; cmd_setup; cmd_build; echo "watch it with: $0 status" ;;
*)       sed -n '4,20p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
