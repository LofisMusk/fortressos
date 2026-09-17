# Building and testing

Three levels. The first runs anywhere, the second on free GitHub runners,
the third needs a big Linux machine.

## 1. Host tests (macOS or Linux)

```
make -C tools/fortress-policy test
```

Runs the policy compiler unit tests, plus the **kernel's own parser source**
compiled for the host under ASan/UBSan. Checks include every truncation,
every single-bit flip, and 25 targeted malformed blobs. `make ... fuzz` runs
libFuzzer; it needs LLVM clang, not Apple clang.

## 2. Kernel CI (free GitHub Actions)

`.github/workflows/kernel.yml`, on `ubuntu-22.04` runners. The repo must be
**public** for unlimited free minutes.

| Job | What it proves |
|---|---|
| `policy-tools` | as above, plus 2 minutes of fuzzing |
| `qemu-test` | vanilla Linux 5.4.254 (sha256-pinned) + Fortress boots in QEMU arm64. `tests/kernel/fortress_test.c` checks the gate, egress, IPC, profile and reload behaviour through real syscalls as different uids |
| `device-kernel` | the real a52sxq tree at a pinned commit compiles with Fortress under AOSP `clang-r563880c` (ThinLTO+CFI), `develop` and `release` variants; `security/fortress` must build warning-free with its extra `-Wmissing-prototypes`/`-Wmissing-declarations` |

Local equivalent, on any Linux box or in Docker:

```
docker build -t fortress-ci ci/
docker run --rm -v "$PWD":/src -w /src fortress-ci ci/qemu-test.sh
```

The kernel source has to sit on a case-sensitive filesystem. macOS volumes
normally aren't, which is why these steps run in Linux.

## 3. Full ROM (Phase 1)

`ci/rom/build.sh` has **not been run yet**. LineageOS documents 64 GB of RAM
and 400 GB of storage for branch 21 and newer, on Linux x86_64. AOSP does
not build on macOS, and a free runner (about 14 GB of disk, 6 hours) or the
Claude Code cloud VM (4 vCPU, 16 GB RAM, 30 GB disk) are both far too small.

### Google Cloud, on the free trial credits (current path)

`ci/rom/gcp-build.sh` drives a VM sized for the job (16 vCPU, 64 GB RAM,
500 GB data disk) and keeps the source tree and ccache on a disk that
outlives the VM:

```
gcloud auth login && gcloud config set project <project-id>
ci/rom/gcp-build.sh all        # create VM, install toolchain, start build
ci/rom/gcp-build.sh status     # tail the build log
ci/rom/gcp-build.sh fetch      # copy target-files + otatools here
ci/rom/gcp-build.sh down       # delete the VM, keep sources and ccache
```

Rough costs: a few dollars of VM time per build, and about $2 a day for the
500 GB disk while it exists. `down` stops the VM charge; `destroy` removes
the disk too. A fresh trial's CPU quota may be below 16 vCPU: either raise
the quota or run `MACHINE=n2d-highmem-8 ci/rom/gcp-build.sh up` (8 vCPU,
64 GB RAM).

### Any other machine

`ci/rom/setup-host.sh` prepares any Ubuntu 22.04/24.04 host the same way
(packages, `repo`, swap, ccache), so a rented dedicated server, your own
x86 box, or a crave.io workspace all run the same `ci/rom/build.sh`.

The output is **unsigned** `target-files` + `otatools`. Signing happens
offline, see [SIGNING.md](SIGNING.md).

## Reproducibility

- Kernel CI pins the kernel commit, the clang version plus AOSP tag, the
  Linux 5.4.254 tarball sha256, the Docker base image digest, and the
  GitHub Actions commit SHAs.
- For releases, `repo manifest -r` snapshots every project revision. The
  snapshot is committed next to the release notes, so anyone can rebuild
  and compare hashes.
