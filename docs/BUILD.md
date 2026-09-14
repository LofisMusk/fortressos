# Building and testing

Three levels. The first runs anywhere, the second on free GitHub runners,
the third needs a big Linux machine.

## 1. Host tests (macOS or Linux)

```
make -C tools/fortress-policy test
```

Runs the policy compiler unit tests, plus the **kernel's own parser and
Identity Guard path rules** compiled for the host under ASan/UBSan. Checks
include every truncation, every single-bit flip, 25 targeted malformed
blobs, and the glob matcher plus every `/proc` and `/sys` rule it drives.
`make ... fuzz` runs libFuzzer against the parser and the matcher; it needs
LLVM clang, not Apple clang.

## 2. Kernel CI (free GitHub Actions)

`.github/workflows/kernel.yml`, on `ubuntu-22.04` runners. The repo must be
**public** for unlimited free minutes.

| Job | What it proves |
|---|---|
| `policy-tools` | as above, plus 2 minutes of fuzzing per target |
| `qemu-test` | vanilla Linux 5.4.254 (sha256-pinned) + Fortress boots in QEMU arm64. `tests/kernel/fortress_test.c` checks the gate, egress, IPC, profile, identity denials and reload behaviour through real syscalls as different uids |
| `device-kernel` | the real a52sxq tree at a pinned commit compiles with Fortress under AOSP `clang-r563880c` (ThinLTO+CFI), `develop` and `release` variants; `security/fortress` must build warning-free with its extra `-Wmissing-prototypes`/`-Wmissing-declarations` |

Local equivalent, on any Linux box or in Docker:

```
docker build -t fortress-ci ci/
docker run --rm -v "$PWD":/src -w /src fortress-ci ci/qemu-test.sh
```

The kernel source has to sit on a case-sensitive filesystem. macOS volumes
normally aren't, which is why these steps run in Linux.

## 3. Full ROM (Phase 1)

`ci/rom/build.sh` has **not been run yet**. It needs Linux x86_64 with about
300 GB of disk and 32-64 GB of RAM. AOSP does not build on macOS, and a free
runner has about 14 GB of disk and a 6-hour limit, so the options are:

- **crave.io**: free build servers for FOSS ROM projects. Self-signup is
  closed; ask for access through the crave community. The workflow gets
  added once there is access.
- Any rented or owned Linux machine.

The disk figure is measured, not guessed. A `repo init -b lineage-23.2`
followed by `repo sync -c --depth=1 --no-tags` (the cheapest sync that can
still build) was run on a 4-core, 15 GB-RAM box with 29 GB free and stopped
by a watchdog at 5 GB remaining:

| After | Projects | Git objects | Working tree | Total |
|---|---|---|---|---|
| ~4 min | 504 of 1171 | 5.1 GB | 22 GB | 27 GB |

That is 43 % of the manifest for 27 GB, so the source alone extrapolates to
**at least ~60 GB**, and the projects not yet reached include the heaviest
ones (`prebuilts/clang`, `prebuilts/rust`, the prebuilt WebView). The `out/`
tree for `target-files-package` comes on top of that. The device and
`sm7325-common` projects from `manifests/fortress.xml` did resolve and sync
against `lineage-23.2` before the abort, so the local manifest itself is
good; only the machine is too small.

The output is **unsigned** `target-files` + `otatools`. Signing happens
offline, see [SIGNING.md](SIGNING.md).

## Reproducibility

- Kernel CI pins the kernel commit, the clang version plus AOSP tag, the
  Linux 5.4.254 tarball sha256, the Docker base image digest, and the
  GitHub Actions commit SHAs.
- For releases, `repo manifest -r` snapshots every project revision. The
  snapshot is committed next to the release notes, so anyone can rebuild
  and compare hashes.
