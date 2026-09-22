# Fortress OS

A privacy-focused, fail-closed Android OS based on LineageOS 23.2 for the
Samsung Galaxy A52s 5G (SM-A528B/DS, `a52sxq`).

Apps are treated as hostile. They must never see the real hardware
identity, location or network path, and when a protection fails, access is
denied. Nothing falls back to real data.

**The guard is part of the kernel, not a process.** A stacked LSM plus
kernel-registered netfilter hooks enforce the policy. With no policy loaded,
no app can start and no packet can leave the device. Framework code only
virtualises what the kernel cannot see (`Build.*`, location, sensors), and it
aborts on error.

## Status

Phase 0 is done and verified in CI: the Fortress LSM core (launch gate,
fail-closed egress / VPN kill switch, unix IPC isolation) passes 54 runtime
checks on Linux 5.4.254 in QEMU, and it builds warning-free into the real
a52sxq kernel (AOSP clang 21, ThinLTO, CFI). It has not run on the phone
yet. The full ROM build (Phase 1) is next. See
[docs/ROADMAP.md](docs/ROADMAP.md).

## Layout

| Path | |
|---|---|
| `kernel/security/fortress/` | the LSM (goes into the kernel tree as `security/fortress/`) |
| `kernel/integrate.sh`, `kernel/configs/` | wiring into any 5.4 tree, config fragments |
| `app/guard/` | **Fortress Guard**, the on-device view: which apps the guard blocked from launching, from the network and from each other |
| `app/telemetry/` | **Fortress Telemetry**, the app-side attack surface: every identity source an unrooted app can still read, tagged by how much it is worth to a tracker |
| `tools/fortress-policy/` | policy compiler (JSON → blob), parser tests, fuzzer |
| `tests/kernel/` | QEMU runtime test (`/init`) and test policies |
| `ci/` | kernel build, QEMU test, ROM build script, Docker env |
| `sepolicy/fortress/`, `platform/` | drafts for Phase 3 |
| `manifests/` | LineageOS local manifest |
| `signing/` | offline key generation |
| `docs/` | [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md), [device notes](docs/DEVICE_A52SXQ.md), [build](docs/BUILD.md), [signing](docs/SIGNING.md), [AVF result](docs/research/AVF.md) |

## Quick start

```
make -C tools/fortress-policy test      # host tests, macOS or Linux
ci/qemu-test.sh                         # Linux: build 5.4 + LSM, run in QEMU
VARIANT=develop ci/kernel-build.sh      # Linux: real a52sxq kernel with Fortress
```

Licensed GPL-2.0 (kernel code and tools).
