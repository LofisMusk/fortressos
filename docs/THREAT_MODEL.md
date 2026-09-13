# Threat model

## Assets

Real hardware identity (IMEI, serial, SoC/UFS ids, MAC, build fingerprint),
real location, real network identity (public IP, LAN, Wi-Fi/cell
environment), user files, and one app's data as seen by another.

## In scope

| Adversary | Capabilities assumed | Fortress answer |
|---|---|---|
| Hostile installed app | Any public API, any syscall allowed to `untrusted_app`, native code, root-exploit attempts from the app sandbox | Launch gate, virtual identity, kernel egress policy, IPC isolation, SELinux hardening |
| Colluding apps | Two apps try to share identifiers or data | Unix IPC isolation now, binder isolation in Phase 9, per-app identity profiles |
| Network observer | Sees traffic on Wi-Fi or mobile networks | Everything except the WireGuard handshake stays inside the tunnel; no fallback path |
| Remote server of an app | Correlates IP, device model and sensor fingerprints | Tunnel exit IP, virtual `Build.*`, sensor spoofing and hiding |

## Out of scope, or only partly mitigated

- **Physical attacker with the device.** On Samsung the bootloader cannot be
  re-locked with custom AVB keys, and unlocking permanently trips Knox.
  Anyone holding the phone can flash a modified image. Mitigations: a strong
  lock-screen password (FBE keys) and our own AVB signing, so tampering is
  visible. This is a hard limit of the hardware, see
  [DEVICE_A52SXQ.md](DEVICE_A52SXQ.md).
- **Baseband, carrier and modem firmware.** The modem knows the IMEI and the
  serving cell, so the carrier always knows the approximate location.
  Fortress cannot hide anything from the network operator.
- **Proprietary vendor code** (Qualcomm/Samsung blobs, TrustZone, bootloader)
  has to be trusted.
- **Kernel exploits.** A kernel compromise defeats every in-kernel control.
  Phase 8 hardening (lockdown, module signing, CFI/SCS which are already on,
  init-on-free) raises the cost.

## Trusted computing base

Bootloader and TrustZone (vendor), the kernel including Fortress, init,
system_server (holds the policy), zygote (applies virtual identity), and the
vendor HALs.

## Fail-closed requirements, and where they are met

| Failure | Required result | Mechanism |
|---|---|---|
| No or invalid policy | apps cannot launch, no egress | `UNLOADED` state, atomic rejection |
| App missing from policy | app killed at launch | launch gate + `SIGKILL` |
| Identity profile unreadable | app does not start | zygote aborts on `self/profile` error (Phase 3) |
| Tunnel down | no network | only tunnel interfaces are permitted; there is no fallback route |
| Fortress not enabled in the kernel | no boot | panic from `fortress_late_init` |
| Netfilter hook registration fails | no boot / no namespace | panic, or netns creation fails |
