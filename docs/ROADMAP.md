# Roadmap

Status legend: **done**, **in progress**, planned.

| Phase | Scope | Kernel part | Framework part | Status |
|---|---|---|---|---|
| 0 | Repo, docs, CI, Fortress LSM core | policy/securityfs, launch gate, Network Guard, unix IPC isolation, QEMU tests | – | **done**: CI green (QEMU 54/54, a52sxq kernel builds); not yet on device |
| 1 | Device validation | develop-mode kernel on device | – | **in progress, free path**: `ci/bootimg.sh` puts the Fortress kernel into the official LineageOS boot.img. A full own-key ROM still needs a big machine (`ci/rom/`), which needs a payment method, so it waits |
| 2 | Own keys, release pipeline | vbmeta `--flags 0` + own AVB key | `sign_release.sh`, OTA JSON on GitHub Releases | keys script **done** |
| 3 | Identity Guard | `/proc` and `/sys` identity denials, `RTM_GETLINK` filter | FortressService policy loader, zygote `self/profile` + `Build.*` + property overlay, Android ID | planned |
| 4 | Network Guard | WireGuard backport to 5.4, exemption tuning (DHCP, clat, IMS) | platform WireGuard VPN, system-uid routing, captive portal/NTP via tunnel | kernel core written |
| 5 | Location Guard | deny GNSS/QMI nodes | `LocationProviderManager`, scan filtering, SUPL off | planned |
| 6 | Storage Broker | deny lower filesystem | permission lockdown, Photo Picker/SAF, audit log | planned |
| 7 | Sensor Guard | deny `iio` and sensor-hub nodes | `SensorService` per-uid filter/spoof | planned |
| 8 | Hardening | `MODULE_SIG_FORCE` (ephemeral per-build key), lockdown LSM, `INIT_ON_FREE`, Yama (after checking crash_dump), `SELINUX_DEVELOP=n` in release | extra sepolicy | planned |
| 9 | App isolation | binder app↔app mediation, isolation groups | – | planned |
| 10 | AVF/Microdroid | – | – | **closed: not feasible** ([research/AVF.md](research/AVF.md)) |
| 11 | Fail-closed audit | review every failure path | zygote/system_server abort paths | continuous |
| 12 | Security test suite | QEMU suite (exists) | on-device probe app; `sign_release.sh` refuses builds without a PASS report for their fingerprint | planned |

## Deferred decisions

- **Yama** is not in the first kernel fragment. `ptrace_scope=1` may break
  Android's crash_dump, which ptraces its parent. It gets tested in Phase 8.
- The **`release` kernel variant** is only usable once Phase 3 loads a
  policy. Until then every app launch is denied, which is correct but not
  usable. Bring-up uses `develop`.
