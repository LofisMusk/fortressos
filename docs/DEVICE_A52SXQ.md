# Samsung Galaxy A52s 5G (SM-A528B/DS, `a52sxq`)

## Facts (checked 2026-09-12 against LineageOS sources)

| | |
|---|---|
| SoC | Qualcomm SM7325 (Snapdragon 778G), arm64 |
| LineageOS | Official, maintainer Simon1511, current branch `lineage-23.2` (Android 16) |
| Stock firmware prerequisite | Android 13/14 firmware must be flashed before installing |
| Install method | Odin / `samloader`, then Lineage Recovery |
| Partitions | Not A/B. Samsung dynamic partitions (`system vendor product odm`). OTA installs through recovery |
| Kernel | `LineageOS/android_kernel_samsung_sm7325`, Linux **5.4.254**, `vendor/lineage-a52sxq_defconfig`, non-GKI, clang ThinLTO + CFI + SCS |
| Toolchain | AOSP `clang-r563880c` (tag `android-16.0.0_r4`), `LLVM=1 LLVM_IAS=1` |
| AVB | `BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS += --flags 3`, so verification is **disabled** in LineageOS |
| Virtualisation | `CONFIG_VIRTUALIZATION` not set; EL2 held by Qualcomm firmware, see [research/AVF.md](research/AVF.md) |

Pins used by CI (`ci/kernel-build.sh`): kernel commit
`12334aaea98147c1739de857b4f36f8949a3f095`, clang `clang-r563880c`.

## Security consequences

- **Knox e-fuse.** Unlocking the bootloader trips it permanently (0x1).
  Samsung Pay, Secure Folder and similar stop working for good. That doesn't
  matter to Fortress, but it cannot be undone.
- **No re-lock.** Samsung's bootloader only boots Samsung-signed images when
  locked; custom AVB keys are not supported. The device stays unlocked
  (orange state), so verified boot cannot stop a physical attacker. Fortress
  still signs vbmeta with its own key and aims to turn hash verification on
  (`--flags 0`) so that dm-verity protects the running system. That still
  has to be tested on the device (Phase 2).
- **Kernel config gaps found:** no BPF-LSM (5.4), `SELINUX_DEVELOP=y`, no
  Yama, no module signing, no WireGuard. See [ROADMAP.md](ROADMAP.md).

## Bring-up checklist (Phase 1)

With a clean LineageOS 23.2 build signed with our keys, then with the
Fortress kernel in develop (permissive) mode:

- [ ] Boots. `cat /sys/kernel/security/lsm` contains `fortress`
- [ ] `dmesg | grep -i "started at EL"` shows EL1 (AVF research)
- [ ] Wi-Fi, LTE, 5G NR, VoLTE (IMS), SMS
- [ ] Fingerprint, all cameras, GPS fix, Bluetooth audio, NFC
- [ ] OTA from recovery with our release key
- [ ] Fortress "would deny" log lines reviewed (`dmesg | grep fortress`)

## Recovery path

Keep the matching stock firmware (`samloader`) and Odin (or Heimdall) ready.
Flashing stock firmware restores the device, apart from the Knox fuse.
Kernel-only iteration: repack `boot.img` with the new `Image` (header v3),
then from Lineage Recovery's adb shell, write it with
`dd of=/dev/block/by-name/boot`. The exact procedure gets validated in
Phase 1.
