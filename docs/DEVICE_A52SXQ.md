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

## Knox Guard delays the unlock by 7 days

The bootloader itself is offline: at boot it only reads a locally stored
flag plus the `KG STATE` shown on the download-mode screen. What needs the
network is *permission to change that flag*. After the setup wizard the
state sits at `Prenormal` for 168 hours, and only once Samsung's servers
confirm the device is not reported stolen or carrier-locked does it become
`Normal` and the "OEM unlocking" toggle appear.

So a freshly reset device cannot be unlocked for a week, however offline
the bootloader is. Keep the phone powered on and online, and do not factory
reset it: that restarts the counter. The widely shared trick of moving the
system date forward manipulates the local counter only, which is why it
works for some people and not others.

This is the same vendor control that makes re-locking with our own AVB key
impossible: on this hardware the owner never gets the final say over what
the device will boot.

## Flashing tools (macOS)

Samsung devices have no fastboot, and on macOS the usual alternatives are
dead ends: the Homebrew `heimdall-suite` cask was disabled on 2026-03-29,
and Thor lists macOS as not implemented. The "Odin for Mac" projects on
GitHub are unvetted binaries - not something to run against the device this
project exists to harden.

Use **samloader-rs**, which is what the LineageOS wiki prescribes for this
device and ships a macOS universal build:
<https://github.com/topjohnwu/samloader-rs/releases/latest>

    samloader print-pit                                  # connection test
    samloader flash --partition BOOT boot-fortress.img
    samloader flash --partition RECOVERY recovery.img --no-reboot
    samloader flash --partition VBMETA vbmeta.img

Once LineageOS Recovery is installed, `adb` alone is enough for kernel
iteration: push the image and `dd` it to `/dev/block/by-name/boot`.

## Recovery path

Keep the matching stock firmware ready (`samloader-rs` can also download
it). Flashing stock firmware restores the device, apart from the Knox fuse.
