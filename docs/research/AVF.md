# AVF / pKVM / Microdroid on SM7325: result

**Conclusion: not feasible on this device.** Phase 10 is closed as research.
No Fortress component depends on AVF.

## Evidence

1. **No KVM in the kernel.** `vendor/lineage-a52sxq_defconfig` has
   `# CONFIG_VIRTUALIZATION is not set`. So there is no KVM and no
   `/dev/kvm`.
2. **Kernel 5.4 has no pKVM.** Protected KVM exists only in newer kernels
   (upstream 5.13+, Android GKI 5.10+). AVF on Android 13+ needs pKVM (or
   Gunyah on newer Qualcomm SoCs).
3. **EL2 is not ours.** On Snapdragon with Qualcomm's boot chain, EL2 is
   occupied by Qualcomm's hypervisor firmware and Linux is entered at EL1. KVM
   needs Linux to own EL2, so even a rebuilt kernel with
   `CONFIG_KVM=y` could not run guests. The bootloader and hypervisor are
   signed by the vendor and cannot be replaced.

To confirm on the device (Phase 1 checklist):

```
dmesg | grep -i "started at EL"     # expected: "CPU: All CPU(s) started at EL1"
ls /dev/kvm                         # expected: No such file or directory
```

## Consequences for application isolation (Phase 9)

Isolation is built from kernel primitives that work at EL1:

- The Fortress LSM: IPC mediation, and later binder app↔app.
- Per-app mount namespaces, already provided by zygote.
- SELinux categories per app, as in stock Android.
- Per-uid network policy.
- seccomp, and denials of shared filesystem locations.

A VM boundary per app remains out of reach on this hardware.
