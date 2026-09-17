# Fortress OS architecture

## Principles

1. **The guard lives in the kernel, not in a process.** There is no Fortress
   daemon that could crash, be killed, or be raced. Enforcement is a stacked
   Linux Security Module (`security/fortress/`) plus netfilter hooks that the
   kernel registers itself.
2. **Fail closed.** Before a policy is loaded the kernel is in the
   `UNLOADED` state: no app process can start and no packet can leave through
   a non-loopback interface. A rejected policy never replaces a working one.
   A kernel with Fortress built in but not enabled panics at boot.
3. **Kernel enforces, framework only virtualises.** Some data never passes
   through the kernel in a form it can rewrite (`Build.MODEL` is a Java field
   inside zygote's heap; locations and sensor events travel over binder).
   For those, small shims are compiled *into* zygote and system_server. They
   read their inputs from the kernel and abort on failure. They are not a
   separate process and cannot fail open.

```
 app process ──syscalls──▶ kernel: Fortress LSM + netfilter ──▶ resources
     │                         ▲  (gate, egress, IPC, /proc,/sys)
     │ binder                  │ policy blob (securityfs, RCU swap)
     ▼                         │
 system_server ── FortressService (Phase 3) ── policy compiler
   location / sensors / Android ID shims
 zygote child ── reads self/profile after setuid, virtualises Build.*
```

## Enforcement map

| Area | Kernel (this repo, `kernel/security/fortress`) | In-process shim (later phases) |
|---|---|---|
| Launch gate | `task_fix_setuid`: becoming an app uid without an active policy entry fails, and the would-be app process is killed | FortressService adds an entry when PackageManager assigns a uid |
| Identity | `self/profile` hands each app its virtual identity. Planned: deny identity leaks under `/proc` and `/sys`, and `RTM_GETLINK` (MAC) for all apps, whatever their targetSdk | zygote rewrites `Build.*` and overlays the `build_prop` property area in the app's mount namespace. Per-app Android ID in SettingsProvider |
| Network | netfilter LOCAL_OUT/POST_ROUTING/FORWARD, IPv4+IPv6 (below) | Platform WireGuard VPN in system_server. Routing for system uids through the tunnel |
| Location | Planned: deny app access to GNSS/QMI/diag nodes | `LocationProviderManager` substitution, Wi-Fi/cell scan filtering, SUPL off |
| Sensors | Planned: deny `iio` and sensor-hub nodes | Per-uid filtering in `SensorService` |
| Storage | Planned: deny the lower filesystem to apps | Broad media permissions denied, Photo Picker/SAF forced, access audit log |
| Isolation | `unix_stream_connect` / `unix_may_send`: untrusted uid ↔ other untrusted uid denied. Planned: binder app↔app | Isolation groups in policy |

Android already withholds a lot from third-party apps: IMEI and serial since
Android 10, a per-signing-key Android ID since 8, hardware MAC for apps
targeting API 30+, and per-network Wi-Fi MAC randomisation. Fortress does not
rely on those defaults. It adds the launch gate, virtual identities, and
enforcement that does not depend on targetSdk.

## Kernel module

| File | Role |
|---|---|
| `lsm.c` | `DEFINE_LSM(fortress)`, hook registration, boot wiring, fatal-on-misconfiguration |
| `policy_parse.[ch]` | Blob format v1 and its validating parser; kernel-independent so the identical code is unit-tested and fuzzed on the host |
| `policy.c` | Active policy pointer, all-or-nothing RCU replacement, profile copy |
| `fs.c` | securityfs: `status`, `policy`, `self/profile`, (develop) `enforce` |
| `gate.c` | Launch gate |
| `netguard.c` | Egress policy |
| `ipc.c` | AF_UNIX isolation |

### uid classes

`appid = uid % 100000`, so the same rules apply in every Android user.

| appid | class | gate | network | unix IPC |
|---|---|---|---|---|
| < 10000 and all other ranges | system | always | tunnel, plus explicit exemptions | unrestricted |
| 10000–19999 | app | needs policy entry | tunnel only, needs `NET` flag | other untrusted uids denied unless either side is `TRUSTED` |
| 20000–29999 | SDK sandbox | needs any policy | none | as app |
| 90000–99999 | isolated / app zygote | needs any policy | none | as app |

### Network Guard decision (per locally generated packet)

1. Out device is loopback → accept.
2. No owning socket, or a kernel socket (`sk_kern_sock`) → accept. This is
   how the in-kernel WireGuard UDP socket reaches the physical network, and
   how TCP RST and ICMP control packets go out.
3. Owner is not a full socket → drop (owner unknown).
4. No policy → drop.
5. App: accept only via a policy tunnel and only with `NET`. Sandbox and
   isolated processes: drop.
6. System uid: accept via a tunnel, or on an interface matching an
   `(appid, ifprefix)` exemption. Otherwise drop.

A tunnel is matched by interface name **and** `rtnl_link_ops->kind`
(`wireguard` in production). Only privileged processes can create or rename
interfaces. A tunnel created through `VpnService` is `tun`, and its packets
still have to leave as the VPN app's uid, which rule 5 drops. Forwarded
traffic may only leave through a tunnel, unless the policy sets
`allow_forward`.

Exemptions only accept system uids; the parser rejects anything else. A
permissive boot on the device (2026-09-18, Wi-Fi only, no SIM) showed
exactly which ones matter:

| uid | seen doing | decision |
|---|---|---|
| 1000 `system` | NTP (`NetworkTimeUpdate`) | route through the tunnel (Phase 4) |
| 1051 `dns` | netd's DnsResolver queries | tunnel |
| 1073 `network_stack` | connectivity checks, DHCP | exempt on `wlan`/`rmnet` |
| 10062 media/downloads provider | app-range uid, 10 attempts | no exemption: apps go through the tunnel |

Still to be observed with a SIM present: `clat` (1029) on `rmnet` for
464xlat, and the IMS/radio uid on the IMS APN interface for VoLTE.

Captive-portal probes and NTP from system_server have to be routed into the
tunnel (Phase 4) or they are dropped.

### Policy blob (v1)

Little-endian, defined in `policy_parse.h`, produced by
`tools/fortress-policy/fpol.py` from JSON. The layout is a 64-byte header,
then apps (sorted, 12 B), tunnels (32 B), exemptions (20 B), a profile table
(8 B) and opaque profile data. Limits: 4 MiB total, 10 000 apps, 8 tunnels,
64 exemptions, 64 KiB per profile. Unknown flags, unsorted apps, bad names
and out-of-range appids are all rejected. The whole blob must arrive in one
`write()`.

Writers must have euid 0 or `AID_SYSTEM` in the initial user namespace.
SELinux (`sepolicy/fortress`) narrows that down to system_server.

### Develop mode

`CONFIG_SECURITY_FORTRESS_DEVELOP` adds `fortress.enforce=` and a writable
`enforce` file (requires `CAP_MAC_ADMIN`). With `..._DEVELOP_PERMISSIVE`, the
kernel boots log-only, which is what bring-up on stock LineageOS userspace
needs. Release builds compile all of it out.

## Known limitations (v1)

- Policy is keyed by appid, so an app has one profile across Android users.
- An isolated process cannot connect to its own app's named unix socket,
  because the kernel cannot tell which app owns an isolated uid. Socketpairs
  passed to it are unaffected.
- SDK sandboxes get no network.
- Binder transactions between apps are not mediated yet (Phase 9).
- system_server is in the TCB: whoever controls it controls the policy. That
  is already true of Android's permission model.
