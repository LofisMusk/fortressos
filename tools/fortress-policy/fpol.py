#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Fortress policy compiler: JSON source -> binary blob (format v1).

The binary layout is defined in kernel/security/fortress/policy_parse.h;
keep the two in sync. The kernel re-validates everything, so this tool's
own checks exist only to give readable errors early.

Usage:
  fpol.py compile policy.json -o policy.bin
  fpol.py dump policy.bin
"""

import argparse
import json
import struct
import sys

MAGIC = b"FRTP"
VERSION = 1
HEADER_SIZE = 64
NAME_LEN = 16

F_ALLOW_FORWARD = 1 << 0
APP_NET = 1 << 0
APP_TRUSTED = 1 << 1
PROFILE_NONE = 0xFFFFFFFF

MAX_SIZE = 4 << 20
MAX_APPS = 10000
MAX_TUNNELS = 8
MAX_EXEMPT = 64
MAX_PROFILES = 10000
MAX_PROFILE_LEN = 64 << 10

PER_USER_RANGE = 100000
APP_START, APP_END = 10000, 19999
SANDBOX_START, SANDBOX_END = 20000, 29999
ISOLATED_START, ISOLATED_END = 90000, 99999

# magic, version, header_size, total_size, flags, serial,
# (count, offset) x 4 sections, 12 reserved bytes
HEADER_FMT = "<4sHH" + "I" * 11 + "12x"
assert struct.calcsize(HEADER_FMT) == HEADER_SIZE


class PolicyError(ValueError):
    pass


def classify(appid):
    if APP_START <= appid <= APP_END:
        return "app"
    if SANDBOX_START <= appid <= SANDBOX_END:
        return "sandbox"
    if ISOLATED_START <= appid <= ISOLATED_END:
        return "isolated"
    return "system"


def encode_name(name, what):
    if not isinstance(name, str):
        raise PolicyError(f"{what}: expected a string")
    raw = name.encode("ascii", errors="strict")
    if not 1 <= len(raw) < NAME_LEN:
        raise PolicyError(f"{what}: {name!r} must be 1..{NAME_LEN - 1} bytes")
    for b in raw:
        if b < 0x21 or b > 0x7E or b in b"/:":
            raise PolicyError(f"{what}: {name!r} contains an invalid character")
    return raw.ljust(NAME_LEN, b"\0")


def encode_profile(name, props):
    """A profile is opaque to the kernel; zygote parses 'key=value' lines."""
    if not isinstance(props, dict):
        raise PolicyError(f"profile {name!r}: expected an object")
    lines = []
    for key in sorted(props):
        value = props[key]
        if not isinstance(value, str):
            raise PolicyError(f"profile {name!r}: {key} must be a string")
        if not key or "=" in key or "\n" in key or "\n" in value:
            raise PolicyError(f"profile {name!r}: bad entry {key!r}")
        lines.append(f"{key}={value}\n")
    data = "".join(lines).encode("utf-8")
    if len(data) > MAX_PROFILE_LEN:
        raise PolicyError(f"profile {name!r}: larger than {MAX_PROFILE_LEN} bytes")
    return data


def compile_policy(src):
    """Build a blob from a policy dict (the parsed JSON source)."""
    known = {"serial", "allow_forward", "tunnels", "exempt", "profiles", "apps"}
    unknown = set(src) - known
    if unknown:
        raise PolicyError(f"unknown top-level keys: {sorted(unknown)}")

    serial = int(src.get("serial", 0))
    if not 0 <= serial <= 0xFFFFFFFF:
        raise PolicyError("serial out of range")
    flags = F_ALLOW_FORWARD if src.get("allow_forward", False) else 0

    profile_names = sorted(src.get("profiles", {}))
    profile_index = {n: i for i, n in enumerate(profile_names)}
    profile_data = [encode_profile(n, src["profiles"][n]) for n in profile_names]

    apps = []
    for i, app in enumerate(src.get("apps", [])):
        appid = int(app["appid"])
        if classify(appid) != "app":
            raise PolicyError(f"apps[{i}]: appid {appid} is not in {APP_START}..{APP_END}")
        aflags = (APP_NET if app.get("net", False) else 0) | \
                 (APP_TRUSTED if app.get("trusted", False) else 0)
        profile = app.get("profile")
        if profile is None:
            pid = PROFILE_NONE
        elif profile in profile_index:
            pid = profile_index[profile]
        else:
            raise PolicyError(f"apps[{i}]: unknown profile {profile!r}")
        apps.append((appid, aflags, pid))
    apps.sort()
    for a, b in zip(apps, apps[1:]):
        if a[0] == b[0]:
            raise PolicyError(f"duplicate appid {a[0]}")

    tunnels = [(encode_name(t["ifname"], "tunnel ifname"),
                encode_name(t["kind"], "tunnel kind"))
               for t in src.get("tunnels", [])]

    exempt = []
    for i, e in enumerate(src.get("exempt", [])):
        appid = int(e["appid"])
        if classify(appid) != "system":
            raise PolicyError(f"exempt[{i}]: appid {appid} is not a system uid")
        exempt.append((appid, encode_name(e["ifprefix"], "exempt ifprefix")))

    for what, n, limit in (("apps", len(apps), MAX_APPS),
                           ("tunnels", len(tunnels), MAX_TUNNELS),
                           ("exempt", len(exempt), MAX_EXEMPT),
                           ("profiles", len(profile_data), MAX_PROFILES)):
        if n > limit:
            raise PolicyError(f"too many {what}: {n} > {limit}")

    off = HEADER_SIZE

    def section(n, entsize):
        nonlocal off
        if n == 0:
            return 0
        start = off
        off += n * entsize
        return start

    apps_off = section(len(apps), 12)
    tunnels_off = section(len(tunnels), 32)
    exempt_off = section(len(exempt), 20)
    profiles_off = section(len(profile_data), 8)

    body = bytearray()
    for appid, aflags, pid in apps:
        body += struct.pack("<III", appid, aflags, pid)
    for ifname, kind in tunnels:
        body += ifname + kind
    for appid, prefix in exempt:
        body += struct.pack("<I", appid) + prefix
    data_off = off
    for data in profile_data:
        body += struct.pack("<II", data_off, len(data))
        data_off += len(data)
    for data in profile_data:
        body += data

    total = HEADER_SIZE + len(body)
    if total > MAX_SIZE:
        raise PolicyError(f"policy too large: {total} bytes")

    header = struct.pack(HEADER_FMT, MAGIC, VERSION, HEADER_SIZE, total,
                         flags, serial,
                         len(apps), apps_off, len(tunnels), tunnels_off,
                         len(exempt), exempt_off, len(profile_data), profiles_off)
    return bytes(header + body)


def decode_policy(blob):
    """Inverse of compile_policy (profiles come back keyed by index)."""
    if len(blob) < HEADER_SIZE:
        raise PolicyError("blob shorter than header")
    (magic, version, hsize, total, flags, serial,
     n_apps, apps_off, n_tun, tun_off, n_ex, ex_off, n_prof, prof_off) = \
        struct.unpack_from(HEADER_FMT, blob)
    if magic != MAGIC or version != VERSION or hsize != HEADER_SIZE or total != len(blob):
        raise PolicyError("bad header")

    def name(raw):
        return raw.rstrip(b"\0").decode("ascii")

    out = {"serial": serial, "allow_forward": bool(flags & F_ALLOW_FORWARD),
           "apps": [], "tunnels": [], "exempt": [], "profiles": []}
    for i in range(n_prof):
        doff, dlen = struct.unpack_from("<II", blob, prof_off + i * 8)
        text = blob[doff:doff + dlen].decode("utf-8")
        out["profiles"].append(dict(line.split("=", 1) for line in text.splitlines()))
    for i in range(n_apps):
        appid, aflags, pid = struct.unpack_from("<III", blob, apps_off + i * 12)
        out["apps"].append({"appid": appid, "net": bool(aflags & APP_NET),
                            "trusted": bool(aflags & APP_TRUSTED),
                            "profile": None if pid == PROFILE_NONE else pid})
    for i in range(n_tun):
        base = tun_off + i * 32
        out["tunnels"].append({"ifname": name(blob[base:base + 16]),
                               "kind": name(blob[base + 16:base + 32])})
    for i in range(n_ex):
        base = ex_off + i * 20
        appid, = struct.unpack_from("<I", blob, base)
        out["exempt"].append({"appid": appid, "ifprefix": name(blob[base + 4:base + 20])})
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("compile", help="compile a JSON policy to a blob")
    c.add_argument("source")
    c.add_argument("-o", "--output", required=True)
    d = sub.add_parser("dump", help="print a blob as JSON")
    d.add_argument("blob")
    args = ap.parse_args(argv)

    try:
        if args.cmd == "compile":
            with open(args.source, encoding="utf-8") as f:
                blob = compile_policy(json.load(f))
            with open(args.output, "wb") as f:
                f.write(blob)
        else:
            with open(args.blob, "rb") as f:
                print(json.dumps(decode_policy(f.read()), indent=2))
    except (PolicyError, KeyError, ValueError) as e:
        print(f"fpol: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
