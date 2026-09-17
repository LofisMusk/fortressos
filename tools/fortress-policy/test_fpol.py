# SPDX-License-Identifier: GPL-2.0
"""Unit tests for the policy compiler. Run: python3 -m unittest -v"""

import copy
import struct
import unittest

import fpol

BASE = {
    "serial": 7,
    "tunnels": [{"ifname": "fwg0", "kind": "wireguard"}],
    "exempt": [{"appid": 1073, "ifprefix": "wlan"}],
    "profiles": {"pixel9": {"ro.product.model": "Pixel 9",
                            "ro.product.brand": "google"}},
    "apps": [
        {"appid": 10051, "net": True},
        {"appid": 10050, "net": True, "profile": "pixel9"},
        {"appid": 10060, "net": True, "trusted": True},
    ],
}


class CompileTest(unittest.TestCase):
    def test_header(self):
        blob = fpol.compile_policy(BASE)
        magic, version, hsize, total = struct.unpack_from("<4sHHI", blob)
        self.assertEqual((magic, version, hsize, total),
                         (b"FRTP", 1, 64, len(blob)))
        self.assertEqual(blob[52:64], b"\0" * 12)

    def test_roundtrip(self):
        out = fpol.decode_policy(fpol.compile_policy(BASE))
        self.assertEqual(out["serial"], 7)
        self.assertEqual([a["appid"] for a in out["apps"]], [10050, 10051, 10060])
        self.assertEqual(out["apps"][0], {"appid": 10050, "net": True,
                                          "trusted": False, "profile": 0})
        self.assertTrue(out["apps"][2]["trusted"])
        self.assertEqual(out["tunnels"], BASE["tunnels"])
        self.assertEqual(out["exempt"], BASE["exempt"])
        self.assertEqual(out["profiles"][0]["ro.product.model"], "Pixel 9")

    def test_sections_aligned(self):
        blob = fpol.compile_policy(BASE)
        offsets = struct.unpack_from("<8I", blob, 20)[1::2]
        for off in offsets:
            self.assertEqual(off % 4, 0)

    def test_empty_policy(self):
        blob = fpol.compile_policy({})
        self.assertEqual(len(blob), 64)
        self.assertEqual(struct.unpack_from("<8I", blob, 20), (0,) * 8)

    def test_block_getlink_flag(self):
        src = copy.deepcopy(BASE)
        src["block_getlink"] = True
        blob = fpol.compile_policy(src)
        self.assertEqual(struct.unpack_from("<I", blob, 12)[0], fpol.F_BLOCK_GETLINK)
        self.assertTrue(fpol.decode_policy(blob)["block_getlink"])
        self.assertFalse(fpol.decode_policy(fpol.compile_policy(BASE))["block_getlink"])

    def test_deterministic(self):
        self.assertEqual(fpol.compile_policy(BASE), fpol.compile_policy(BASE))

    def reject(self, mutate):
        src = copy.deepcopy(BASE)
        mutate(src)
        with self.assertRaises(fpol.PolicyError):
            fpol.compile_policy(src)

    def test_rejects_system_uid_as_app(self):
        self.reject(lambda s: s["apps"].append({"appid": 1000}))

    def test_rejects_isolated_uid_as_app(self):
        self.reject(lambda s: s["apps"].append({"appid": 90001}))

    def test_rejects_app_exemption(self):
        # No installed app may ever be granted physical network access.
        self.reject(lambda s: s["exempt"].append({"appid": 10050, "ifprefix": "wlan"}))

    def test_rejects_duplicate_app(self):
        self.reject(lambda s: s["apps"].append({"appid": 10050}))

    def test_rejects_unknown_profile(self):
        self.reject(lambda s: s["apps"].append({"appid": 10070, "profile": "nope"}))

    def test_rejects_bad_ifnames(self):
        for bad in ("", "a" * 16, "we/ird", "a:b", "sp ace"):
            with self.subTest(name=bad):
                self.reject(lambda s, b=bad: s["tunnels"].append({"ifname": b, "kind": "tun"}))

    def test_rejects_bad_profile_entries(self):
        self.reject(lambda s: s["profiles"].update({"x": {"a=b": "c"}}))
        self.reject(lambda s: s["profiles"].update({"x": {"a": "multi\nline"}}))

    def test_rejects_unknown_key(self):
        self.reject(lambda s: s.update({"tunnel": []}))

    def test_rejects_too_many_tunnels(self):
        self.reject(lambda s: s.update(
            {"tunnels": [{"ifname": f"t{i}", "kind": "tun"} for i in range(9)]}))


if __name__ == "__main__":
    unittest.main()
