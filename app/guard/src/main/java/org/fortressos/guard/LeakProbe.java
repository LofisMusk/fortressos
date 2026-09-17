// SPDX-License-Identifier: GPL-2.0
package org.fortressos.guard;

import android.content.ContentResolver;
import android.os.Build;
import android.provider.Settings;

import java.io.BufferedReader;
import java.io.FileReader;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * What identity can this app actually see?
 *
 * Runs as a plain untrusted_app, so the result is the real attack surface
 * left after SELinux and Android's own restrictions - exactly the list the
 * kernel guard has to close (Phase 3, kernel half).
 */
final class LeakProbe {

    static final class Probe {
        final String name;
        final String source;
        final boolean visible;
        final String value;     // trimmed, never the full identifier

        Probe(String name, String source, boolean visible, String value) {
            this.name = name;
            this.source = source;
            this.visible = visible;
            this.value = value;
        }
    }

    /** Kernel interfaces that can carry hardware identity. */
    private static final String[][] FILES = {
            {"SoC serial", "/sys/devices/soc0/serial_number"},
            {"SoC id", "/sys/devices/soc0/soc_id"},
            {"SoC machine", "/sys/devices/soc0/machine"},
            {"boot cmdline", "/proc/cmdline"},
            {"cpuinfo", "/proc/cpuinfo"},
            {"kernel build", "/proc/version"},
            {"boot id", "/proc/sys/kernel/random/boot_id"},
            {"Wi-Fi MAC", "/sys/class/net/wlan0/address"},
            {"Bluetooth MAC", "/sys/class/net/bt-pan/address"},
            {"ARP neighbours", "/proc/net/arp"},
            {"device tree serial", "/sys/firmware/devicetree/base/serial-number"},
            {"UFS model", "/sys/block/sda/device/model"},
            {"UFS serial", "/sys/block/sda/device/serial"},
    };

    private LeakProbe() {
    }

    static List<Probe> run(ContentResolver resolver) {
        List<Probe> out = new ArrayList<>();

        for (String[] f : FILES) {
            String value = read(f[1]);
            out.add(new Probe(f[0], f[1], value != null, value));
        }

        out.add(new Probe("Build.MODEL", "android.os.Build", true, Build.MODEL));
        out.add(new Probe("Build.DEVICE", "android.os.Build", true, Build.DEVICE));
        out.add(new Probe("Build.FINGERPRINT", "android.os.Build", true, Build.FINGERPRINT));

        String androidId = null;
        try {
            androidId = Settings.Secure.getString(resolver, Settings.Secure.ANDROID_ID);
        } catch (Exception ignored) {
            // falls through to "not visible"
        }
        out.add(new Probe("Android ID", "Settings.Secure", androidId != null, androidId));

        out.add(hardwareAddress());
        return out;
    }

    private static Probe hardwareAddress() {
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                byte[] mac = ni.getHardwareAddress();
                if (mac != null && mac.length > 0) {
                    StringBuilder sb = new StringBuilder(ni.getName()).append(' ');
                    for (byte b : mac) {
                        sb.append(String.format("%02x:", b));
                    }
                    return new Probe("MAC via NetworkInterface", "java.net", true,
                            sb.substring(0, sb.length() - 1));
                }
            }
        } catch (Exception ignored) {
            // treated as not visible
        }
        return new Probe("MAC via NetworkInterface", "java.net", false, null);
    }

    private static String read(String path) {
        try (BufferedReader in = new BufferedReader(new FileReader(path))) {
            String line = in.readLine();
            return line == null ? "" : line.trim();
        } catch (Exception e) {
            return null;
        }
    }

    /** Keep reports shareable: enough to recognise a leak, not to identify the phone. */
    static String preview(String value) {
        if (value == null) {
            return "";
        }
        String v = value.replaceAll("\\s+", " ").trim();
        return v.length() <= 28 ? v : v.substring(0, 28) + "…";
    }
}
