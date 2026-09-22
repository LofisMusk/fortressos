// SPDX-License-Identifier: GPL-2.0
package org.fortressos.telemetry;

import android.app.ActivityManager;
import android.bluetooth.BluetoothAdapter;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.net.ConnectivityManager;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Debug;
import android.os.Environment;
import android.os.StatFs;
import android.os.SystemClock;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.util.DisplayMetrics;
import android.view.WindowManager;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

import org.fortressos.telemetry.Report.Tag;

/**
 * Reads every piece of device identity a plain, unrooted app can reach.
 *
 * The point of the app is the shape of the list, not any one value: after
 * years of "privacy" changes, an app with only install-time permissions
 * still walks away with a stable fingerprint. Rows tagged ID survive a
 * reinstall; BLOCKED rows are where the platform actually stops you.
 *
 * Kept dependency-free (no AndroidX) so it drops onto any device, including
 * a Fortress ROM, exactly like the Guard app next door.
 */
// Probing the legacy identity APIs (getImei, getSubscriberId, getMacAddress,
// getDefaultDisplay, …) is the entire point, so their deprecation is expected.
@SuppressWarnings("deprecation")
final class Collector {

    private final Context ctx;
    private final PackageManager pm;

    Collector(Context ctx) {
        this.ctx = ctx.getApplicationContext();
        this.pm = this.ctx.getPackageManager();
    }

    Report collect() {
        Report r = new Report();
        build(r);
        identifiers(r);
        telephony(r);
        network(r);
        wifi(r);
        bluetooth(r);
        display(r);
        hardware(r);
        sensors(r);
        storage(r);
        battery(r);
        locale(r);
        kernelFiles(r);
        installedApps(r);
        return r;
    }

    // ---- android.os.Build: free, no permission, and highly stable -------

    private void build(Report r) {
        Report.Section s = r.section("Build fingerprint",
                "Free to any app. Not unique alone, but 15+ stable fields "
                        + "narrow the device to a handful of models.");
        s.put(Tag.FP, "MANUFACTURER", Build.MANUFACTURER);
        s.put(Tag.FP, "BRAND", Build.BRAND);
        s.put(Tag.FP, "MODEL", Build.MODEL);
        s.put(Tag.FP, "DEVICE", Build.DEVICE);
        s.put(Tag.FP, "PRODUCT", Build.PRODUCT);
        s.put(Tag.FP, "BOARD", Build.BOARD);
        s.put(Tag.FP, "HARDWARE", Build.HARDWARE);
        s.put(Tag.FP, "FINGERPRINT", Build.FINGERPRINT);
        s.put(Tag.FP, "BOOTLOADER", Build.BOOTLOADER);
        s.put(Tag.FP, "ID (build)", Build.ID);
        s.put(Tag.FP, "TAGS", Build.TAGS);
        s.put(Tag.FP, "TYPE", Build.TYPE);
        s.put(Tag.FP, "supported ABIs", Build.SUPPORTED_ABIS);
        s.put(Tag.FP, "OS release", Build.VERSION.RELEASE);
        s.put(Tag.FP, "SDK_INT", Build.VERSION.SDK_INT);
        s.put(Tag.FP, "security patch", Build.VERSION.SECURITY_PATCH);
        s.put(Tag.FP, "incremental", Build.VERSION.INCREMENTAL);
        // getSerial() needs privileged/carrier access since Android 10.
        s.add(Tag.ID, "Build.getSerial()", Build::getSerial);
    }

    // ---- Software identifiers -------------------------------------------

    private void identifiers(Report r) {
        Report.Section s = r.section("Software identifiers",
                "ANDROID_ID is the big one: per-app, but stable until factory "
                        + "reset, so it links every session of THIS app forever.");
        s.add(Tag.ID, "ANDROID_ID", () ->
                Settings.Secure.getString(ctx.getContentResolver(),
                        Settings.Secure.ANDROID_ID));
        s.add(Tag.ID, "GSF ID (Google Services Framework)", this::gsfId);
        s.add(Tag.FP, "boot count", () -> Settings.Global.getString(
                ctx.getContentResolver(), Settings.Global.BOOT_COUNT));
        s.add(Tag.FP, "device name (user set)", () -> Settings.Global.getString(
                ctx.getContentResolver(), "device_name"));
        s.add(Tag.INFO, "developer options on", () -> Settings.Global.getInt(
                ctx.getContentResolver(),
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1);
        s.add(Tag.INFO, "ADB enabled", () -> Settings.Global.getInt(
                ctx.getContentResolver(), Settings.Global.ADB_ENABLED, 0) == 1);
    }

    private String gsfId() {
        android.database.Cursor c = ctx.getContentResolver().query(
                android.net.Uri.parse("content://com.google.android.gsf.gservices"),
                null, null, new String[]{"android_id"}, null);
        if (c == null) {
            throw new IllegalStateException("GSF provider unavailable");
        }
        try {
            if (!c.moveToFirst() || c.getColumnCount() < 2) {
                throw new IllegalStateException("no row");
            }
            return Long.toHexString(Long.parseLong(c.getString(1)));
        } finally {
            c.close();
        }
    }

    // ---- Telephony: mostly locked down since Android 10 -----------------

    private void telephony(Report r) {
        Report.Section s = r.section("Telephony (SIM / carrier)",
                "IMEI, IMSI and the line number now need privileged access; "
                        + "carrier and SIM country still leak.");
        TelephonyManager tm = (TelephonyManager)
                ctx.getSystemService(Context.TELEPHONY_SERVICE);
        if (tm == null) {
            s.blocked("TelephonyManager", "no telephony on this device");
            return;
        }
        s.add(Tag.FP, "network operator name", tm::getNetworkOperatorName);
        s.add(Tag.FP, "network operator (MCC+MNC)", tm::getNetworkOperator);
        s.add(Tag.FP, "SIM operator name", tm::getSimOperatorName);
        s.add(Tag.FP, "SIM country ISO", tm::getSimCountryIso);
        s.add(Tag.FP, "network country ISO", tm::getNetworkCountryIso);
        s.add(Tag.INFO, "phone type", tm::getPhoneType);
        s.add(Tag.INFO, "SIM state", tm::getSimState);
        // Each of these throws SecurityException without READ_PHONE_STATE and
        // typically stays blocked even with it (privileged as of API 29).
        s.add(Tag.ID, "IMEI / MEID", tm::getImei);
        s.add(Tag.ID, "subscriber ID (IMSI)", tm::getSubscriberId);
        s.add(Tag.ID, "SIM serial (ICCID)", tm::getSimSerialNumber);
        s.add(Tag.ID, "line number", tm::getLine1Number);
    }

    // ---- Network interfaces ---------------------------------------------

    private void network(Report r) {
        Report.Section s = r.section("Network interfaces",
                "MAC addresses are randomised/hidden to apps now; the list of "
                        + "interface names and IPv6 addresses can still add entropy.");
        s.add(Tag.INFO, "interfaces", this::interfaces);
        ConnectivityManager cm = (ConnectivityManager)
                ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm != null) {
            s.add(Tag.INFO, "active transport", () -> {
                android.net.Network n = cm.getActiveNetwork();
                android.net.NetworkCapabilities c = cm.getNetworkCapabilities(n);
                if (c == null) {
                    return "none";
                }
                List<String> t = new ArrayList<>();
                if (c.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI)) t.add("wifi");
                if (c.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR)) t.add("cellular");
                if (c.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET)) t.add("ethernet");
                if (c.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)) t.add("vpn");
                return t.isEmpty() ? "other" : t;
            });
        }
    }

    private List<String> interfaces() throws Exception {
        List<String> out = new ArrayList<>();
        for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            StringBuilder sb = new StringBuilder(ni.getName());
            byte[] mac = null;
            try {
                mac = ni.getHardwareAddress();
            } catch (Exception ignored) {
                // permission-gated on some builds; leave null
            }
            if (mac != null && mac.length > 0) {
                sb.append(" mac=");
                for (byte b : mac) {
                    sb.append(String.format("%02x:", b));
                }
                sb.setLength(sb.length() - 1);
            }
            out.add(sb.toString());
        }
        return out;
    }

    // ---- Wi-Fi ----------------------------------------------------------

    private void wifi(Report r) {
        Report.Section s = r.section("Wi-Fi",
                "SSID/BSSID are location-gated; the device MAC is the "
                        + "placeholder 02:00:00:00:00:00 without special access.");
        WifiManager wm = (WifiManager) ctx.getApplicationContext()
                .getSystemService(Context.WIFI_SERVICE);
        if (wm == null) {
            s.blocked("WifiManager", "no Wi-Fi service");
            return;
        }
        s.add(Tag.INFO, "Wi-Fi enabled", wm::isWifiEnabled);
        s.add(Tag.FP, "5GHz supported", wm::is5GHzBandSupported);
        WifiInfo info = wm.getConnectionInfo();
        if (info != null) {
            s.add(Tag.ID, "device MAC", info::getMacAddress);
            s.add(Tag.ID, "BSSID (router)", info::getBSSID);
            s.add(Tag.ID, "SSID", info::getSSID);
            s.add(Tag.INFO, "link speed Mbps", info::getLinkSpeed);
            s.add(Tag.FP, "IP address (int)", info::getIpAddress);
        } else {
            s.blocked("connection info", "not connected");
        }
    }

    // ---- Bluetooth ------------------------------------------------------

    private void bluetooth(Report r) {
        Report.Section s = r.section("Bluetooth",
                "Adapter name is often the user's chosen device name; the MAC "
                        + "needs BLUETOOTH_CONNECT and is usually redacted anyway.");
        BluetoothAdapter a = BluetoothAdapter.getDefaultAdapter();
        if (a == null) {
            s.blocked("BluetoothAdapter", "no Bluetooth on this device");
            return;
        }
        s.add(Tag.ID, "adapter name", a::getName);
        s.add(Tag.ID, "adapter address", a::getAddress);
        s.add(Tag.INFO, "enabled", a::isEnabled);
    }

    // ---- Display --------------------------------------------------------

    private void display(Report r) {
        Report.Section s = r.section("Display",
                "Exact pixel size, density and refresh rate are a classic "
                        + "fingerprinting triple.");
        WindowManager wm = (WindowManager) ctx.getSystemService(Context.WINDOW_SERVICE);
        DisplayMetrics dm = new DisplayMetrics();
        if (wm != null && wm.getDefaultDisplay() != null) {
            wm.getDefaultDisplay().getRealMetrics(dm);
            s.put(Tag.FP, "resolution", dm.widthPixels + "x" + dm.heightPixels);
            s.put(Tag.FP, "density dpi", dm.densityDpi);
            s.put(Tag.FP, "xdpi/ydpi", String.format(Locale.ROOT, "%.1f/%.1f", dm.xdpi, dm.ydpi));
            s.add(Tag.FP, "refresh rate", () -> wm.getDefaultDisplay().getRefreshRate());
        } else {
            s.blocked("Display", "no window manager");
        }
        s.add(Tag.FP, "font scale", () -> ctx.getResources().getConfiguration().fontScale);
    }

    // ---- CPU / memory ---------------------------------------------------

    private void hardware(Report r) {
        Report.Section s = r.section("CPU & memory",
                "Core count, governor and total RAM stay constant for a device "
                        + "model and refine the fingerprint.");
        s.put(Tag.FP, "available processors", Runtime.getRuntime().availableProcessors());
        s.add(Tag.FP, "CPU cores (sysfs)", () -> {
            File d = new File("/sys/devices/system/cpu");
            int n = 0;
            File[] kids = d.listFiles();
            if (kids != null) {
                for (File f : kids) {
                    if (f.getName().matches("cpu[0-9]+")) {
                        n++;
                    }
                }
            }
            return n;
        });
        s.add(Tag.FP, "max CPU freq kHz", () -> firstLine(
                "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq"));
        ActivityManager am = (ActivityManager) ctx.getSystemService(Context.ACTIVITY_SERVICE);
        if (am != null) {
            ActivityManager.MemoryInfo mi = new ActivityManager.MemoryInfo();
            am.getMemoryInfo(mi);
            s.put(Tag.FP, "total RAM MB", mi.totalMem / (1024 * 1024));
            s.put(Tag.INFO, "low RAM device", am.isLowRamDevice());
        }
        s.put(Tag.INFO, "native heap total KB", Debug.getNativeHeapSize() / 1024);
    }

    // ---- Sensors: a strong, permissionless fingerprint ------------------

    private void sensors(Report r) {
        Report.Section s = r.section("Sensors",
                "No permission required. The exact set, vendors and model "
                        + "strings are one of the most stable fingerprints there is.");
        SensorManager sm = (SensorManager) ctx.getSystemService(Context.SENSOR_SERVICE);
        if (sm == null) {
            s.blocked("SensorManager", "no sensor service");
            return;
        }
        List<Sensor> all = sm.getSensorList(Sensor.TYPE_ALL);
        s.put(Tag.FP, "sensor count", all.size());
        for (Sensor sensor : all) {
            s.put(Tag.FP, sensor.getName(),
                    sensor.getVendor() + " v" + sensor.getVersion());
        }
    }

    // ---- Storage --------------------------------------------------------

    private void storage(Report r) {
        Report.Section s = r.section("Storage",
                "Total capacity is a coarse fingerprint bucket (64/128/256 GB).");
        try {
            StatFs fs = new StatFs(Environment.getDataDirectory().getPath());
            long total = fs.getBlockCountLong() * fs.getBlockSizeLong();
            long free = fs.getAvailableBlocksLong() * fs.getBlockSizeLong();
            s.put(Tag.FP, "data total GB", String.format(Locale.ROOT, "%.1f", total / 1e9));
            s.put(Tag.INFO, "data free GB", String.format(Locale.ROOT, "%.1f", free / 1e9));
        } catch (Exception e) {
            s.blocked("StatFs", Report.describe(e));
        }
        s.put(Tag.INFO, "external emulated", Environment.isExternalStorageEmulated());
    }

    // ---- Battery / uptime -----------------------------------------------

    private void battery(Report r) {
        Report.Section s = r.section("Battery & uptime",
                "Charge counter and capacity design help profile the exact "
                        + "hardware; uptime is a short-lived session signal.");
        BatteryManager bm = (BatteryManager) ctx.getSystemService(Context.BATTERY_SERVICE);
        if (bm != null) {
            s.put(Tag.INFO, "level %",
                    bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY));
            s.put(Tag.FP, "charge counter uAh",
                    bm.getLongProperty(BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER));
            s.put(Tag.FP, "energy counter nWh",
                    bm.getLongProperty(BatteryManager.BATTERY_PROPERTY_ENERGY_COUNTER));
        }
        s.put(Tag.INFO, "uptime ms", SystemClock.elapsedRealtime());
        s.add(Tag.FP, "boot time (uptime-derived)",
                () -> System.currentTimeMillis() - SystemClock.elapsedRealtime());
    }

    // ---- Locale / time --------------------------------------------------

    private void locale(Report r) {
        Report.Section s = r.section("Locale, time & settings",
                "Language, timezone and 24-hour preference are low entropy "
                        + "individually but stack up in a fingerprint.");
        Configuration cfg = ctx.getResources().getConfiguration();
        s.put(Tag.FP, "locale", cfg.getLocales().get(0).toString());
        s.put(Tag.FP, "timezone", TimeZone.getDefault().getID());
        s.put(Tag.FP, "timezone offset min",
                TimeZone.getDefault().getRawOffset() / 60000);
        s.add(Tag.INFO, "24-hour clock", () -> Settings.System.getString(
                ctx.getContentResolver(), Settings.System.TIME_12_24));
        s.put(Tag.FP, "system default locale", Locale.getDefault().toString());
        s.put(Tag.FP, "night mode", (cfg.uiMode & Configuration.UI_MODE_NIGHT_MASK)
                == Configuration.UI_MODE_NIGHT_YES ? "yes" : "no");
    }

    // ---- Raw kernel files (same set the Guard app probes) ---------------

    private void kernelFiles(Report r) {
        Report.Section s = r.section("Kernel & sysfs files",
                "Direct reads the in-kernel Fortress guard is built to deny. "
                        + "On stock Android several still succeed.");
        String[][] files = {
                {"/proc/cpuinfo", "cpuinfo"},
                {"/proc/version", "kernel build string"},
                {"/proc/cmdline", "boot cmdline"},
                {"/proc/sys/kernel/random/boot_id", "boot id (per-boot, all apps see same)"},
                {"/sys/devices/soc0/serial_number", "SoC serial"},
                {"/sys/devices/soc0/soc_id", "SoC id"},
                {"/sys/devices/soc0/machine", "SoC machine"},
                {"/sys/class/net/wlan0/address", "Wi-Fi MAC (sysfs)"},
                {"/sys/firmware/devicetree/base/serial-number", "devicetree serial"},
                {"/sys/block/sda/device/model", "UFS model"},
                {"/sys/block/sda/device/serial", "UFS serial"},
                {"/proc/net/arp", "ARP neighbours"},
        };
        for (String[] f : files) {
            final String path = f[0];
            s.add(readTag(path), f[1] + "  " + path, () -> {
                String line = firstLine(path);
                if (line == null) {
                    throw new IllegalStateException("unreadable");
                }
                return line;
            });
        }
    }

    private static Tag readTag(String path) {
        // Serials and boot id are stable identifiers; the rest is fingerprint.
        if (path.contains("serial") || path.contains("boot_id")) {
            return Tag.ID;
        }
        return Tag.FP;
    }

    // ---- Installed apps: QUERY_ALL_PACKAGES, a near-unique set ----------

    private void installedApps(Report r) {
        Report.Section s = r.section("Installed apps",
                "With QUERY_ALL_PACKAGES the full app list is visible. The set "
                        + "of packages is close to unique per user — a strong ID.");
        List<PackageInfo> pkgs;
        try {
            pkgs = pm.getInstalledPackages(0);
        } catch (Exception e) {
            s.blocked("getInstalledPackages", Report.describe(e));
            return;
        }
        int user = 0;
        List<String> names = new ArrayList<>();
        for (PackageInfo p : pkgs) {
            boolean system = p.applicationInfo != null
                    && (p.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if (!system) {
                user++;
                names.add(p.packageName);
            }
        }
        Collections.sort(names);
        s.put(Tag.INFO, "packages total", pkgs.size());
        s.put(Tag.ID, "user-installed count", user);
        s.put(Tag.ID, "user-installed set (hash)", digest(names));
        s.put(Tag.ID, "user-installed packages", names);
    }

    private static String digest(List<String> names) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (String n : names) {
                md.update(n.getBytes(StandardCharsets.UTF_8));
                md.update((byte) '\n');
            }
            return Report.hex(md.digest()).substring(0, 16);
        } catch (Exception e) {
            return "(sha-256 unavailable)";
        }
    }

    // ---- helpers --------------------------------------------------------

    private static String firstLine(String path) {
        try (BufferedReader in = new BufferedReader(new FileReader(path))) {
            StringBuilder sb = new StringBuilder();
            String line;
            int lines = 0;
            while ((line = in.readLine()) != null && lines < 40) {
                if (sb.length() > 0) {
                    sb.append('\n');
                }
                sb.append(line.trim());
                lines++;
            }
            return sb.length() == 0 ? "" : sb.toString();
        } catch (Exception e) {
            return null;
        }
    }
}
