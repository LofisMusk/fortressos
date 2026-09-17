// SPDX-License-Identifier: GPL-2.0
package org.fortressos.guard;

import android.content.pm.PackageManager;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads what the Fortress LSM reports and turns it into a report.
 *
 * On a stock LineageOS userspace securityfs is not mounted and dmesg needs
 * CAP_SYSLOG, so the kernel ring buffer reached through logd is the only
 * source available to an app. That needs READ_LOGS, granted over adb.
 * Once the Fortress ROM ships this app as a platform app it will read
 * /sys/kernel/security/fortress directly instead.
 */
final class GuardReport {

    static final String STATUS_PATH = "/sys/kernel/security/fortress/status";

    enum Kind { GATE, EGRESS, IPC, INFO }

    static final class Event {
        final Kind kind;
        final int uid;          // -1 when the line carries no uid
        final String detail;    // target uid, interface, or free text
        final boolean permissive;
        final String raw;

        Event(Kind kind, int uid, String detail, boolean permissive, String raw) {
            this.kind = kind;
            this.uid = uid;
            this.detail = detail;
            this.permissive = permissive;
            this.raw = raw;
        }
    }

    static final class Result {
        String kernelVersion = "unknown";
        String status;                       // securityfs status, or null
        boolean logReadable;
        String logError;
        boolean permissive;
        final List<Event> events = new ArrayList<>();
        int gate, egress, ipc;
    }

    private static final Pattern GATE =
            Pattern.compile("fortress: (\\(permissive\\) )?deny setuid pid=(\\d+) comm=(\\S+) (\\d+) -> (\\d+)");
    private static final Pattern EGRESS =
            Pattern.compile("fortress: (\\(permissive\\) )?deny egress uid=(\\d+) dev=(\\S+)");
    private static final Pattern IPC =
            Pattern.compile("fortress: (\\(permissive\\) )?deny unix ipc (\\d+) -> (\\d+)");
    private static final Pattern INFO =
            Pattern.compile("fortress: ((?:initialized|policy|netfilter|securityfs|enforce)[^\\n]*)");

    private GuardReport() {
    }

    static Result collect() {
        Result r = new Result();
        // /proc/version is denied to untrusted_app by SELinux, and reading it
        // only produces an audit denial; the release string is exported as a
        // system property anyway.
        String release = System.getProperty("os.version");
        r.kernelVersion = (release == null || release.isEmpty()) ? "unknown" : release;
        r.status = readFile(STATUS_PATH);
        readKernelLog(r);
        return r;
    }

    private static void readKernelLog(Result r) {
        Process p = null;
        try {
            p = new ProcessBuilder("logcat", "-b", "kernel", "-d", "-t", "4000")
                    .redirectErrorStream(true).start();
            BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = in.readLine()) != null) {
                if (!line.contains("fortress:")) {
                    if (line.contains("Permission denied") || line.contains("SecurityException")) {
                        r.logError = line.trim();
                    }
                    continue;
                }
                r.logReadable = true;
                Event e = parse(line);
                if (e == null) {
                    continue;
                }
                if (e.permissive) {
                    r.permissive = true;
                }
                r.events.add(e);
                switch (e.kind) {
                    case GATE: r.gate++; break;
                    case EGRESS: r.egress++; break;
                    case IPC: r.ipc++; break;
                    default: break;
                }
            }
            in.close();
        } catch (Exception e) {
            r.logError = e.getMessage();
        } finally {
            if (p != null) {
                p.destroy();
            }
        }
        if (!r.logReadable && r.logError == null) {
            r.logError = "no fortress lines in the kernel buffer (it only holds\n"
                    + "what happened since boot, and `adb logcat -c` clears it)";
        }
    }

    private static Event parse(String line) {
        Matcher m = EGRESS.matcher(line);
        if (m.find()) {
            return new Event(Kind.EGRESS, Integer.parseInt(m.group(2)),
                    m.group(3), m.group(1) != null, line);
        }
        m = GATE.matcher(line);
        if (m.find()) {
            return new Event(Kind.GATE, Integer.parseInt(m.group(5)),
                    "from uid " + m.group(4) + ", " + m.group(3), m.group(1) != null, line);
        }
        m = IPC.matcher(line);
        if (m.find()) {
            return new Event(Kind.IPC, Integer.parseInt(m.group(2)),
                    "to uid " + m.group(3), m.group(1) != null, line);
        }
        m = INFO.matcher(line);
        if (m.find()) {
            return new Event(Kind.INFO, -1, m.group(1), false, line);
        }
        return null;
    }

    /** uid -> how many events, most active first. */
    static Map<Integer, Integer> countByUid(List<Event> events, Kind kind) {
        Map<Integer, Integer> counts = new LinkedHashMap<>();
        for (Event e : events) {
            if (e.kind == kind && e.uid >= 0) {
                Integer c = counts.get(e.uid);
                counts.put(e.uid, c == null ? 1 : c + 1);
            }
        }
        List<Map.Entry<Integer, Integer>> sorted = new ArrayList<>(counts.entrySet());
        sorted.sort(Comparator.comparingInt((Map.Entry<Integer, Integer> x) -> x.getValue()).reversed());
        Map<Integer, Integer> out = new LinkedHashMap<>();
        for (Map.Entry<Integer, Integer> e : sorted) {
            out.put(e.getKey(), e.getValue());
        }
        return out;
    }

    /** A readable name for a uid: package name, Android AID, or the number. */
    static String nameForUid(PackageManager pm, int uid) {
        String known = knownAid(uid);
        if (known != null) {
            return known + " (" + uid + ")";
        }
        try {
            String[] pkgs = pm.getPackagesForUid(uid);
            if (pkgs != null && pkgs.length > 0) {
                String name = pkgs[0];
                if (pkgs.length > 1) {
                    name += " +" + (pkgs.length - 1);
                }
                return name + " (" + uid + ")";
            }
        } catch (Exception ignored) {
            // package visibility can still refuse; fall through to the number
        }
        return "uid " + uid;
    }

    private static String knownAid(int uid) {
        switch (uid) {
            case 0: return "root";
            case 1000: return "system";
            case 1001: return "radio";
            case 1013: return "media";
            case 1021: return "gps";
            case 1029: return "clat";
            case 1051: return "dns";
            case 1073: return "network_stack";
            case 2000: return "shell";
            default: return null;
        }
    }

    static String classOfUid(int uid) {
        int appid = uid % 100000;
        if (appid >= 10000 && appid <= 19999) {
            return "app";
        }
        if (appid >= 20000 && appid <= 29999) {
            return "sdk sandbox";
        }
        if (appid >= 90000 && appid <= 99999) {
            return "isolated";
        }
        return "system";
    }

    private static String readFile(String path) {
        File f = new File(path);
        if (!f.exists()) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        try (BufferedReader in = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = in.readLine()) != null) {
                sb.append(line).append('\n');
            }
        } catch (Exception e) {
            return null;
        }
        return sb.toString();
    }
}
