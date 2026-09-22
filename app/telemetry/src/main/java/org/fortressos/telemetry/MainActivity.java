// SPDX-License-Identifier: GPL-2.0
package org.fortressos.telemetry;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Fortress Telemetry: one screen of everything an unrooted app can learn
 * about the phone it runs on.
 *
 * A companion to Fortress Guard. The Guard app shows what the in-kernel LSM
 * blocks; this app shows the attack surface from the app side — the same
 * probe an ad SDK runs on first launch, made visible. No INTERNET permission,
 * so nothing leaves the device: it is a mirror, not a tracker.
 *
 * Dependency-free (no AndroidX) to match the Guard app and install anywhere.
 */
public class MainActivity extends Activity {

    private static final int PAD = 24;
    private static final int REQ_PERMS = 1;

    /** Runtime permissions we ask for, to show what "Allow" hands over. */
    private static final String[] RUNTIME_PERMS = {
            Manifest.permission.READ_PHONE_STATE,
            Manifest.permission.READ_PHONE_NUMBERS,
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.NEARBY_WIFI_DEVICES,
            Manifest.permission.GET_ACCOUNTS,
    };

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());

    private TextView headline;
    private TextView body;
    private Report last;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(PAD, PAD, PAD, PAD);
        root.setFitsSystemWindows(true);

        headline = new TextView(this);
        headline.setTextSize(15);
        headline.setTypeface(Typeface.DEFAULT_BOLD);
        headline.setPadding(0, PAD / 2, 0, PAD / 2);
        root.addView(headline, wrap());

        LinearLayout buttons = new LinearLayout(this);
        buttons.setOrientation(LinearLayout.HORIZONTAL);
        buttons.addView(button("Refresh", v -> probe()));
        buttons.addView(button("Permissions", v -> requestRuntimePerms()));
        buttons.addView(button("Save", v -> save()));
        root.addView(buttons);

        body = new TextView(this);
        body.setTypeface(Typeface.MONOSPACE);
        body.setTextSize(11);
        body.setTextIsSelectable(true);
        body.setPadding(0, PAD, 0, PAD);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(body);
        root.addView(scroll, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        setContentView(root);
        probe();
    }

    private Button button(String text, View.OnClickListener onClick) {
        Button b = new Button(this);
        b.setText(text);
        b.setOnClickListener(onClick);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        b.setLayoutParams(lp);
        return b;
    }

    private LinearLayout.LayoutParams wrap() {
        return new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
    }

    private void probe() {
        headline.setText("Probing…");
        headline.setTextColor(Color.parseColor("#c08a2e"));
        body.setText("");
        worker.execute(() -> {
            final Report r = new Collector(this).collect();
            final CharSequence text = render(r);
            ui.post(() -> {
                last = r;
                showHeadline(r);
                body.setText(text);
            });
        });
    }

    private void showHeadline(Report r) {
        int id = r.count(Report.Tag.ID);
        int fp = r.count(Report.Tag.FP);
        int blocked = r.count(Report.Tag.BLOCKED);
        headline.setText(id + " stable IDs · " + fp + " fingerprint bits · "
                + blocked + " blocked");
        headline.setTextColor(id > 0
                ? Color.parseColor("#c0392b")   // red: something uniquely identifies you
                : Color.parseColor("#2e8b57"));
    }

    private CharSequence render(Report r) {
        SpannableStringBuilder sb = new SpannableStringBuilder();

        String grantedNote = grantedRuntimeCount() + "/" + RUNTIME_PERMS.length
                + " runtime permissions granted. Tap Permissions to grant more,\n"
                + "then Refresh to see what opens up.";
        append(sb, grantedNote + "\n\n", Color.parseColor("#888888"), false);

        for (Report.Section s : r.sections) {
            int id = s.count(Report.Tag.ID);
            append(sb, s.title.toUpperCase(Locale.ROOT), null, true);
            append(sb, "  (" + s.items.size() + " probes, " + id + " stable ID"
                    + (id == 1 ? "" : "s") + ")\n", Color.parseColor("#888888"), false);
            append(sb, "  " + s.note + "\n", Color.parseColor("#888888"), false);

            for (Report.Item i : s.items) {
                int c = colorFor(i.tag);
                append(sb, "  " + pad(tagLabel(i.tag), 8), c, true);
                append(sb, pad(i.name, 30), null, false);
                append(sb, oneLine(i.value) + "\n", c, false);
                if (i.value.indexOf('\n') >= 0) {
                    // Multi-line values (app list, cpuinfo): indent the rest.
                    append(sb, indent(i.value) + "\n",
                            Color.parseColor("#777777"), false);
                }
            }
            append(sb, "\n", null, false);
        }
        return sb;
    }

    private static String tagLabel(Report.Tag t) {
        switch (t) {
            case ID: return "ID";
            case FP: return "fp";
            case BLOCKED: return "blocked";
            default: return "info";
        }
    }

    private static int colorFor(Report.Tag t) {
        switch (t) {
            case ID: return Color.parseColor("#c0392b");
            case FP: return Color.parseColor("#c08a2e");
            case BLOCKED: return Color.parseColor("#2e8b57");
            default: return Color.parseColor("#4a7bb5");
        }
    }

    private static String oneLine(String v) {
        int nl = v.indexOf('\n');
        String first = nl < 0 ? v : v.substring(0, nl) + " …";
        return first.length() <= 44 ? first : first.substring(0, 44) + "…";
    }

    private static String indent(String v) {
        StringBuilder out = new StringBuilder();
        for (String line : v.split("\n")) {
            if (out.length() > 0) {
                out.append('\n');
            }
            out.append("      ").append(line);
        }
        return out.toString();
    }

    private static String pad(String s, int n) {
        if (s.length() >= n) {
            return s.substring(0, n - 1) + " ";
        }
        StringBuilder sb = new StringBuilder(s);
        while (sb.length() < n) {
            sb.append(' ');
        }
        return sb.toString();
    }

    private void append(SpannableStringBuilder sb, CharSequence text, Integer color,
                        boolean bold) {
        int start = sb.length();
        sb.append(text);
        if (color != null) {
            sb.setSpan(new ForegroundColorSpan(color), start, sb.length(),
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
        if (bold) {
            sb.setSpan(new StyleSpan(Typeface.BOLD), start, sb.length(),
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
    }

    // ---- Runtime permissions --------------------------------------------

    private int grantedRuntimeCount() {
        int n = 0;
        for (String p : RUNTIME_PERMS) {
            if (checkSelfPermission(p) == PackageManager.PERMISSION_GRANTED) {
                n++;
            }
        }
        return n;
    }

    private void requestRuntimePerms() {
        requestPermissions(RUNTIME_PERMS, REQ_PERMS);
    }

    @Override
    public void onRequestPermissionsResult(int req, String[] perms, int[] results) {
        super.onRequestPermissionsResult(req, perms, results);
        if (req == REQ_PERMS) {
            probe();   // re-run so newly-granted sources show their values
        }
    }

    // ---- Save report -----------------------------------------------------

    private void save() {
        if (last == null) {
            toast("Nothing to save yet");
            return;
        }
        worker.execute(() -> {
            String stamp = new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US)
                    .format(new Date());
            File dir = getExternalFilesDir(null);
            if (dir == null) {
                dir = getFilesDir();
            }
            File out = new File(dir, "telemetry-" + stamp + ".json");
            String result;
            try {
                byte[] json = last.toJson().toString(2)
                        .getBytes(StandardCharsets.UTF_8);
                try (FileOutputStream fos = new FileOutputStream(out)) {
                    fos.write(json);
                }
                result = "Saved to\n" + out.getAbsolutePath();
            } catch (Exception e) {
                result = "Save failed: " + Report.describe(e);
            }
            final String msg = result;
            ui.post(() -> toast(msg));
        });
    }

    private void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_LONG).show();
    }

    @Override
    protected void onDestroy() {
        worker.shutdownNow();
        super.onDestroy();
    }
}
