// SPDX-License-Identifier: GPL-2.0
package org.fortressos.guard;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Fortress Guard: what the in-kernel guard is doing, on one screen.
 *
 * Deliberately dependency-free (no AndroidX): it is a diagnostic tool that
 * has to build and install anywhere, including on a phone running a stock
 * LineageOS build with our kernel swapped in.
 */
public class MainActivity extends Activity {

    private static final int PAD = 24;
    private static final int RECENT = 60;

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());

    private TextView headline;
    private TextView body;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(PAD, PAD, PAD, PAD);
        // Android 15+ draws apps edge to edge, so keep content out from under
        // the status and navigation bars.
        root.setFitsSystemWindows(true);

        headline = new TextView(this);
        headline.setTextSize(15);
        headline.setTypeface(Typeface.DEFAULT_BOLD);
        headline.setPadding(0, PAD / 2, 0, PAD);
        root.addView(headline, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));

        Button refresh = new Button(this);
        refresh.setText("Refresh");
        refresh.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                load();
            }
        });
        root.addView(refresh);

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
        load();
    }

    private void load() {
        headline.setText("Reading the kernel log…");
        headline.setGravity(Gravity.START);
        body.setText("");
        worker.execute(new Runnable() {
            @Override
            public void run() {
                final GuardReport.Result r = GuardReport.collect();
                final String text = render(r);
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        showHeadline(r);
                        body.setText(text);
                    }
                });
            }
        });
    }

    private void showHeadline(GuardReport.Result r) {
        boolean guardSeen = r.logReadable || r.status != null;
        String state;
        int color;
        if (!guardSeen) {
            state = "No guard activity visible";
            color = Color.parseColor("#c08a2e");
        } else if (r.permissive) {
            state = "Guard active — PERMISSIVE (logging only)";
            color = Color.parseColor("#c08a2e");
        } else {
            state = "Guard active — ENFORCING";
            color = Color.parseColor("#2e8b57");
        }
        headline.setText(state);
        headline.setTextColor(color);
    }

    private String render(GuardReport.Result r) {
        StringBuilder sb = new StringBuilder();

        sb.append("KERNEL\n").append(r.kernelVersion).append("\n\n");

        sb.append("STATUS\n");
        if (r.status != null) {
            sb.append(r.status).append('\n');
        } else {
            sb.append("securityfs is not mounted on this build, so the policy\n")
              .append("interface is unreachable. Events below come from the\n")
              .append("kernel log instead.\n\n");
        }

        if (!r.logReadable) {
            sb.append("KERNEL LOG UNAVAILABLE\n");
            if (r.logError != null) {
                sb.append(r.logError).append('\n');
            }
            sb.append("\nGrant the permission once, over adb:\n")
              .append("  adb shell pm grant org.fortressos.guard \\\n")
              .append("      android.permission.READ_LOGS\n")
              .append("then force-stop and reopen this app.\n");
            return sb.toString();
        }

        sb.append("EVENTS  gate ").append(r.gate)
          .append("   egress ").append(r.egress)
          .append("   unix ipc ").append(r.ipc).append("\n\n");

        appendByUid(sb, "BLOCKED FROM LAUNCHING", r.events, GuardReport.Kind.GATE);
        appendByUid(sb, "BLOCKED FROM THE NETWORK", r.events, GuardReport.Kind.EGRESS);
        appendByUid(sb, "BLOCKED FROM OTHER APPS", r.events, GuardReport.Kind.IPC);

        sb.append("RECENT\n");
        List<GuardReport.Event> events = r.events;
        int from = Math.max(0, events.size() - RECENT);
        for (int i = events.size() - 1; i >= from; i--) {
            GuardReport.Event e = events.get(i);
            sb.append(label(e.kind)).append(' ');
            if (e.uid >= 0) {
                sb.append(GuardReport.nameForUid(getPackageManager(), e.uid)).append(' ');
            }
            sb.append(e.detail).append('\n');
        }
        return sb.toString();
    }

    private void appendByUid(StringBuilder sb, String title,
                             List<GuardReport.Event> events, GuardReport.Kind kind) {
        Map<Integer, Integer> counts = GuardReport.countByUid(events, kind);
        if (counts.isEmpty()) {
            return;
        }
        sb.append(title).append('\n');
        for (Map.Entry<Integer, Integer> e : counts.entrySet()) {
            sb.append(String.format("  %-38s %3d  %s\n",
                    GuardReport.nameForUid(getPackageManager(), e.getKey()),
                    e.getValue(),
                    GuardReport.classOfUid(e.getKey())));
        }
        sb.append('\n');
    }

    private static String label(GuardReport.Kind kind) {
        switch (kind) {
            case GATE: return "[launch]";
            case EGRESS: return "[net]   ";
            case IPC: return "[ipc]   ";
            default: return "[info]  ";
        }
    }

    @Override
    protected void onDestroy() {
        worker.shutdownNow();
        super.onDestroy();
    }
}
