// SPDX-License-Identifier: GPL-2.0
package org.fortressos.telemetry;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

/**
 * Everything one probe run saw, grouped into sections.
 *
 * Each value carries a tag saying how much it is worth to a tracker, so the
 * report reads as a list of leaks rather than a spec sheet.
 */
final class Report {

    enum Tag {
        /** Stable, unique to this phone or user: survives an app reinstall. */
        ID,
        /** Not unique alone, but adds entropy to a fingerprint. */
        FP,
        /** Readable, low value on its own. */
        INFO,
        /** The platform refused: exception, null or a redacted placeholder. */
        BLOCKED
    }

    static final class Item {
        final String name;
        final String value;
        final Tag tag;

        Item(String name, String value, Tag tag) {
            this.name = name;
            this.value = value;
            this.tag = tag;
        }
    }

    interface Value {
        Object get() throws Throwable;
    }

    static final class Section {
        final String title;
        final String note;
        final List<Item> items = new ArrayList<>();

        Section(String title, String note) {
            this.title = title;
            this.note = note;
        }

        /** Reads one value; a failure becomes a BLOCKED row, never a crash. */
        Section add(Tag tag, String name, Value v) {
            Object o;
            try {
                o = v.get();
            } catch (Throwable t) {
                items.add(new Item(name, describe(t), Tag.BLOCKED));
                return this;
            }
            if (o == null) {
                items.add(new Item(name, "null", Tag.BLOCKED));
                return this;
            }
            String s = format(o);
            items.add(new Item(name, s, isPlaceholder(s) ? Tag.BLOCKED : tag));
            return this;
        }

        Section put(Tag tag, String name, Object value) {
            return add(tag, name, () -> value);
        }

        Section blocked(String name, String why) {
            items.add(new Item(name, why, Tag.BLOCKED));
            return this;
        }

        int count(Tag tag) {
            int n = 0;
            for (Item i : items) {
                if (i.tag == tag) {
                    n++;
                }
            }
            return n;
        }
    }

    final List<Section> sections = new ArrayList<>();
    final long createdAt = System.currentTimeMillis();

    Section section(String title, String note) {
        Section s = new Section(title, note);
        sections.add(s);
        return s;
    }

    int count(Tag tag) {
        int n = 0;
        for (Section s : sections) {
            n += s.count(tag);
        }
        return n;
    }

    JSONObject toJson() throws JSONException {
        JSONObject root = new JSONObject();
        root.put("created_at", createdAt);
        for (Tag t : Tag.values()) {
            root.put("count_" + t.name().toLowerCase(Locale.ROOT), count(t));
        }
        JSONArray secs = new JSONArray();
        for (Section s : sections) {
            JSONObject js = new JSONObject();
            js.put("title", s.title);
            JSONArray items = new JSONArray();
            for (Item i : s.items) {
                JSONObject ji = new JSONObject();
                ji.put("name", i.name);
                ji.put("tag", i.tag.name());
                ji.put("value", i.value);
                items.put(ji);
            }
            js.put("items", items);
            secs.put(js);
        }
        root.put("sections", secs);
        return root;
    }

    static String describe(Throwable t) {
        String msg = t.getMessage();
        String name = t.getClass().getSimpleName();
        if (msg == null || msg.isEmpty()) {
            return name;
        }
        msg = msg.replaceAll("\\s+", " ").trim();
        if (msg.length() > 160) {
            msg = msg.substring(0, 160) + "…";
        }
        return name + ": " + msg;
    }

    static String format(Object o) {
        if (o instanceof Object[]) {
            return join(java.util.Arrays.asList((Object[]) o));
        }
        if (o instanceof int[]) {
            return java.util.Arrays.toString((int[]) o);
        }
        if (o instanceof long[]) {
            return java.util.Arrays.toString((long[]) o);
        }
        if (o instanceof float[]) {
            return java.util.Arrays.toString((float[]) o);
        }
        if (o instanceof byte[]) {
            return hex((byte[]) o);
        }
        if (o instanceof Collection) {
            return join((Collection<?>) o);
        }
        String s = String.valueOf(o);
        return s.isEmpty() ? "(empty)" : s;
    }

    private static String join(Collection<?> c) {
        if (c.isEmpty()) {
            return "(empty)";
        }
        StringBuilder sb = new StringBuilder();
        for (Object x : c) {
            if (sb.length() > 0) {
                sb.append('\n');
            }
            sb.append(x);
        }
        return sb.toString();
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }

    /** Values Android hands out instead of the real thing. */
    private static boolean isPlaceholder(String s) {
        return s.equals("02:00:00:00:00:00")
                || s.equals("<unknown ssid>")
                || s.equals("unknown")
                || s.equals("00000000-0000-0000-0000-000000000000");
    }
}
