/*
 * Copyright (C) 2026 IchthysOS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.ichthys.probe;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.os.Build;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * The results of one labelled run, written as JSON to
 * {@code <external files dir>/reports/<label>.json}
 * (/sdcard/Android/data/org.ichthys.probe/files/reports/), which adb can pull. A tap probe run
 * later rewrites the same file with its result merged in.
 */
public final class Report {
    public static final int FORMAT = 1;

    public final String label;
    private final Map<String, Probe> mProbes = new LinkedHashMap<>();
    private final Map<String, Result> mResults = new LinkedHashMap<>();
    private final long mStarted = System.currentTimeMillis();
    /** IchthysOS: the "shields" block of a report read back by {@link #load}; null when live. */
    Map<String, String> recordedShields;
    /** IchthysOS: the Guard expectations ({@code expect_*} extras) the run was given; may be empty. */
    final Map<String, String> expectations = new LinkedHashMap<>();

    /** The launch extras a report keeps: what Guard expected, never the token. */
    static final String[] KEPT_EXTRAS = {
        "stand_in", "expect_net", "expect_location", "expect_fake_latlon", "expect_scans",
        "expect_lan", "expect_shields", "expect_screen_off", "expect_spoofed", "expect_profile",
        "expect_ip",
    };

    Report(String label) {
        this.label = label;
    }

    public synchronized void add(Probe p, Result r) {
        mProbes.put(p.id, p);
        mResults.put(p.id, r);
    }

    public synchronized Result get(String id) {
        return mResults.get(id);
    }

    public synchronized int count(Verdict v) {
        int n = 0;
        for (Result r : mResults.values()) {
            if (r.verdict == v) {
                n++;
            }
        }
        return n;
    }

    public synchronized int size() {
        return mResults.size();
    }

    /** IchthysOS: every result by probe id, in run order (a copy). */
    public synchronized Map<String, Result> entries() {
        return new LinkedHashMap<>(mResults);
    }

    /** Writes the file and returns its path, or null on failure (logged). */
    public synchronized File write(Ctx c) {
        try {
            final JSONObject root = new JSONObject();
            root.put("format", FORMAT);
            root.put("label", label);
            root.put("started", iso(mStarted));
            root.put("written", iso(System.currentTimeMillis()));
            root.put("device", device(c.app));
            final JSONObject shields = new JSONObject();
            for (Map.Entry<String, String> e : c.shields.describe().entrySet()) {
                shields.put(e.getKey(), e.getValue());
            }
            root.put("shields", shields);
            final JSONObject expect = new JSONObject();
            for (String k : KEPT_EXTRAS) {
                final String v = c.option(k);
                if (v != null) {
                    expect.put(k, v);
                    expectations.put(k, v);
                }
            }
            root.put("expect", expect);
            final JSONObject totals = new JSONObject();
            for (Verdict v : Verdict.values()) {
                totals.put(v.key, count(v));
            }
            root.put("totals", totals);
            final JSONArray arr = new JSONArray();
            for (Map.Entry<String, Result> e : mResults.entrySet()) {
                arr.put(toJson(mProbes.get(e.getKey()), e.getValue()));
            }
            root.put("probes", arr);

            final File dir = new File(c.app.getExternalFilesDir(null), "reports");
            if (!dir.isDirectory() && !dir.mkdirs()) {
                Log.e(Runner.TAG, "cannot create " + dir);
                return null;
            }
            final File out = new File(dir, safe(label) + ".json");
            final File tmp = new File(dir, safe(label) + ".json.tmp");
            try (FileOutputStream os = new FileOutputStream(tmp)) {
                os.write(root.toString(1).getBytes(StandardCharsets.UTF_8));
            }
            if (!tmp.renameTo(out)) {
                Log.e(Runner.TAG, "cannot rename report to " + out);
                return null;
            }
            return out;
        } catch (Exception e) {
            Log.e(Runner.TAG, "report write failed", e);
            return null;
        }
    }

    /**
     * IchthysOS: reads back a report this app wrote, so the screen can show the last run at
     * launch. Probes this build no longer has are left out. Null when the file is unreadable.
     */
    static Report load(File f) {
        if (f == null || !f.isFile()) {
            return null;
        }
        try {
            final JSONObject root = new JSONObject(new String(
                    java.nio.file.Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8));
            final Report report = new Report(root.optString("label", f.getName()));
            report.recordedShields = new LinkedHashMap<>();
            final JSONObject shields = root.optJSONObject("shields");
            if (shields != null) {
                for (java.util.Iterator<String> it = shields.keys(); it.hasNext();) {
                    final String k = it.next();
                    report.recordedShields.put(k, shields.optString(k));
                }
            }
            final JSONObject expect = root.optJSONObject("expect");
            if (expect != null) {
                for (java.util.Iterator<String> it = expect.keys(); it.hasNext();) {
                    final String k = it.next();
                    report.expectations.put(k, expect.optString(k));
                }
            }
            final JSONArray arr = root.optJSONArray("probes");
            for (int i = 0; arr != null && i < arr.length(); i++) {
                final JSONObject o = arr.getJSONObject(i);
                final Probe p = Registry.byId(o.optString("id"));
                if (p == null) {
                    continue;
                }
                Outcome outcome = Outcome.ERROR;
                for (Outcome x : Outcome.values()) {
                    if (x.key.equals(o.optString("outcome"))) {
                        outcome = x;
                    }
                }
                final Result r = Result.of(outcome);
                final JSONObject d = o.optJSONObject("detail");
                if (d != null) {
                    for (java.util.Iterator<String> it = d.keys(); it.hasNext();) {
                        final String k = it.next();
                        r.detail.put(k, d.optString(k));
                    }
                }
                for (Verdict v : Verdict.values()) {
                    if (v.key.equals(o.optString("verdict"))) {
                        r.verdict = v;
                    }
                }
                r.verdictWhy = o.optString("verdict_why");
                r.granted = o.optString("granted", "n/a");
                r.millis = o.optLong("millis");
                report.add(p, r);
            }
            return report;
        } catch (Exception e) {
            Log.w(Runner.TAG, "report not readable: " + f, e);
            return null;
        }
    }

    private static JSONObject toJson(Probe p, Result r) throws JSONException {
        final JSONObject o = new JSONObject();
        o.put("id", p.id);
        o.put("category", p.category);
        o.put("reveals", p.reveals);
        final JSONArray perms = new JSONArray();
        for (String s : p.permissions) {
            perms.put(s);
        }
        o.put("permissions", perms);
        o.put("granted", r.granted);
        o.put("outcome", r.outcome.key);
        final JSONObject d = new JSONObject();
        for (Map.Entry<String, String> e : r.detail.entrySet()) {
            d.put(e.getKey(), e.getValue());
        }
        o.put("detail", d);
        o.put("verdict", r.verdict.key);
        o.put("verdict_why", r.verdictWhy);
        o.put("millis", r.millis);
        o.put("tap", p.isTapProbe());
        final Expect x = p.expectation();
        if (x != null) {
            final JSONObject e = new JSONObject();
            e.put("feature", x.feature);
            e.put("promise", x.promise);
            e.put("expected", x.expectedText());
            e.put("source", x.source);
            o.put("expectation", e);
        }
        return o;
    }

    private static JSONObject device(Context context) throws JSONException {
        final JSONObject o = new JSONObject();
        o.put("sdk", Build.VERSION.SDK_INT);
        o.put("release", Build.VERSION.RELEASE);
        o.put("security_patch", Build.VERSION.SECURITY_PATCH);
        o.put("model", Build.MODEL);
        o.put("device", Build.DEVICE);
        o.put("build_id", Build.ID);
        o.put("incremental", Build.VERSION.INCREMENTAL);
        try {
            final PackageInfo pi = context.getPackageManager()
                    .getPackageInfo(context.getPackageName(), 0);
            o.put("probe_version", pi.versionName + " (" + pi.getLongVersionCode() + ")");
            o.put("probe_installer", String.valueOf(context.getPackageManager()
                    .getInstallSourceInfo(context.getPackageName()).getInstallingPackageName()));
        } catch (Exception e) {
            o.put("probe_version", "?");
        }
        o.put("probe_target_sdk", context.getApplicationInfo().targetSdkVersion);
        // A locked or sleeping phone changes many answers (clipboard reads are refused while
        // locked, sensors and scans throttle): record the state the run saw.
        final android.app.KeyguardManager km =
                context.getSystemService(android.app.KeyguardManager.class);
        final android.os.PowerManager pm = context.getSystemService(android.os.PowerManager.class);
        o.put("keyguard_locked", km != null && km.isKeyguardLocked());
        o.put("interactive", pm != null && pm.isInteractive());
        return o;
    }

    private static String iso(long t) {
        return new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ", Locale.US).format(new Date(t));
    }

    private static String safe(String s) {
        return s.replaceAll("[^A-Za-z0-9._-]", "_");
    }
}
