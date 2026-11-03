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
import android.os.Build;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * IchthysOS: the run history this app keeps ({@code files/history.json}, newest first, the last
 * {@link #MAX} runs): date, label, pass/fail/info/skip, build id, and every probe's verdict, so a
 * run can be compared with the previous one ("location.current_fix: pass → fail"). Guard shows
 * the diff. The screen also keeps each run's problem cards (key, title, severity; Triage), the
 * Guard stand-in and the report path, so it can show the last result at launch and say what is
 * new or fixed since the previous run of the same kind.
 */
public final class History {
    public static final int MAX = 30;

    /** A problem card as a past run recorded it. */
    public static final class Ref {
        public final String key;
        public final String title;
        public final String severity;

        Ref(String key, String title, String severity) {
            this.key = key;
            this.title = title;
            this.severity = severity;
        }
    }

    /** One past run. */
    public static final class Entry {
        public final String label;
        public final long startedMs;
        public final String buildId;
        public final int pass;
        public final int fail;
        public final int info;
        public final int skip;
        /** probe id -> verdict key. */
        public final Map<String, String> verdicts;
        /** IchthysOS: the Guard stand-in ("" outside Guard runs). */
        public String standIn = "";
        /** IchthysOS: the report file ("" when unknown). */
        public String report = "";
        /** IchthysOS: the problem cards; null for runs recorded before cards existed. */
        public List<Ref> problems;

        Entry(String label, long startedMs, String buildId, int pass, int fail, int info,
                int skip, Map<String, String> verdicts) {
            this.label = label;
            this.startedMs = startedMs;
            this.buildId = buildId;
            this.pass = pass;
            this.fail = fail;
            this.info = info;
            this.skip = skip;
            this.verdicts = verdicts;
        }

        public String line() {
            return new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(new Date(startedMs))
                    + "  " + label + "  pass=" + pass + " fail=" + fail + " info=" + info
                    + " skip=" + skip + "  " + buildId;
        }

        /** Runs of the same kind compare: manual/headless with each other, Guard per stand-in. */
        public String kind() {
            return label.startsWith("guard-") ? "guard:" + standIn : "run";
        }

        /** Problem keys; FAILs mapped to their card for runs recorded before cards. */
        public Map<String, String> problemTitles() {
            final Map<String, String> out = new java.util.LinkedHashMap<>();
            if (problems != null) {
                for (Ref r : problems) {
                    out.put(r.key, r.title);
                }
                return out;
            }
            for (Map.Entry<String, String> e : verdicts.entrySet()) {
                if (Verdict.FAIL.key.equals(e.getValue())) {
                    final Triage.Rule rule = Triage.rule(e.getKey());
                    out.put(Triage.failKey(e.getKey()), rule == null ? e.getKey() : rule.title);
                }
            }
            return out;
        }
    }

    private History() {}

    private static File file(Context context) {
        return new File(context.getFilesDir(), "history.json");
    }

    public static List<Entry> load(Context context) {
        final List<Entry> out = new ArrayList<>();
        final File f = file(context);
        if (!f.isFile()) {
            return out;
        }
        try {
            final String text = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
            final JSONArray arr = new JSONArray(text);
            for (int i = 0; i < arr.length(); i++) {
                final JSONObject o = arr.getJSONObject(i);
                final Map<String, String> verdicts = new java.util.LinkedHashMap<>();
                final JSONObject v = o.optJSONObject("verdicts");
                if (v != null) {
                    for (java.util.Iterator<String> it = v.keys(); it.hasNext();) {
                        final String k = it.next();
                        verdicts.put(k, v.optString(k));
                    }
                }
                final Entry entry = new Entry(o.optString("label"), o.optLong("started"),
                        o.optString("build_id"), o.optInt("pass"), o.optInt("fail"),
                        o.optInt("info"), o.optInt("skip"), verdicts);
                entry.standIn = o.optString("stand_in");
                entry.report = o.optString("report");
                final JSONArray probs = o.optJSONArray("problems");
                if (probs != null) {
                    entry.problems = new ArrayList<>();
                    for (int j = 0; j < probs.length(); j++) {
                        final JSONObject p = probs.optJSONObject(j);
                        if (p != null) {
                            entry.problems.add(new Ref(p.optString("key"), p.optString("title"),
                                    p.optString("severity")));
                        }
                    }
                }
                out.add(entry);
            }
        } catch (Exception e) {
            Log.w(Runner.TAG, "history unreadable", e);
        }
        return out;
    }

    /**
     * Records {@code report} and returns the diff against the previous run: every probe whose
     * verdict changed ("id: old → new"), plus probes new or gone.
     */
    public static List<String> record(Context context, Report report, long startedMs) {
        return record(context, report, startedMs, null, null, null);
    }

    /**
     * IchthysOS: as above, also keeping the stand-in, the report path and the run's problem
     * cards (Triage) for the screen.
     */
    public static List<String> record(Context context, Report report, long startedMs,
            String standIn, File reportFile, List<Triage.Problem> problems) {
        final List<Entry> all = load(context);
        final Map<String, String> verdicts = new java.util.LinkedHashMap<>();
        for (Map.Entry<String, Result> e : report.entries().entrySet()) {
            verdicts.put(e.getKey(), e.getValue().verdict.key);
        }
        final Entry now = new Entry(report.label, startedMs, Build.ID,
                report.count(Verdict.PASS), report.count(Verdict.FAIL),
                report.count(Verdict.INFO), report.count(Verdict.SKIP), verdicts);
        now.standIn = standIn == null ? "" : standIn;
        now.report = reportFile == null ? "" : reportFile.getPath();
        // IchthysOS: compare with the previous run of the same kind (manual with manual, a
        // Guard phase with the same stand-in), not with whatever ran last.
        Entry previous = null;
        for (Entry e : all) {
            if (e.kind().equals(now.kind())) {
                previous = e;
                break;
            }
        }
        if (problems != null) {
            now.problems = new ArrayList<>();
            for (Triage.Problem p : problems) {
                now.problems.add(new Ref(p.key, p.title, p.severity.label));
            }
        }
        final List<String> diff = new ArrayList<>();
        if (previous != null) {
            for (Map.Entry<String, String> e : verdicts.entrySet()) {
                final String old = previous.verdicts.get(e.getKey());
                if (old != null && !old.equals(e.getValue())) {
                    diff.add(e.getKey() + ": " + old + " → " + e.getValue());
                }
            }
        }
        all.add(0, now);
        while (all.size() > MAX) {
            all.remove(all.size() - 1);
        }
        save(context, all);
        return diff;
    }

    /**
     * IchthysOS: replaces the problem cards of the newest run when it is {@code label} (a tap
     * probe ran after it), so the next run compares with what the screen showed.
     */
    public static void updateProblems(Context context, String label,
            List<Triage.Problem> problems) {
        final List<Entry> all = load(context);
        if (all.isEmpty() || !all.get(0).label.equals(label)) {
            return;
        }
        final Entry e = all.get(0);
        e.problems = new ArrayList<>();
        for (Triage.Problem p : problems) {
            e.problems.add(new Ref(p.key, p.title, p.severity.label));
        }
        save(context, all);
    }

    /** The newest run, or null. */
    public static Entry latest(Context context) {
        final List<Entry> all = load(context);
        return all.isEmpty() ? null : all.get(0);
    }

    /** The newest run of the same kind as {@code current} that started before it, or null. */
    public static Entry previous(Context context, Entry current) {
        if (current == null) {
            return null;
        }
        for (Entry e : load(context)) {
            if (e.startedMs < current.startedMs && e.kind().equals(current.kind())) {
                return e;
            }
        }
        return null;
    }

    private static void save(Context context, List<Entry> all) {
        try {
            final JSONArray arr = new JSONArray();
            for (Entry e : all) {
                final JSONObject o = new JSONObject();
                o.put("label", e.label);
                o.put("started", e.startedMs);
                o.put("build_id", e.buildId);
                o.put("pass", e.pass);
                o.put("fail", e.fail);
                o.put("info", e.info);
                o.put("skip", e.skip);
                o.put("verdicts", new JSONObject(e.verdicts));
                o.put("stand_in", e.standIn);
                o.put("report", e.report);
                if (e.problems != null) {
                    final JSONArray probs = new JSONArray();
                    for (Ref r : e.problems) {
                        probs.put(new JSONObject().put("key", r.key).put("title", r.title)
                                .put("severity", r.severity));
                    }
                    o.put("problems", probs);
                }
                arr.put(o);
            }
            final File f = file(context);
            final File tmp = new File(f.getPath() + ".tmp");
            try (FileOutputStream os = new FileOutputStream(tmp)) {
                os.write(arr.toString().getBytes(StandardCharsets.UTF_8));
            }
            if (!tmp.renameTo(f)) {
                Log.w(Runner.TAG, "history not renamed");
            }
        } catch (JSONException | java.io.IOException e) {
            Log.w(Runner.TAG, "history not saved", e);
        }
    }
}
