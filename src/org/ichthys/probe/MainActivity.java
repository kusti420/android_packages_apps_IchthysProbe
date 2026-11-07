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

import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PermissionInfo;
import android.content.res.ColorStateList;
import android.net.Uri;
import android.os.Bundle;
import android.os.SystemClock;
import android.provider.Settings;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.format.DateUtils;
import android.text.style.ForegroundColorSpan;
import android.util.Log;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.ichthys.probe.probes.ClipProbes;
import org.json.JSONObject;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The one screen, built as a health check: a verdict line ("Protected" / "N leaks found") with
 * the run's time and build, what changed since the previous run of the same kind, the problem
 * cards (what was promised, what was seen, since when, and the one Fix), the checks that
 * couldn't test anything (each group with its one action), the passed checks folded into one
 * line per category, then every protection in every state of the last Guard verification (the
 * matrix), the spoofed values as real / expected / seen, and the run history as a strip.
 * {@link Triage} does the sorting.
 *
 * <p>"Check everything" asks Guard (Settings) to run its verification: Guard puts this app into
 * each stand-in state and starts it headless ({@link GuardRun}); each phase lands here as a run.
 * With {@code --ez autorun true} from the shell it runs every probe that needs no tap, writes the
 * JSON report and logs one line per probe under the tag IchthysProbe, ending with a "DONE
 * label=..." line the host script waits for. Only the system (Guard) may start a Guard run and
 * only the shell, root or the system a plain autorun: any other app could otherwise make this
 * app measure and broadcast what it sees. At launch the screen shows the last run, read back.
 */
public class MainActivity extends Activity {
    private static final String TAG = Runner.TAG;

    /** Content description of the clipboard tap button, for adb / uiautomator. */
    public static final String TAP_CLIPBOARD_DESC = "probe_tap_clipboard";

    /** The matrix rows: a protection and the probe ids (exact, or prefixes ending in '.' / '_'). */
    private static final String[][] MATRIX_ROWS = {
        {"Contacts", "contacts."},
        {"Calendar", "calendar."},
        {"Call log", "calllog."},
        {"Messages", "sms."},
        {"Phone number", "phone.line1_number", "phone.subscription_number"},
        {"Location", "location.", "phone.cell_info", "wifi.connection"},
        {"Scans", "wifi.scan_results", "bt.le_scan", "bt.discovery"},
        {"Clipboard", "clip."},
        {"Sensors", "sensors."},
        {"Usage history", "apps.usage_"},
        {"Spoofed values", "spoof."},
        {"Firewall", "net.https", "net.dns_control", "guard.net_matches"},
        {"Local network", "net.lan"},
        {"Radios", "bt.advertise", "uwb.", "nfc.", "wifi.control"},
    };

    private final ExecutorService mSerial = Executors.newSingleThreadExecutor();
    /** Expanded sections and cards, kept across re-renders. */
    private final Set<String> mOpen = new HashSet<>();

    private Ui mUi;
    private ScrollView mScroll;
    private TextView mVerdict;
    private TextView mMeta;
    private TextView mCounts;
    private ProgressBar mProgress;
    private LinearLayout mDiff;
    private LinearLayout mBody;
    private Ctx mCtx;
    private Report mReport;
    private volatile boolean mRunning;
    /** IchthysOS: a Guard verification run (GuardRun): Guard's categories, a reply at the end. */
    private volatile boolean mGuardRun;
    private long mRunStartedMs;

    // What the screen shows: the last finished run (live or read back from its report).
    private Map<String, Result> mShown;
    private Map<String, String> mShownShields;
    private Map<String, String> mShownExpect;
    private boolean mShownGuard;
    private History.Entry mShownEntry;
    /** The phases of the newest Guard verification, oldest first (for the matrix). */
    private List<Column> mMatrix = new ArrayList<>();

    /** One state (a Guard stand-in) of the matrix and what every probe found in it. */
    private static final class Column {
        final String label;
        final Map<String, Result> results;

        Column(String label, Map<String, Result> results) {
            this.label = label;
            this.results = results;
        }
    }

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        Redact.init(this);
        mUi = new Ui(this);
        buildUi();
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    @Override
    protected void onDestroy() {
        if (mCtx != null) {
            mCtx.quit();
        }
        super.onDestroy();
    }

    @Override
    public boolean dispatchTouchEvent(MotionEvent ev) {
        Ctx.sLastInputUptime = SystemClock.uptimeMillis();
        return super.dispatchTouchEvent(ev);
    }

    @Override
    public boolean dispatchKeyEvent(KeyEvent ev) {
        Ctx.sLastInputUptime = SystemClock.uptimeMillis();
        return super.dispatchKeyEvent(ev);
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] results) {
        toast("Run the checks again to test with the new permissions.");
    }

    private void handleIntent(Intent intent) {
        if (intent != null && intent.getBooleanExtra("autorun", false)) {
            final boolean guard = GuardRun.isGuardRun(intent.getExtras());
            // IchthysOS: only Guard (system uid) may drive a verification, only the shell, root
            // or the system a headless run; anyone else is shown the last run and nothing more.
            if (!GuardRun.trustedLaunch(this, guard)) {
                // The package too (null when the launcher is unknown), for diagnostics.
                Log.w(TAG, "autorun ignored: launched from uid " + getLaunchedFromUid()
                        + " package " + getLaunchedFromPackage()
                        + (guard ? " (guard run)" : ""));
                toast("Only Guard or adb can start the checks headless.");
                if (mCtx == null) {
                    mGuardRun = false;
                    newCtx("manual-" + stamp(), null);
                    loadLast();
                }
                return;
            }
            if (mRunning) {
                // Guard would otherwise wait five minutes for an answer that never comes.
                Log.w(TAG, "run already in progress, refusing " + intent.getStringExtra("label"));
                if (guard) {
                    GuardRun.replyBusy(getApplicationContext(), intent.getExtras());
                }
                return;
            }
            String label = intent.getStringExtra("label");
            if (label == null || label.isEmpty()) {
                label = "autorun";
            }
            mGuardRun = guard;
            startRun(label, intent.getExtras(), true);
        } else if (mCtx == null) {
            mGuardRun = false;
            newCtx("manual-" + stamp(), intent == null ? null : intent.getExtras());
            loadLast();
        }
    }

    private void newCtx(String label, Bundle extras) {
        if (mCtx != null) {
            mCtx.quit();
        }
        mCtx = new Ctx(this, label, extras);
        mReport = new Report(label);
    }

    /** Shows the newest recorded run, read back from its report file. */
    private void loadLast() {
        final android.content.Context app = getApplicationContext();
        mSerial.execute(() -> {
            final History.Entry e = History.latest(app);
            final Report r = e == null ? null : loadReport(app, e);
            final List<Column> matrix = loadMatrix(app);
            runOnUiThread(() -> {
                if (mRunning || mShown != null) {
                    return;
                }
                mShownEntry = e;
                mMatrix = matrix;
                if (r != null) {
                    show(r, e);
                } else {
                    render();
                }
            });
        });
    }

    /** Shows one past run from the history strip. */
    private void loadEntry(History.Entry e) {
        if (mRunning) {
            return;
        }
        final android.content.Context app = getApplicationContext();
        mSerial.execute(() -> {
            final Report r = loadReport(app, e);
            runOnUiThread(() -> {
                if (mRunning) {
                    return;
                }
                mShownEntry = e;
                if (r != null) {
                    show(r, e);
                } else {
                    toast("That run's report is gone.");
                }
            });
        });
    }

    private void show(Report r, History.Entry e) {
        mShown = r.entries();
        mShownShields = r.recordedShields;
        mShownExpect = r.expectations;
        mShownGuard = e != null && e.label.startsWith("guard-");
        render();
    }

    private static Report loadReport(android.content.Context app, History.Entry e) {
        File f = e.report.isEmpty() ? null : new File(e.report);
        if (f == null || !f.isFile()) {
            // Runs recorded before the path was kept: the report's usual place.
            f = new File(new File(app.getExternalFilesDir(null), "reports"),
                    e.label.replaceAll("[^A-Za-z0-9._-]", "_") + ".json");
        }
        return Report.load(f);
    }

    /**
     * The newest Guard verification's phases, oldest first: every history entry whose label
     * shares the run id of the newest "guard-" entry ({@code guard-<run>-<phase>}).
     */
    private static List<Column> loadMatrix(android.content.Context app) {
        final List<Column> out = new ArrayList<>();
        final List<History.Entry> all = History.load(app);
        String runPrefix = null;
        for (History.Entry e : all) {
            if (e.label.startsWith("guard-")) {
                final int dash = e.label.lastIndexOf('-');
                runPrefix = dash > 6 ? e.label.substring(0, dash + 1) : e.label;
                break;
            }
        }
        if (runPrefix == null) {
            return out;
        }
        final List<History.Entry> phases = new ArrayList<>();
        for (History.Entry e : all) {
            if (e.label.startsWith(runPrefix)) {
                phases.add(0, e); // history is newest first; the matrix wants oldest first
            }
        }
        for (History.Entry e : phases) {
            final Report r = loadReport(app, e);
            if (r != null) {
                out.add(new Column(e.standIn.isEmpty() ? e.label : e.standIn, r.entries()));
            }
        }
        return out;
    }

    private void startRun(String label, Bundle extras, boolean autorun) {
        if (mRunning) {
            Log.w(TAG, "run already in progress, ignoring start of " + label);
            return;
        }
        mRunning = true;
        newCtx(label, extras);
        mCtx.autorun = autorun;
        final Ctx c = mCtx;
        final Report report = mReport;
        final boolean guard = mGuardRun;
        mRunStartedMs = System.currentTimeMillis();
        final String standIn = c.option(GuardRun.EXTRA_STAND_IN);
        final List<Probe> probes = new ArrayList<>();
        for (Probe p : Registry.all()) {
            // IchthysOS: a Guard run keeps to Guard's rule categories.
            if (!guard || GuardRun.includes(p)) {
                probes.add(p);
            }
        }
        showRunning(guard, standIn, null, 0, probes.size());
        Log.i(TAG, "START label=" + label + " autorun=" + autorun + " guard=" + guard
                + " probes=" + Registry.all().size());
        mSerial.execute(() -> {
            int done = 0;
            for (Probe p : probes) {
                final int index = done++;
                runOnUiThread(() -> showRunning(guard, standIn, p.id, index, probes.size()));
                if (p.isTapProbe()) {
                    final Result r = Result.skipped("needs a real tap on its button");
                    r.verdict = Verdict.SKIP;
                    r.verdictWhy = "not run";
                    r.granted = p.grantedState(c);
                    report.add(p, r);
                    continue;
                }
                report.add(p, Runner.run(p, c));
            }
            final File f = report.write(c);
            final String line = "DONE label=" + label + " probes=" + report.size()
                    + " pass=" + report.count(Verdict.PASS) + " fail=" + report.count(Verdict.FAIL)
                    + " info=" + report.count(Verdict.INFO) + " skip="
                    + report.count(Verdict.SKIP) + " report=" + (f == null ? "none" : f);
            Log.i(TAG, line);
            // IchthysOS: the run history (date, verdicts, build, problem cards) and the diff
            // against the last run of the same kind.
            final Map<String, String> shields = c.shields.describe();
            List<Triage.Problem> problems = null;
            try {
                problems = Triage.analyse(report.entries(), shields, guard).all();
            } catch (RuntimeException e) {
                // Never let the screen's sorting cost Guard its reply.
                Log.w(TAG, "triage failed", e);
            }
            final List<String> diff = History.record(getApplicationContext(), report,
                    mRunStartedMs, standIn, f, problems);
            if (guard) {
                GuardRun.reply(getApplicationContext(), c, report, f, diff);
            }
            final History.Entry entry = History.latest(getApplicationContext());
            final List<Column> matrix = loadMatrix(getApplicationContext());
            mRunning = false;
            runOnUiThread(() -> {
                mShownEntry = entry;
                mMatrix = matrix;
                show(report, entry);
                mScroll.scrollTo(0, 0);
            });
        });
    }

    /** Runs one tap probe from its button: called from the click, so the tap backs it. */
    private void runTapProbe(String id) {
        final Probe p = Registry.byId(id);
        if (p == null || mCtx == null) {
            return;
        }
        if (mRunning) {
            // Queued behind the run, the read would come long after the tap's 2 s grant.
            toast("Wait for the run to finish, then tap.");
            Log.i(TAG, "TAP_IGNORED label=" + mCtx.label + " probe=" + id + " (run in progress)");
            return;
        }
        final Ctx c = mCtx;
        final Report report = mReport;
        mSerial.execute(() -> {
            c.fromTap = true;
            final Result r;
            try {
                r = Runner.run(p, c);
            } finally {
                c.fromTap = false;
            }
            report.add(p, r);
            final File f = report.write(c);
            Log.i(TAG, "TAP_DONE label=" + c.label + " probe=" + p.id + " verdict="
                    + r.verdict.key + " report=" + (f == null ? "none" : f));
            final Map<String, String> shields = c.shields.describe();
            runOnUiThread(() -> {
                if (mShown == null) {
                    mShown = new LinkedHashMap<>();
                }
                mShown.put(p.id, r);
                if (mShownShields == null) {
                    mShownShields = shields;
                }
                if (mShownEntry != null && mShownEntry.label.equals(c.label)) {
                    final List<Triage.Problem> now =
                            Triage.analyse(mShown, mShownShields, mShownGuard).all();
                    final android.content.Context app = getApplicationContext();
                    mSerial.execute(() -> History.updateProblems(app, c.label, now));
                }
                render();
                toast(r.verdict == Verdict.PASS ? "Tap test passed"
                        : r.verdict == Verdict.FAIL ? "Tap test failed: " + r.verdictWhy
                        : "Tap test: " + r.outcome.key);
            });
        });
    }

    // ---- UI ----------------------------------------------------------------------------------

    private void buildUi() {
        final Ui u = mUi;
        getWindow().getDecorView().setBackgroundColor(u.ink);
        getWindow().setStatusBarColor(u.ink);
        getWindow().setNavigationBarColor(u.ink);

        final LinearLayout root = u.vbox();
        root.setPadding(u.dp(20), u.dp(20), u.dp(20), u.dp(32));

        // IchthysOS: a probe in /system is exempt from the shields; every shield result is wrong
        // then. Persistent, red, before anything else.
        if (GuardRun.inSystem(this)) {
            final LinearLayout warn = u.card();
            warn.setBackground(u.shape(Ui.alpha(u.danger, 0x26), u.danger, 20));
            warn.addView(u.title("Installed in /system", 15, u.danger));
            warn.addView(u.text("System apps are exempt from the shields, so shield results "
                    + "are wrong. Install the APK as a user app (adb install).", 13, u.text));
            root.addView(warn, u.wide(0));
        }

        root.addView(u.title("IchthysProbe", 13, u.muted), u.wide(4));
        mVerdict = u.title("", 30, u.text);
        root.addView(mVerdict, u.wide(6));
        mMeta = u.text("", 13, u.muted);
        root.addView(mMeta, u.wide(4));
        mCounts = u.text("", 13, u.muted);
        root.addView(mCounts, u.wide(2));
        mProgress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        mProgress.setProgressTintList(ColorStateList.valueOf(u.accent));
        mProgress.setProgressBackgroundTintList(ColorStateList.valueOf(u.hairline));
        mProgress.setVisibility(View.GONE);
        root.addView(mProgress, u.wide(10));

        mDiff = u.vbox();
        root.addView(mDiff, u.wide(16));

        // The buttons sit at a fixed place at the top: easy for adb.
        final LinearLayout actions = u.hbox();
        actions.addView(u.button("Check everything", "probe_check_everything", true,
                v -> checkEverything()), u.weight(0));
        actions.addView(u.button("Run checks", "probe_run_all", false, v -> {
            mGuardRun = false;
            startRun("manual-" + stamp(), null, false);
        }), u.weight(8));
        actions.addView(tapButton("Tap test", TAP_CLIPBOARD_DESC), u.wrap(8));
        root.addView(actions, u.wide(16));
        root.addView(u.text("Check everything: Guard runs this app as a blocked app, a "
                + "messenger, a maps app (and with full access when you gave it that) and "
                + "judges every protection in each state. Run checks: this state only; shield "
                + "promises are then not judged, because apps can't see the shield lists.",
                12, u.muted), u.wide(6));

        mBody = u.vbox();
        root.addView(mBody, u.wide(4));

        mScroll = new ScrollView(this);
        mScroll.setFitsSystemWindows(true);
        mScroll.setBackgroundColor(u.ink);
        mScroll.addView(root);
        setContentView(mScroll);

        mVerdict.setText("…");
    }

    /** Asks Guard for "Verify my protection" (every stand-in), see {@link GuardRun}. */
    private void checkEverything() {
        if (mRunning) {
            toast("Wait for the run to finish.");
            return;
        }
        if (GuardRun.inSystem(this)) {
            toast("Install IchthysProbe as a user app first (adb install).");
            return;
        }
        try {
            GuardRun.requestVerification(this);
            toast("Guard is running the checks. This screen fills in as each state ends.");
        } catch (RuntimeException e) {
            toast("Couldn't reach Guard: " + Redact.exception(e));
        }
    }

    /** The clipboard tap probe's button: the touch arms the probe, the click runs it. */
    private TextView tapButton(String text, String desc) {
        final TextView b = mUi.button(text, desc, false, v -> runTapProbe("clip.tap_read"));
        b.setOnTouchListener((v, ev) -> {
            if (ev.getActionMasked() == MotionEvent.ACTION_DOWN && mCtx != null) {
                ClipProbes.prepareTap(mCtx);
            }
            return false;
        });
        return b;
    }

    private void showRunning(boolean guard, String standIn, String id, int index, int total) {
        mVerdict.setText(guard ? "Guard verification…" : "Checking…");
        mVerdict.setTextColor(mUi.text);
        mMeta.setText((guard ? "As " + (standIn == null ? "?" : standIn) + " · " : "")
                + (id == null ? "starting" : id) + " · " + index + " of " + total);
        mCounts.setText("");
        mProgress.setVisibility(View.VISIBLE);
        mProgress.setMax(Math.max(total, 1));
        mProgress.setProgress(index);
        mDiff.removeAllViews();
        mBody.setAlpha(0.4f);
    }

    /** Rebuilds everything below the buttons from {@link #mShown}. */
    private void render() {
        final Ui u = mUi;
        mProgress.setVisibility(View.GONE);
        mBody.setAlpha(1f);
        mBody.removeAllViews();
        mDiff.removeAllViews();
        final History.Entry entry = mShownEntry;

        if (mShown == null || mShown.isEmpty()) {
            mVerdict.setText("Not checked yet");
            mVerdict.setTextColor(u.text);
            mMeta.setText(entry == null ? "Tap Check everything to see what an ordinary app gets."
                    : "Last run " + when(entry.startedMs) + " · its report is gone, run again");
            mCounts.setText("");
            addMatrix();
            addFooter();
            return;
        }

        final Triage.Analysis a = Triage.analyse(mShown, mShownShields, mShownGuard);

        // ---- verdict line ----
        final int n = a.problems.size();
        if (n > 0) {
            mVerdict.setText(n + (n == 1 ? " leak found" : " leaks found"));
            mVerdict.setTextColor(u.severity(a.worst()));
        } else if (a.passed == 0) {
            mVerdict.setText("Nothing judged yet");
            mVerdict.setTextColor(u.text);
        } else {
            mVerdict.setText("Protected");
            mVerdict.setTextColor(u.ok);
        }
        final StringBuilder meta = new StringBuilder();
        if (entry != null) {
            meta.append("Checked ").append(when(entry.startedMs)).append(" · build ")
                    .append(entry.buildId);
            if (entry.label.startsWith("guard-")) {
                meta.append(" · as ").append(entry.standIn.isEmpty() ? "?" : entry.standIn);
            } else {
                meta.append(" · this state only");
            }
        } else {
            meta.append("Tap test only · run the checks for the rest");
        }
        mMeta.setText(meta);
        final StringBuilder counts = new StringBuilder();
        counts.append(a.passed).append(" passed · ").append(a.notTestedCount())
                .append(" not tested · ").append(a.checks).append(" checks");
        if (!a.gaps.isEmpty()) {
            counts.append("\n").append(a.gaps.size()).append(a.gaps.size() == 1 ? " gap" : " gaps")
                    .append(" IchthysOS doesn't cover yet");
        }
        mCounts.setText(counts);

        // ---- what changed since the previous run of the same kind ----
        final Set<String> fresh = new HashSet<>();
        final History.Entry prev = History.previous(getApplicationContext(), entry);
        if (entry != null) {
            addDiff(a, prev, fresh);
        }

        // ---- problems ----
        if (!a.problems.isEmpty()) {
            mBody.addView(u.section("Problems"));
            int i = 0;
            for (Triage.Problem p : a.problems) {
                mBody.addView(problemCard(p, ++i, a.problems.size(), fresh.contains(p.key)),
                        u.wide(0));
                spacer(10);
            }
        }
        if (!a.gaps.isEmpty()) {
            mBody.addView(u.section("Not covered yet"));
            int i = 0;
            for (Triage.Problem p : a.gaps) {
                mBody.addView(problemCard(p, ++i, a.gaps.size(), fresh.contains(p.key)),
                        u.wide(0));
                spacer(10);
            }
        }

        // ---- not tested ----
        if (!a.notTested.isEmpty()) {
            mBody.addView(u.section("Not tested"));
            final LinearLayout box = u.card();
            box.setPadding(0, u.dp(4), 0, u.dp(4));
            boolean first = true;
            for (Triage.Group g : a.notTested.values()) {
                if (!first) {
                    box.addView(divider());
                }
                first = false;
                box.addView(notTestedRow(g));
            }
            mBody.addView(box, u.wide(0));
        }

        // ---- passed, one line per category; categories with nothing judged fold into one ----
        mBody.addView(u.section("Passed"));
        final LinearLayout box = u.card();
        box.setPadding(0, u.dp(4), 0, u.dp(4));
        final LinearLayout rest = u.vbox();
        int restChecks = 0;
        int restCategories = 0;
        boolean first = true;
        for (Map.Entry<String, Triage.Tally> e : a.categories.entrySet()) {
            final Triage.Tally t = e.getValue();
            if (t.pass + t.fail == 0) {
                rest.addView(divider());
                rest.addView(categoryRow(e.getKey(), t));
                restChecks += t.ids.size();
                restCategories++;
                continue;
            }
            if (!first) {
                box.addView(divider());
            }
            first = false;
            box.addView(categoryRow(e.getKey(), t));
        }
        if (restCategories > 0) {
            final LinearLayout other = u.vbox();
            final LinearLayout head = u.hbox();
            head.setPadding(u.dp(16), u.dp(12), u.dp(16), u.dp(12));
            head.addView(u.dot(u.hairline));
            head.addView(u.title("Observed only", 15, u.muted), u.weight(0));
            head.addView(u.text(restChecks + " checks · " + restCategories + " categories", 13,
                    u.muted), u.wrap(8));
            other.addView(head);
            if (!first) {
                box.addView(divider());
            }
            expandable(other, "cat-rest", rest);
            box.addView(other);
        }
        mBody.addView(box, u.wide(0));

        addMatrix();
        addSpoofedValues();
        addFooter();
    }

    private void spacer(int dp) {
        final View v = new View(this);
        mBody.addView(v, new LinearLayout.LayoutParams(1, mUi.dp(dp)));
    }

    private View divider() {
        final View v = new View(this);
        v.setBackgroundColor(mUi.hairline);
        final LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 1);
        lp.leftMargin = mUi.dp(16);
        lp.rightMargin = mUi.dp(16);
        v.setLayoutParams(lp);
        return v;
    }

    /** "New since last run: 1 problem · Fixed: 2", tap for the titles. */
    private void addDiff(Triage.Analysis a, History.Entry prev, Set<String> fresh) {
        final Ui u = mUi;
        final LinearLayout box = u.vbox();
        box.setBackground(u.shape(u.raised, 0, 16));
        box.setPadding(u.dp(14), u.dp(10), u.dp(14), u.dp(10));
        if (prev == null) {
            box.addView(u.text("First run of its kind: nothing to compare yet", 13, u.muted));
            mDiff.addView(box, u.wide(0));
            return;
        }
        final Map<String, String> now = new LinkedHashMap<>();
        for (Triage.Problem p : a.all()) {
            now.put(p.key, p.title);
        }
        final Map<String, String> before = prev.problemTitles();
        final List<String> added = new ArrayList<>();
        for (Map.Entry<String, String> e : now.entrySet()) {
            if (!before.containsKey(e.getKey())) {
                added.add(e.getValue());
                fresh.add(e.getKey());
            }
        }
        final List<String> fixed = new ArrayList<>();
        for (Map.Entry<String, String> e : before.entrySet()) {
            if (!now.containsKey(e.getKey()) && Triage.evaluated(e.getKey(), mShown)) {
                fixed.add(e.getValue());
            }
        }
        if (added.isEmpty() && fixed.isEmpty()) {
            box.addView(u.text("No change since " + when(prev.startedMs) + " · build "
                    + prev.buildId, 13, u.muted));
            mDiff.addView(box, u.wide(0));
            return;
        }
        final SpannableStringBuilder sb = new SpannableStringBuilder();
        if (!added.isEmpty()) {
            sb.append("New since last run: " + added.size()
                    + (added.size() == 1 ? " problem" : " problems"),
                    new ForegroundColorSpan(u.danger), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
        if (!fixed.isEmpty()) {
            sb.append(added.isEmpty() ? "" : "  ·  ");
            sb.append("Fixed: " + fixed.size(), new ForegroundColorSpan(u.ok),
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
        box.addView(u.title(sb, 14, u.muted));
        final LinearLayout list = u.vbox();
        for (String t : added) {
            list.addView(u.text("+  " + t, 13, u.text), u.wide(6));
        }
        for (String t : fixed) {
            list.addView(u.text("✓  " + t, 13, u.muted), u.wide(6));
        }
        list.addView(u.text("Compared with " + when(prev.startedMs) + " · build "
                + prev.buildId, 12, u.muted), u.wide(8));
        expandable(box, "diff", list);
        mDiff.addView(box, u.wide(0));
    }

    /** Toggles {@code content} under {@code parent} on a tap, remembering it as {@code key}. */
    private void expandable(LinearLayout parent, String key, View content) {
        content.setVisibility(mOpen.contains(key) ? View.VISIBLE : View.GONE);
        parent.addView(content);
        mUi.tappable(parent, v -> {
            final boolean show = content.getVisibility() != View.VISIBLE;
            content.setVisibility(show ? View.VISIBLE : View.GONE);
            if (show) {
                mOpen.add(key);
            } else {
                mOpen.remove(key);
            }
        });
    }

    private View problemCard(Triage.Problem p, int index, int total, boolean isNew) {
        final Ui u = mUi;
        final LinearLayout card = u.card();
        final boolean gap = p.kind == Triage.Kind.GAP;

        final LinearLayout chips = u.hbox();
        chips.addView(u.chip(p.severity.label, u.severity(p.severity)));
        chips.addView(u.chip(p.kind.label, u.muted), u.wrap(6));
        if (isNew) {
            chips.addView(u.chip("New", u.accent), u.wrap(6));
        }
        chips.addView(u.text(index + " of " + total, 12, u.muted), u.weight(8));
        card.addView(chips);

        card.addView(u.title(p.title, 17, u.text), u.wide(10));
        card.addView(u.text(p.why, 14, u.muted), u.wide(4));

        // What was promised, what was seen, in which state, and since when: the facts a reader
        // needs before deciding whether to act.
        final LinearLayout facts = u.vbox();
        facts.setPadding(0, u.dp(8), 0, 0);
        String promised = null;
        String seen = null;
        String state = null;
        for (String id : p.ids) {
            final Probe probe = Registry.byId(id);
            final Result r = mShown.get(id);
            if (probe == null || r == null) {
                continue;
            }
            final Expect x = probe.expectation();
            if (promised == null && x != null) {
                promised = x.promise;
            }
            if (seen == null && (r.verdict == Verdict.FAIL || r.outcome == Outcome.VISIBLE)) {
                seen = r.verdict == Verdict.FAIL && !r.verdictWhy.isEmpty()
                        ? r.verdictWhy : r.detailLine();
                state = (probe.permissions.length == 0 ? "no permission needed"
                        : "permission " + r.granted)
                        + (p.kind == Triage.Kind.SHIELD_OFF ? " · shield switched off"
                        : mShownGuard ? " · as Guard set it up" : " · shield state unknown");
            }
        }
        if (promised != null) {
            facts.addView(factRow("promised", promised));
        }
        if (seen != null) {
            facts.addView(factRow("seen", seen));
        }
        if (state != null) {
            facts.addView(factRow("state", state));
        }
        final String since = firstSeen(p.key);
        if (since != null) {
            facts.addView(factRow("since", since));
        }
        card.addView(facts);

        final TextView rule = u.mono(p.ruleLine);
        rule.setTextIsSelectable(false);
        card.addView(rule, u.wide(8));
        if (!p.ids.isEmpty()) {
            final StringBuilder sb = new StringBuilder();
            sb.append(p.ids.size()).append(p.ids.size() == 1 ? " check: " : " checks: ");
            for (int i = 0; i < Math.min(3, p.ids.size()); i++) {
                sb.append(i == 0 ? "" : ", ").append(p.ids.get(i));
            }
            if (p.ids.size() > 3) {
                sb.append(" +").append(p.ids.size() - 3);
            }
            card.addView(u.text(sb, 12, u.muted), u.wide(2));
        }

        final String detailText = details(p);
        final TextView details = u.mono(detailText);
        details.setVisibility(mOpen.contains("card:" + p.key) ? View.VISIBLE : View.GONE);

        final LinearLayout buttons = u.hbox();
        if (p.fix.opensScreen()) {
            buttons.addView(u.button(p.fix.label, "probe_fix_" + p.key, !gap, v -> {
                final String hint = p.fix.open(this);
                if (hint != null) {
                    toast(hint);
                }
            }), u.weight(0));
            buttons.addView(u.button("Share", null, false, v -> share(p, detailText)),
                    u.wrap(8));
        } else {
            buttons.addView(u.button("Share details", "probe_share_" + p.key, !gap,
                    v -> share(p, detailText)), u.weight(0));
        }
        buttons.addView(u.button("Details", "probe_details_" + p.key, false, v -> {
            final boolean show = details.getVisibility() != View.VISIBLE;
            details.setVisibility(show ? View.VISIBLE : View.GONE);
            if (show) {
                mOpen.add("card:" + p.key);
            } else {
                mOpen.remove("card:" + p.key);
            }
        }), u.wrap(8));
        card.addView(buttons, u.wide(14));
        card.addView(u.text(p.fix.opensScreen() ? "Set in " + p.fix.path
                : gap ? "Needs a new shield in the ROM" : "Needs a fix in the ROM source",
                12, u.muted), u.wide(6));
        card.addView(details, u.wide(10));
        return card;
    }

    private View factRow(String key, String value) {
        final Ui u = mUi;
        final LinearLayout row = u.hbox();
        row.setGravity(Gravity.TOP);
        final TextView k = u.mono(key);
        k.setTextColor(u.muted);
        k.setMinWidth(u.dp(72));
        row.addView(k);
        final TextView v = u.text(value, 13, u.text);
        row.addView(v, u.weight(8));
        return row;
    }

    /**
     * "since today 19:52 (passed on build 1102j)": the oldest run in the unbroken streak of runs
     * of the shown run's kind that carried this problem, and the run before the streak.
     */
    private String firstSeen(String key) {
        final History.Entry shown = mShownEntry;
        if (shown == null) {
            return null;
        }
        History.Entry oldest = null;
        History.Entry before = null;
        for (History.Entry e : History.load(getApplicationContext())) {
            if (e.startedMs > shown.startedMs || !e.kind().equals(shown.kind())) {
                continue;
            }
            if (e.problemTitles().containsKey(key)) {
                oldest = e;
            } else if (oldest != null) {
                before = e;
                break;
            } else {
                break;
            }
        }
        if (oldest == null || oldest.startedMs == shown.startedMs && before == null) {
            return oldest == null ? null : "this run (first time)";
        }
        return when(oldest.startedMs) + " · build " + oldest.buildId
                + (before == null ? "" : " (passed on build " + before.buildId + ")");
    }

    /** The raw output behind a card: ids, outcomes, why, detail, promise and source line. */
    private String details(Triage.Problem p) {
        final StringBuilder sb = new StringBuilder();
        if (p.kind == Triage.Kind.SHIELD_OFF && mShownShields != null) {
            final String name = p.key.substring(p.key.indexOf(':') + 1);
            sb.append("shield ").append(name).append(": ").append(mShownShields.get(name))
                    .append('\n');
        }
        for (String id : p.ids) {
            final Probe probe = Registry.byId(id);
            final Result r = mShown.get(id);
            if (probe == null || r == null) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append('\n');
            }
            sb.append(probeDetails(probe, r));
        }
        return sb.toString().trim();
    }

    private static String probeDetails(Probe p, Result r) {
        final StringBuilder sb = new StringBuilder();
        sb.append(p.id).append("\n  outcome ").append(r.outcome.key).append(" · verdict ")
                .append(r.verdict.key);
        if (p.permissions.length > 0) {
            sb.append(" · permission ").append(r.granted);
        }
        if (!r.verdictWhy.isEmpty()) {
            sb.append("\n  why: ").append(r.verdictWhy);
        }
        if (!r.detail.isEmpty()) {
            sb.append("\n  found: ").append(r.detailLine());
        }
        final Expect x = p.expectation();
        if (x != null) {
            sb.append("\n  promise: ").append(x.promise);
            if (!x.expectedText().isEmpty()) {
                sb.append(" (").append(x.expectedText()).append(')');
            }
            sb.append("\n  source: ").append(x.source);
        } else {
            sb.append("\n  reveals: ").append(p.reveals);
        }
        return sb.append('\n').toString();
    }

    private void share(Triage.Problem p, String detailText) {
        final String label = mShownEntry == null ? "" : mShownEntry.label + " · build "
                + mShownEntry.buildId + "\n";
        final String text = p.title + "\n" + p.severity.label + " · " + p.kind.label + "\n"
                + p.ruleLine + "\n" + label + "\n" + detailText;
        final Intent send = new Intent(Intent.ACTION_SEND).setType("text/plain")
                .putExtra(Intent.EXTRA_SUBJECT, "IchthysProbe: " + p.title)
                .putExtra(Intent.EXTRA_TEXT, text);
        open(Intent.createChooser(send, "Share details"));
    }

    private View notTestedRow(Triage.Group g) {
        final Ui u = mUi;
        final LinearLayout row = u.vbox();
        row.setPadding(u.dp(16), u.dp(12), u.dp(16), u.dp(12));
        final LinearLayout top = u.hbox();
        final LinearLayout words = u.vbox();
        words.addView(u.title(g.reason.label + " · " + g.ids.size(), 15, u.text));
        final StringBuilder subjects = new StringBuilder();
        int i = 0;
        for (String s : g.subjects) {
            if (i++ == 4) {
                subjects.append(", …");
                break;
            }
            subjects.append(i == 1 ? "" : ", ").append(s);
        }
        words.addView(u.text(subjects, 13, u.muted), u.wide(2));
        top.addView(words, u.weight(0));
        final View action = groupAction(g);
        if (action != null) {
            top.addView(action, u.wrap(12));
        }
        row.addView(top);
        if (g.reason == Triage.Reason.PERMISSION) {
            row.addView(u.text("One tap in Guard: IchthysProbe › Full access (asks twice) "
                    + "grants every permission at once. Grant asks the stock dialogs one by one.",
                    12, u.muted), u.wide(6));
        } else if (g.reason == Triage.Reason.GUARD_ONLY) {
            row.addView(u.text("Apps can't see the shield lists, so shields are judged only "
                    + "when Guard runs the checks (Check everything).", 12, u.muted), u.wide(6));
        }

        final StringBuilder sb = new StringBuilder();
        for (String id : g.ids) {
            final Result r = mShown.get(id);
            String why = r == null ? "" : r.verdictWhy;
            if (r != null && (why.isEmpty() || why.equals("not run"))) {
                why = String.valueOf(r.detail.get("why"));
            }
            sb.append(id).append("  ").append(why.replaceFirst("^n/a: ", "")).append('\n');
        }
        final TextView list = u.mono(sb.toString().trim());
        final LinearLayout.LayoutParams lp = u.wide(8);
        list.setLayoutParams(lp);
        expandable(row, "nt:" + g.reason.name(), list);
        return row;
    }

    private View groupAction(Triage.Group g) {
        switch (g.reason.fix) {
            case GRANT: {
                final LinearLayout two = mUi.vbox();
                two.addView(mUi.button("Full access", "probe_full_access", true,
                        v -> openGuardFullAccess()));
                two.addView(mUi.button("Grant", "probe_grant_missing", false,
                        v -> requestAllPermissions()), mUi.wide(6));
                return two;
            }
            case TAP:
                return tapButton("Run tap test", "probe_tap_clip.tap_read");
            case VERIFY:
                return mUi.button("Check everything", "probe_nt_" + g.reason.name(), true,
                        v -> checkEverything());
            case NONE:
                return null;
            default:
                return mUi.button(g.reason.fix == Fix.USAGE_ACCESS ? "Open" : "Guard",
                        "probe_nt_" + g.reason.name(), false, v -> {
                            final String hint = g.reason.fix.open(this);
                            if (hint != null) {
                                toast(hint);
                            }
                        });
        }
    }

    /** Guard isn't exported: App info › Guard is as close as a user app can get. */
    private void openGuardFullAccess() {
        open(new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.fromParts("package", getPackageName(), null)));
        toast("Tap Guard, then the Full access preset (it asks twice).");
    }

    private View categoryRow(String name, Triage.Tally t) {
        final Ui u = mUi;
        final LinearLayout row = u.vbox();
        row.setPadding(u.dp(16), u.dp(12), u.dp(16), u.dp(12));
        final LinearLayout top = u.hbox();
        top.addView(u.dot(t.fail > 0 ? u.danger : t.pass > 0 ? u.ok : u.hairline));
        top.addView(u.title(name, 15, u.text), u.weight(0));
        final StringBuilder sb = new StringBuilder();
        if (t.pass + t.fail == 0) {
            sb.append(t.ids.size()).append(t.ids.size() == 1 ? " check" : " checks");
        } else {
            sb.append(t.pass).append(" passed");
            if (t.fail > 0) {
                sb.append(" · ").append(t.fail).append(" failed");
            }
            if (t.info + t.skip > 0) {
                sb.append(" · ").append(t.info + t.skip).append(" other");
            }
        }
        top.addView(u.text(sb, 13, u.muted), u.wrap(8));
        row.addView(top);

        final String key = "cat:" + name;
        final LinearLayout list = u.vbox();
        if (mOpen.contains(key)) {
            fillCategory(list, t);
        }
        list.setVisibility(mOpen.contains(key) ? View.VISIBLE : View.GONE);
        row.addView(list, u.wide(6));
        u.tappable(row, v -> {
            final boolean show = list.getVisibility() != View.VISIBLE;
            if (show && list.getChildCount() == 0) {
                fillCategory(list, t);
            }
            list.setVisibility(show ? View.VISIBLE : View.GONE);
            if (show) {
                mOpen.add(key);
            } else {
                mOpen.remove(key);
            }
        });
        return row;
    }

    /** One line per check of a category; a tap shows its raw output. */
    private void fillCategory(LinearLayout list, Triage.Tally t) {
        final Ui u = mUi;
        for (String id : t.ids) {
            final Probe p = Registry.byId(id);
            final Result r = mShown.get(id);
            if (p == null || r == null) {
                continue;
            }
            final LinearLayout item = u.vbox();
            item.setPadding(u.dp(4), u.dp(6), 0, u.dp(6));
            final LinearLayout line = u.hbox();
            line.addView(u.dot(u.verdict(r.verdict)));
            final TextView name = u.text(id, 13, u.text);
            name.setSingleLine(true);
            name.setEllipsize(android.text.TextUtils.TruncateAt.MIDDLE);
            line.addView(name, u.weight(0));
            line.addView(u.text(r.outcome.key, 12, u.muted), u.wrap(8));
            item.addView(line);
            final TextView raw = u.mono(probeDetails(p, r).trim());
            raw.setVisibility(View.GONE);
            item.addView(raw, u.wide(4));
            u.tappable(item, v -> raw.setVisibility(
                    raw.getVisibility() == View.VISIBLE ? View.GONE : View.VISIBLE));
            list.addView(item);
        }
    }

    // ---- the matrix: every protection in every state of the last Guard verification --------

    private static boolean rowMatches(String[] row, String id) {
        for (int i = 1; i < row.length; i++) {
            final String m = row[i];
            final char last = m.charAt(m.length() - 1);
            if (last == '.' || last == '_' ? id.startsWith(m) : id.equals(m)) {
                return true;
            }
        }
        return false;
    }

    /** "✓" when every judged check of the row passed, "✗" when one failed, "○" when none judged. */
    private static String cell(String[] row, Map<String, Result> results, List<String> failed) {
        int pass = 0;
        int fail = 0;
        for (Map.Entry<String, Result> e : results.entrySet()) {
            if (!rowMatches(row, e.getKey())) {
                continue;
            }
            if (e.getValue().verdict == Verdict.PASS) {
                pass++;
            } else if (e.getValue().verdict == Verdict.FAIL) {
                fail++;
                failed.add(e.getKey());
            }
        }
        return fail > 0 ? "✗" : pass > 0 ? "✓" : "○";
    }

    private void addMatrix() {
        final Ui u = mUi;
        if (mMatrix.isEmpty()) {
            return;
        }
        mBody.addView(u.section("Every protection, every state"));
        final LinearLayout box = u.card();
        box.setPadding(u.dp(12), u.dp(8), u.dp(12), u.dp(10));
        box.addView(u.text("From the last Guard verification. ✓ as promised · ✗ leak · ○ not "
                + "judged in that state. A ✗ under Full access means real data was withheld "
                + "from an app that is allowed it.", 12, u.muted));

        // Header: the states.
        final LinearLayout head = u.hbox();
        head.addView(u.text("", 12, u.muted), u.weight(0));
        for (Column col : mMatrix) {
            final TextView t = u.mono(shortState(col.label));
            t.setGravity(Gravity.CENTER);
            t.setMinWidth(u.dp(56));
            head.addView(t, u.wrap(4));
        }
        head.setPadding(0, u.dp(8), 0, u.dp(4));
        box.addView(head);
        box.addView(divider());

        for (String[] row : MATRIX_ROWS) {
            boolean any = false;
            for (Column col : mMatrix) {
                for (String id : col.results.keySet()) {
                    if (rowMatches(row, id)) {
                        any = true;
                        break;
                    }
                }
            }
            if (!any) {
                continue;
            }
            final LinearLayout line = u.hbox();
            line.setPadding(0, u.dp(8), 0, u.dp(8));
            line.addView(u.text(row[0], 14, u.text), u.weight(0));
            final StringBuilder why = new StringBuilder();
            for (Column col : mMatrix) {
                final List<String> failed = new ArrayList<>();
                final String c = cell(row, col.results, failed);
                final TextView t = u.mono(c);
                t.setGravity(Gravity.CENTER);
                t.setMinWidth(u.dp(56));
                t.setTextColor("✗".equals(c) ? u.danger : "✓".equals(c) ? u.ok : u.muted);
                line.addView(t, u.wrap(4));
                if (!failed.isEmpty()) {
                    why.append(col.label).append(": ");
                    for (String id : failed) {
                        final Result r = col.results.get(id);
                        why.append(id).append(" (").append(r == null ? "" : r.verdictWhy)
                                .append(")\n");
                    }
                }
            }
            final LinearLayout item = u.vbox();
            item.addView(line);
            if (why.length() > 0) {
                final TextView detail = u.mono(why.toString().trim());
                expandable(item, "mx:" + row[0], detail);
            }
            box.addView(item);
            box.addView(divider());
        }
        mBody.addView(box, u.wide(0));
    }

    private static String shortState(String label) {
        switch (label) {
            case "Untrusted": return "Blocked";
            case "Messenger": return "Msgr";
            case "Full access": return "Full";
            default: return label.length() > 7 ? label.substring(0, 7) : label;
        }
    }

    // ---- spoofed values: real / expected / seen ------------------------------------------------

    private String detail(String probeId, String key) {
        final Result r = mShown == null ? null : mShown.get(probeId);
        if (r == null) {
            return null;
        }
        final String v = r.detail.get(key);
        return v == null || v.equals("null") ? null : v;
    }

    private void addSpoofedValues() {
        final Ui u = mUi;
        if (mShown == null || mShown.get("spoof.telephony_country") == null) {
            return;
        }
        JSONObject profile = null;
        boolean spoofed = false;
        if (mShownExpect != null) {
            spoofed = "yes".equals(mShownExpect.get("expect_spoofed"));
            final String json = mShownExpect.get("expect_profile");
            if (spoofed && json != null && !json.isEmpty()) {
                try {
                    profile = new JSONObject(json);
                } catch (org.json.JSONException e) {
                    profile = null;
                }
            }
        }
        mBody.addView(u.section("Spoofed values"));
        final LinearLayout box = u.card();
        box.setPadding(u.dp(12), u.dp(8), u.dp(12), u.dp(10));
        box.addView(u.text(mShownExpect == null || mShownExpect.isEmpty()
                ? "Real is what the phone reports to the shell; Seen is what this app got. "
                        + "Expected needs a Guard run (Check everything)."
                : spoofed ? "Guard set this app to get the fake place: Seen must equal Expected."
                : "Guard set this app to see the real values: Seen must equal Real.",
                12, u.muted));
        final LinearLayout head = u.hbox();
        head.setPadding(0, u.dp(8), 0, u.dp(4));
        head.addView(u.text("", 12, u.muted), u.weight(0));
        for (String h : new String[] {"Real", "Expected", "Seen"}) {
            final TextView t = u.mono(h);
            t.setMinWidth(u.dp(72));
            head.addView(t, u.wrap(4));
        }
        box.addView(head);
        box.addView(divider());

        final String[][] rows = {
            {"Country", "spoof.configuration", "getprop_gsm.sim.operator.iso-country",
                    "country", "spoof.telephony_country", "sim_country"},
            {"Carrier", "spoof.configuration", "getprop_gsm.sim.operator.numeric", "plmn",
                    "spoof.telephony_country", "sim_operator"},
            {"Carrier name", "spoof.configuration", "getprop_gsm.sim.operator.alpha",
                    "operator", "spoof.telephony_country", "sim_operator_name"},
            {"Time zone", "spoof.timezone", "getprop_persist.sys.timezone", "tz",
                    "spoof.timezone", "java_tz"},
            {"Language", "spoof.configuration", "getprop_persist.sys.locale", "locale",
                    "spoof.configuration", "config_locales"},
        };
        for (String[] row : rows) {
            final String real = detail(row[1], row[2]);
            String expected = null;
            if (profile != null) {
                if ("plmn".equals(row[3])) {
                    final String mcc = profile.optString("mcc", "");
                    final String mnc = profile.optString("mnc", "");
                    expected = mcc.isEmpty() ? null : mcc + mnc;
                } else {
                    expected = profile.optString(row[3], "");
                    if (expected.isEmpty()) {
                        expected = null;
                    }
                }
            } else if (mShownExpect != null && !mShownExpect.isEmpty() && !spoofed) {
                expected = real;
            }
            final String seen = detail(row[4], row[5]);
            box.addView(spoofRow(row[0], real, expected, seen));
            box.addView(divider());
        }
        // The public address: country of the exit, and whether the app was offline instead.
        final String ipCheck = detail("spoof.network_visibility", "ip_check");
        final String ipCountry = detail("spoof.network_visibility", "ip_country");
        final String vpnExit = detail("spoof.network_visibility", "mullvad_exit_ip");
        final String expectIp = mShownExpect == null ? null : mShownExpect.get("expect_ip");
        final String seenIp = "offline".equals(ipCheck) ? "offline"
                : ipCountry == null ? ipCheck : ipCountry + ("true".equals(vpnExit) ? " via VPN" : "");
        final String expectedIp = expectIp == null ? null
                : "blocked".equals(expectIp) ? "offline (no VPN)" : "VPN exit or real";
        box.addView(spoofRow("Public IP", null, expectedIp, seenIp));
        box.addView(divider());
        final String broadcasts = detail("spoof.broadcasts", "country_broadcasts");
        box.addView(spoofRow("Country broadcasts", null, spoofed ? "0" : null, broadcasts));
        mBody.addView(box, u.wide(0));
    }

    private View spoofRow(String name, String real, String expected, String seen) {
        final Ui u = mUi;
        final LinearLayout line = u.hbox();
        line.setPadding(0, u.dp(8), 0, u.dp(8));
        line.addView(u.text(name, 14, u.text), u.weight(0));
        final TextView r = u.mono(real == null ? "–" : real);
        r.setMinWidth(u.dp(72));
        r.setTextColor(u.muted);
        line.addView(r, u.wrap(4));
        final TextView e = u.mono(expected == null ? "?" : expected);
        e.setMinWidth(u.dp(72));
        line.addView(e, u.wrap(4));
        final boolean judged = expected != null && seen != null;
        final boolean ok = judged && same(expected, seen);
        final TextView s = u.mono((seen == null ? "–" : seen) + (judged ? ok ? " ✓" : " ✗" : ""));
        s.setMinWidth(u.dp(72));
        s.setTextColor(!judged ? u.text : ok ? u.ok : u.danger);
        line.addView(s, u.wrap(4));
        return line;
    }

    /** Loose equality for the comparison: case, spaces and comma lists (multi-SIM) ignored. */
    private static boolean same(String expected, String seen) {
        final String a = expected.trim().toLowerCase(Locale.ROOT);
        for (String part : seen.split(",")) {
            final String b = part.trim().toLowerCase(Locale.ROOT);
            if (b.equals(a) || b.startsWith(a) || a.startsWith(b) && !b.isEmpty()) {
                return true;
            }
        }
        return false;
    }

    // ---- footer: history strip, system screens ------------------------------------------------

    private void addFooter() {
        final Ui u = mUi;
        mBody.addView(u.section("History"));
        final LinearLayout box = u.card();
        box.setPadding(0, u.dp(4), 0, u.dp(4));

        // IchthysOS: one dot per run, oldest left, the shown run outlined; tap to open it.
        final List<History.Entry> runs = History.load(getApplicationContext());
        final LinearLayout hist = u.vbox();
        hist.setPadding(u.dp(16), u.dp(12), u.dp(16), u.dp(12));
        hist.addView(u.title("Last " + Math.min(runs.size(), 10) + " runs · newest right", 15,
                u.text));
        final LinearLayout dots = u.hbox();
        dots.setPadding(0, u.dp(8), 0, 0);
        final int shownCount = Math.min(runs.size(), 10);
        for (int i = shownCount - 1; i >= 0; i--) {
            final History.Entry e = runs.get(i);
            final LinearLayout cell = u.vbox();
            cell.setGravity(Gravity.CENTER_HORIZONTAL);
            final boolean current = mShownEntry != null && mShownEntry.label.equals(e.label);
            final View dot = u.dot(e.fail > 0 ? u.danger : e.pass > 0 ? u.ok : u.hairline);
            final LinearLayout ring = u.vbox();
            ring.setPadding(u.dp(3), u.dp(3), u.dp(3), u.dp(3));
            ring.setBackground(u.shape(0, current ? u.accent : 0, 12));
            ring.addView(dot);
            cell.addView(ring);
            final TextView tag = u.text(e.label.startsWith("guard-")
                    ? (e.standIn.isEmpty() ? "G" : e.standIn.substring(0, 1)) : "·", 10, u.muted);
            cell.addView(tag);
            u.tappable(cell, v -> loadEntry(e));
            dots.addView(cell, u.wrap(i == shownCount - 1 ? 0 : 8));
        }
        hist.addView(dots);
        final StringBuilder sb = new StringBuilder();
        int n = 0;
        for (History.Entry e : runs) {
            sb.append(e.line()).append('\n');
            if (++n >= 8) {
                break;
            }
        }
        final TextView lines = u.mono(runs.isEmpty() ? "No runs recorded yet." : sb.toString()
                .trim());
        lines.setLayoutParams(u.wide(8));
        expandable(hist, "history", lines);
        box.addView(hist);
        box.addView(divider());

        final LinearLayout tools = u.vbox();
        tools.setPadding(u.dp(16), u.dp(12), u.dp(16), u.dp(12));
        tools.addView(u.title("System screens", 15, u.text));
        final LinearLayout grid = u.vbox();
        grid.setLayoutParams(u.wide(10));
        grid.addView(pair(
                u.button("App info", "probe_app_info", false, v -> open(new Intent(
                        Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                        Uri.fromParts("package", getPackageName(), null)))),
                u.button("Usage access", "probe_usage_access", false, v -> open(new Intent(
                        Settings.ACTION_USAGE_ACCESS_SETTINGS)))));
        grid.addView(pair(
                u.button("Draw over apps", "probe_overlay", false, v -> open(new Intent(
                        Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                        Uri.fromParts("package", getPackageName(), null)))),
                u.button("Notifications", "probe_notifications", false, v -> open(new Intent(
                        Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                        .putExtra(Settings.EXTRA_APP_PACKAGE, getPackageName())))), u.wide(8));
        grid.addView(pair(
                u.button("Location", "probe_location", false, v -> open(new Intent(
                        Settings.ACTION_LOCATION_SOURCE_SETTINGS))),
                u.button("Permissions", "probe_request_permissions", false,
                        v -> requestAllPermissions())), u.wide(8));
        if (mShownEntry != null && !mShownEntry.report.isEmpty()) {
            grid.addView(u.mono("Report: " + mShownEntry.report), u.wide(10));
        }
        expandable(tools, "tools", grid);
        box.addView(tools);
        mBody.addView(box, u.wide(0));
    }

    private LinearLayout pair(View a, View b) {
        final LinearLayout row = mUi.hbox();
        row.addView(a, mUi.weight(0));
        row.addView(b, mUi.weight(8));
        return row;
    }

    private void open(Intent i) {
        try {
            startActivity(i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        } catch (RuntimeException e) {
            toast("Couldn't open: " + Redact.exception(e));
        }
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_LONG).show();
    }

    private void requestAllPermissions() {
        final List<String> want = new ArrayList<>();
        try {
            final PackageInfo pi = getPackageManager().getPackageInfo(getPackageName(),
                    PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS));
            for (String p : pi.requestedPermissions) {
                try {
                    final PermissionInfo info = getPackageManager().getPermissionInfo(p, 0);
                    if (info.getProtection() == PermissionInfo.PROTECTION_DANGEROUS
                            && checkSelfPermission(p) != PackageManager.PERMISSION_GRANTED
                            && !p.equals(android.Manifest.permission.ACCESS_BACKGROUND_LOCATION)) {
                        want.add(p);
                    }
                } catch (PackageManager.NameNotFoundException e) {
                    // Not defined on this build (feature-flagged permission).
                }
            }
        } catch (PackageManager.NameNotFoundException e) {
            return;
        }
        if (want.isEmpty()) {
            toast("Every runtime permission is granted. Background location: App info › "
                    + "Permissions › Location › Allow all the time.");
            return;
        }
        requestPermissions(want.toArray(new String[0]), 1);
    }

    private String when(long ms) {
        final String time = new SimpleDateFormat("HH:mm", Locale.US).format(new Date(ms));
        if (DateUtils.isToday(ms)) {
            return "today " + time;
        }
        if (DateUtils.isToday(ms + DateUtils.DAY_IN_MILLIS)) {
            return "yesterday " + time;
        }
        return new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(new Date(ms));
    }

    private static String stamp() {
        return new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(new Date());
    }
}
