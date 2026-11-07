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

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * IchthysOS: the protocol between Guard (Settings) and this app for a verification run. Guard
 * puts this app on the lists and policy of a stand-in preset and starts MainActivity with:
 *
 * <pre>
 *   --ez autorun true --ez guard_run true --es label guard-RUN-N
 *   --es reply_token T --es reply_component com.android.settings/...VerifyResultReceiver
 *   --es stand_in Untrusted|Messenger|Maps|...
 *   --es expect_net allowed|blocked          (what Guard's firewall holds for this uid)
 *   --es expect_location real|fake|none      (the location control of the stand-in)
 *   --es expect_fake_latlon "lat,lon"        (the fake place, when the fake place is on)
 *   --es expect_scans real|empty
 *   --es expect_lan allowed|blocked
 *   --es expect_shields id,id,...            (the shields Guard says protect this app)
 *   --ei truth_contacts N ... (row counts as the system sees them)
 * </pre>
 *
 * Only the probes of Guard's rule categories run (no file system, display, media, camera). When
 * the run is done the per-probe verdicts go back as an explicit broadcast to
 * {@code reply_component} with the token, so Guard can group them into its categories and
 * compare them with the events its own stream saw. Nothing in the reply is personal: ids,
 * verdicts, outcomes and the redacted detail line, plus the keyguard and screen state the run
 * saw ({@code keyguard_locked}, {@code interactive}), so Guard can mark a phase inconclusive.
 */
public final class GuardRun {
    public static final String ACTION_RESULT = "org.ichthys.probe.action.RESULT";
    public static final String EXTRA_GUARD_RUN = "guard_run";
    public static final String EXTRA_REPLY_TOKEN = "reply_token";
    public static final String EXTRA_REPLY_COMPONENT = "reply_component";
    public static final String EXTRA_STAND_IN = "stand_in";
    public static final String EXTRA_EXPECT_LOCATION = "expect_location";
    public static final String EXTRA_EXPECT_FAKE_LATLON = "expect_fake_latlon";
    public static final String EXTRA_EXPECT_SCANS = "expect_scans";
    public static final String EXTRA_EXPECT_LAN = "expect_lan";
    public static final String EXTRA_EXPECT_SHIELDS = "expect_shields";
    /** No longer sent by Guard: no probe reads it (the rule can't be tested from the screen). */
    public static final String EXTRA_EXPECT_SCREEN_OFF = "expect_screen_off";
    /** Reply extras. */
    public static final String EXTRA_PROBES = "probes";
    public static final String EXTRA_IN_SYSTEM = "in_system";
    public static final String EXTRA_DIFF = "diff";
    public static final String EXTRA_REPORT = "report";
    public static final String EXTRA_LABEL = "label";
    /** Reply extras: the keyguard and screen state at reply time (same sources as Report.device). */
    public static final String EXTRA_KEYGUARD_LOCKED = "keyguard_locked";
    public static final String EXTRA_INTERACTIVE = "interactive";
    /** Reply extra: set (with the token) when the run could not happen; the value says why. */
    public static final String EXTRA_ERROR = "error";

    /** Guard lives in Settings; it is the only valid sender and reply target. */
    public static final String SETTINGS_PACKAGE = "com.android.settings";
    /** Settings' receiver that starts "Verify my protection" when this app asks for it. */
    public static final String ACTION_VERIFY_REQUEST = "org.ichthys.guard.action.VERIFY_REQUEST";
    public static final String VERIFY_REQUEST_RECEIVER =
            "com.android.settings.ichthys.guard.notify.VerifyRequestReceiver";

    /** Id prefixes of the probes that belong to Guard's rule categories. */
    private static final String[] GUARD_PREFIXES = {
        "net.", "location.", "contacts.", "calendar.", "calllog.", "sms.", "clip.", "sensors.",
        "bt.", "wifi.", "uwb.", "nfc.", "guard.", "settings.shield_lists", "phone.cell_info",
        "phone.line1_number", "phone.subscription_number", "apps.usage_stats",
        "apps.usage_events", "spoof.",
    };

    private GuardRun() {}

    /** True when the launch intent asks for a Guard verification run. */
    public static boolean isGuardRun(Bundle extras) {
        return extras != null && extras.getBoolean(EXTRA_GUARD_RUN, false);
    }

    /**
     * Whether an autorun launch may be honoured: a Guard run only from the system uid (Settings
     * shares it), a plain headless run from the shell, root or the system. Any other app could
     * otherwise make this app measure and broadcast what it sees to a receiver of its choice.
     */
    public static boolean trustedLaunch(android.app.Activity activity, boolean guardRun) {
        // Since Android 14 the launcher's identity is only shared when it opts in
        // (ActivityOptions.setShareIdentityEnabled); Guard does, `am start` from the shell
        // cannot, so -1 means "unknown", not "an app". A known app uid is refused; an unknown
        // launcher may start a run, but its replies only ever go to Settings (reply()) and a
        // busy probe ignores it, so the most it gains is a run of this app's own checks.
        final int uid = activity.getLaunchedFromUid();
        if (uid < 0) {
            return true;
        }
        if (guardRun) {
            return uid == android.os.Process.SYSTEM_UID;
        }
        // UserHandle.getAppId is hidden from the SDK: the per-user range is 100000.
        return uid % 100_000 < android.os.Process.FIRST_APPLICATION_UID;
    }

    /** Tells Guard at once that this phase could not run (another run is in progress). */
    public static void replyBusy(Context context, Bundle extras) {
        if (extras == null) {
            return;
        }
        final String target = extras.getString(EXTRA_REPLY_COMPONENT);
        final String token = extras.getString(EXTRA_REPLY_TOKEN);
        final ComponentName cn = target == null ? null
                : ComponentName.unflattenFromString(target);
        if (cn == null || token == null || !SETTINGS_PACKAGE.equals(cn.getPackageName())) {
            return;
        }
        context.sendBroadcast(new Intent(ACTION_RESULT)
                .setComponent(cn)
                .addFlags(Intent.FLAG_RECEIVER_FOREGROUND)
                .putExtra(EXTRA_REPLY_TOKEN, token)
                .putExtra(EXTRA_LABEL, String.valueOf(extras.getString(EXTRA_LABEL)))
                .putExtra(EXTRA_ERROR, "IchthysProbe was busy with another run")
                .putExtra(EXTRA_PROBES, "[]")
                .putExtra(EXTRA_IN_SYSTEM, inSystem(context)));
        Log.w(Runner.TAG, "REPLY busy to " + target);
    }

    /**
     * Asks Guard to run "Verify my protection" (every stand-in, this app as the tester). The
     * broadcast shares this app's identity so Settings can refuse anyone else.
     */
    public static void requestVerification(Context context) {
        final Intent i = new Intent(ACTION_VERIFY_REQUEST)
                .setComponent(new ComponentName(SETTINGS_PACKAGE, VERIFY_REQUEST_RECEIVER))
                .addFlags(Intent.FLAG_RECEIVER_FOREGROUND);
        final android.app.BroadcastOptions options = android.app.BroadcastOptions.makeBasic()
                .setShareIdentityEnabled(true);
        context.sendBroadcast(i, null, options.toBundle());
        Log.i(Runner.TAG, "VERIFY_REQUEST sent to Guard");
    }

    /** Whether {@code p} runs in a Guard verification (a tap probe never does). */
    public static boolean includes(Probe p) {
        if (p.isTapProbe()) {
            return false;
        }
        for (String prefix : GUARD_PREFIXES) {
            if (p.id.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    /** Guard's rule category of a probe, for the headers of the probe's own screen. */
    public static String category(Probe p) {
        final String id = p.id;
        if (id.startsWith("net.lan") || id.startsWith("net.dns_trackers")) {
            return "Local network & hosts";
        }
        if (id.startsWith("net.")) {
            return "Firewall";
        }
        if (id.startsWith("location.") || id.equals("bt.le_scan") || id.equals("bt.discovery")
                || id.equals("wifi.scan_results") || id.equals("wifi.connection")
                || id.equals("phone.cell_info")) {
            return "Location";
        }
        if (id.startsWith("guard.")) {
            return "Service health";
        }
        if (id.startsWith("spoof.")) {
            return "Spoofed values";
        }
        return "Shields";
    }

    /** Whether this app sits in /system (or updates a system app): shield results are skewed. */
    public static boolean inSystem(Context context) {
        final ApplicationInfo ai = context.getApplicationInfo();
        return (ai.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP))
                != 0 || (ai.sourceDir != null && ai.sourceDir.startsWith("/system"));
    }

    /**
     * Sends the run's verdicts to Guard. Only the probes' ids, categories, verdicts, outcomes and
     * why; the redacted detail line is left out of the broadcast (it is in the report file),
     * except for the {@code spoof.*} probes, whose raw coarse values Guard's Verify compares.
     */
    public static void reply(Context context, Ctx c, Report report, File reportFile,
            List<String> diff) {
        final String target = c.option(EXTRA_REPLY_COMPONENT);
        final String token = c.option(EXTRA_REPLY_TOKEN);
        if (target == null || token == null) {
            return;
        }
        final ComponentName cn = ComponentName.unflattenFromString(target);
        if (cn == null || !SETTINGS_PACKAGE.equals(cn.getPackageName())) {
            // IchthysOS: the verdicts go to Guard and nowhere else.
            Log.w(Runner.TAG, "bad reply_component " + target);
            return;
        }
        final JSONArray probes = new JSONArray();
        try {
            for (Map.Entry<String, Result> e : report.entries().entrySet()) {
                final Probe p = Registry.byId(e.getKey());
                final Result r = e.getValue();
                final JSONObject o = new JSONObject();
                o.put("id", e.getKey());
                o.put("category", p == null ? "" : p.category);
                o.put("verdict", r.verdict.key);
                o.put("outcome", r.outcome.key);
                o.put("why", r.verdictWhy);
                if (e.getKey().startsWith("spoof.")) {
                    // IchthysOS: the Spoofed values probes carry raw coarse region values
                    // (country, PLMN, operator, zone, locale) that Guard's Verify compares
                    // with the profile it wrote; nothing personal is in them (README).
                    final JSONObject d = new JSONObject();
                    for (Map.Entry<String, String> f : r.detail.entrySet()) {
                        d.put(f.getKey(), f.getValue());
                    }
                    o.put("detail", d);
                }
                probes.put(o);
            }
        } catch (org.json.JSONException e) {
            Log.w(Runner.TAG, "reply not built", e);
            return;
        }
        // A locked or sleeping phone changes many answers (see Report.device): Guard marks the
        // phase inconclusive from these two, so they travel with the verdicts.
        final android.app.KeyguardManager km =
                context.getSystemService(android.app.KeyguardManager.class);
        final android.os.PowerManager pm = context.getSystemService(android.os.PowerManager.class);
        final Intent i = new Intent(ACTION_RESULT)
                .setComponent(cn)
                .addFlags(Intent.FLAG_RECEIVER_FOREGROUND)
                .putExtra(EXTRA_REPLY_TOKEN, token)
                .putExtra(EXTRA_LABEL, report.label)
                .putExtra(EXTRA_PROBES, probes.toString())
                .putExtra(EXTRA_IN_SYSTEM, inSystem(context))
                .putExtra(EXTRA_REPORT, reportFile == null ? "" : reportFile.getPath())
                .putExtra(EXTRA_KEYGUARD_LOCKED, km != null && km.isKeyguardLocked())
                .putExtra(EXTRA_INTERACTIVE, pm != null && pm.isInteractive())
                .putExtra("build_id", Build.ID)
                .putExtra("pass", report.count(Verdict.PASS))
                .putExtra("fail", report.count(Verdict.FAIL))
                .putExtra("info", report.count(Verdict.INFO))
                .putExtra("skip", report.count(Verdict.SKIP))
                .putStringArrayListExtra(EXTRA_DIFF, new ArrayList<>(diff));
        context.sendBroadcast(i);
        Log.i(Runner.TAG, "REPLY label=" + report.label + " to " + target);
    }

    /** Per-category pass/fail/info/skip counts of a report, for the screen headers. */
    public static Map<String, int[]> tallies(Report report) {
        final Map<String, int[]> out = new LinkedHashMap<>();
        for (Map.Entry<String, Result> e : report.entries().entrySet()) {
            final Probe p = Registry.byId(e.getKey());
            if (p == null) {
                continue;
            }
            final int[] t = out.computeIfAbsent(category(p), k -> new int[4]);
            switch (e.getValue().verdict) {
                case PASS: t[0]++; break;
                case FAIL: t[1]++; break;
                case INFO: t[2]++; break;
                default: t[3]++; break;
            }
        }
        return out;
    }
}
