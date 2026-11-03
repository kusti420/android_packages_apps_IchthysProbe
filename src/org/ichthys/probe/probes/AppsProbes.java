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

package org.ichthys.probe.probes;

import static android.Manifest.permission.GET_ACCOUNTS;
import static android.Manifest.permission.PACKAGE_USAGE_STATS;
import static android.Manifest.permission.QUERY_ALL_PACKAGES;
import static android.Manifest.permission.SYSTEM_ALERT_WINDOW;

import static org.ichthys.probe.Probe.perms;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.accounts.Account;
import android.accounts.AccountManager;
import android.app.ActivityManager;
import android.app.usage.UsageEvents;
import android.app.usage.UsageStats;
import android.app.usage.UsageStatsManager;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.graphics.PixelFormat;
import android.provider.Settings;
import android.view.View;
import android.view.WindowManager;
import android.view.accessibility.AccessibilityManager;
import android.view.inputmethod.InputMethodManager;

import org.ichthys.probe.Expect;
import org.ichthys.probe.Outcome;
import org.ichthys.probe.Probe;
import org.ichthys.probe.Redact;
import org.ichthys.probe.Result;
import org.ichthys.probe.Shields;

import java.security.MessageDigest;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/** Other apps: package visibility, running apps, usage history, accounts, a11y, keyboards. */
public final class AppsProbes {
    static final String CAT = "Apps & usage";

    /** SHA-1 of Google's platform certificate (what microG's spoof reports). */
    static final String GOOGLE_CERT_SHA1 = "38918a453d07199354f8b19af05ec6562ced5788";

    private static final String SRC_QAP =
            "frameworks/base/services/permission/.../AppIdPermissionPolicy.kt:1408-1511 "
                    + "(INSTALL_REVOKED for non-system apps); pm/AppsFilterQueryAllPackages.java, "
                    + "AppsFilterBase.java:495,724";
    private static final String SRC_USAGE =
            "frameworks/base/services/usage/java/com/android/server/usage/"
                    + "UsageStatsService.java:2295-2327,2460-2553; IchthysShields.USAGE_HISTORY "
                    + "(\"apps with usage access see an empty history\")";
    private static final String SRC_SPOOF =
            "frameworks/base/services/core/java/com/android/server/pm/parsing/"
                    + "FakeSignatureUtils.java; PackageInfoUtils.java:300-325 (privileged "
                    + "gms/vending with Google's cert only)";

    private AppsProbes() {}

    public static void add(List<Probe> out) {
        out.add(new Probe(CAT, "apps.installed",
                "How many installed packages the app can enumerate (and how many are user apps).",
                perms(QUERY_ALL_PACKAGES),
                c -> {
                    final List<PackageInfo> all = c.app.getPackageManager()
                            .getInstalledPackages(PackageManager.PackageInfoFlags.of(0));
                    int user = 0;
                    for (PackageInfo p : all) {
                        if (p.applicationInfo != null
                                && (p.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) == 0) {
                            user++;
                        }
                    }
                    final int truth = c.truth("packages");
                    final Result r;
                    if (truth > 0 && all.size() * 10 < truth * 9) {
                        r = Result.blockedIchthys("filtered list (QUERY_ALL_PACKAGES withheld)");
                    } else {
                        r = Result.visible();
                    }
                    return r.put("visible", all.size()).put("visible_user_apps", user)
                            .put("truth_packages", truth < 0 ? "unknown" : String.valueOf(truth))
                            .put("checkSelfPermission", c.granted(QUERY_ALL_PACKAGES)
                                    ? "GRANTED (the app can't see the real state)" : "DENIED");
                })
                .expect(Expect.of("QUERY_ALL_PACKAGES user control", SRC_QAP,
                        "a user app gets the filtered package list until the user allows "
                                + "\"see all apps\"; after that the full list")
                        .when(c -> {
                            if (c.truth("packages") <= 0) {
                                return "no ground truth (--ei truth_packages N)";
                            }
                            return c.option("qap") == null ? "QAP state unknown (--es qap "
                                    + "default|granted)" : null;
                        })
                        .check((c, r) -> {
                            final boolean granted = "granted".equals(c.option("qap"));
                            if (granted && r.outcome != Outcome.VISIBLE) {
                                return "user allowed it but the list is still filtered";
                            }
                            if (!granted && r.outcome != Outcome.BLOCKED_ICHTHYS) {
                                return "full package list without the user's consent";
                            }
                            return null;
                        })));

        out.add(new Probe(CAT, "apps.launcher_query",
                "Apps with a launcher icon the app can resolve (queryIntentActivities).",
                Probe.NONE,
                c -> {
                    final Intent i = new Intent(Intent.ACTION_MAIN)
                            .addCategory(Intent.CATEGORY_LAUNCHER);
                    return Result.count("launchable", c.app.getPackageManager()
                            .queryIntentActivities(i, PackageManager.ResolveInfoFlags.of(0))
                            .size());
                }));

        out.add(new Probe(CAT, "apps.gms_signature",
                "The signing certificate com.google.android.gms reports to ordinary apps.",
                Probe.NONE,
                c -> {
                    final PackageManager pm = c.app.getPackageManager();
                    final PackageInfo pi;
                    try {
                        pi = pm.getPackageInfo("com.google.android.gms",
                                PackageManager.PackageInfoFlags.of(
                                        PackageManager.GET_SIGNING_CERTIFICATES));
                    } catch (PackageManager.NameNotFoundException e) {
                        return Result.unavailable("com.google.android.gms not visible/installed");
                    }
                    if (pi.signingInfo == null) {
                        return Result.empty().put("signing_info", "null");
                    }
                    final Signature[] sigs = pi.signingInfo.getApkContentsSigners();
                    final MessageDigest md = MessageDigest.getInstance("SHA-1");
                    boolean google = false;
                    for (Signature s : sigs) {
                        final StringBuilder hex = new StringBuilder();
                        for (byte b : md.digest(s.toByteArray())) {
                            hex.append(String.format("%02x", b & 0xff));
                        }
                        google |= GOOGLE_CERT_SHA1.equals(hex.toString());
                    }
                    final boolean consistent = sigs.length > 0 && pm.hasSigningCertificate(
                            "com.google.android.gms", sigs[0].toByteArray(),
                            PackageManager.CERT_INPUT_RAW_X509);
                    return Result.visible().put("signers", sigs.length)
                            .put("reports_google_cert", google)
                            .put("hasSigningCertificate_agrees", consistent)
                            .put("version", Redact.length(pi.versionName));
                })
                .expect(Expect.of("Signature spoofing (microG)", SRC_SPOOF,
                        "microG GmsCore reports Google's certificate so apps that check it "
                                + "work; nothing else can fake a signature")
                        // IchthysOS: no signing info at all (EMPTY) used to pass too.
                        .check((c, r) -> r.outcome == Outcome.EMPTY
                                ? "GmsCore reports no signing certificate at all"
                                : r.outcome != Outcome.VISIBLE ? null
                                : "true".equals(r.detail.get("reports_google_cert")) ? null
                                        : "GmsCore does not report Google's certificate")));

        out.add(new Probe(CAT, "apps.running_processes",
                "Other apps' running processes (getRunningAppProcesses).",
                Probe.NONE,
                c -> {
                    final ActivityManager am = c.app.getSystemService(ActivityManager.class);
                    final List<ActivityManager.RunningAppProcessInfo> l =
                            am.getRunningAppProcesses();
                    int others = 0;
                    if (l != null) {
                        for (ActivityManager.RunningAppProcessInfo p : l) {
                            if (p.uid != android.os.Process.myUid()) {
                                others++;
                            }
                        }
                    }
                    return others > 0 ? Result.visible().put("other_processes", others)
                            : Result.blockedPermission("only own processes (stock)")
                                    .put("own", l == null ? 0 : l.size());
                }));

        out.add(new Probe(CAT, "apps.running_tasks",
                "Other apps' tasks / recents (getRunningTasks, getRecentTasks).",
                Probe.NONE,
                c -> {
                    final ActivityManager am = c.app.getSystemService(ActivityManager.class);
                    @SuppressWarnings("deprecation")
                    final List<ActivityManager.RunningTaskInfo> t = am.getRunningTasks(20);
                    int others = 0;
                    for (ActivityManager.RunningTaskInfo i : t) {
                        if (i.baseActivity != null && !c.app.getPackageName().equals(
                                i.baseActivity.getPackageName())) {
                            others++;
                        }
                    }
                    return others > 0 ? Result.visible().put("other_tasks", others)
                            : Result.blockedPermission("only own tasks (stock)")
                                    .put("own", t.size());
                }));

        out.add(new Probe(CAT, "apps.usage_stats",
                "Which apps were used in the last 7 days (usage access; package count only).",
                perms(PACKAGE_USAGE_STATS),
                c -> {
                    final UsageStatsManager usm = c.app.getSystemService(UsageStatsManager.class);
                    final long now = System.currentTimeMillis();
                    final List<UsageStats> l = usm.queryUsageStats(
                            UsageStatsManager.INTERVAL_BEST, now - 7L * 86_400_000L, now);
                    final Set<String> pkgs = new HashSet<>();
                    if (l != null) {
                        for (UsageStats s : l) {
                            if (!c.app.getPackageName().equals(s.getPackageName())) {
                                pkgs.add(s.getPackageName());
                            }
                        }
                    }
                    if (pkgs.isEmpty()) {
                        if (!c.granted(PACKAGE_USAGE_STATS)) {
                            return Result.blockedPermission("no usage access (empty list)");
                        }
                        return c.shields.protects(Shields.USAGE_HISTORY)
                                ? Result.blockedIchthys("usage history shield")
                                : Result.empty().put("packages", 0);
                    }
                    return Result.visible().put("packages", pkgs.size());
                })
                .expect(Expect.of("Usage history shield", SRC_USAGE,
                        "apps with usage access see an empty history")
                        .outcomes(Outcome.BLOCKED_ICHTHYS, Outcome.EMPTY)
                        .when(c -> !c.granted(PACKAGE_USAGE_STATS) ? "no usage access"
                                : c.shields.notProtecting(Shields.USAGE_HISTORY))));

        out.add(new Probe(CAT, "apps.usage_events",
                "App switch events in the last hour (count only).",
                perms(PACKAGE_USAGE_STATS),
                c -> {
                    final UsageStatsManager usm = c.app.getSystemService(UsageStatsManager.class);
                    final long now = System.currentTimeMillis();
                    final UsageEvents ev = usm.queryEvents(now - 3_600_000L, now);
                    int n = 0;
                    final UsageEvents.Event e = new UsageEvents.Event();
                    while (ev != null && ev.hasNextEvent()) {
                        ev.getNextEvent(e);
                        if (!c.app.getPackageName().equals(e.getPackageName())) {
                            n++;
                        }
                    }
                    if (n == 0) {
                        if (!c.granted(PACKAGE_USAGE_STATS)) {
                            return Result.blockedPermission("no usage access");
                        }
                        return c.shields.protects(Shields.USAGE_HISTORY)
                                ? Result.blockedIchthys("usage history shield")
                                : Result.empty().put("events", 0);
                    }
                    return Result.visible().put("events", Redact.bucket(n));
                })
                .expect(Expect.of("Usage history shield", SRC_USAGE,
                        "queryEvents returns nothing for other apps")
                        .outcomes(Outcome.BLOCKED_ICHTHYS, Outcome.EMPTY)
                        .when(c -> !c.granted(PACKAGE_USAGE_STATS) ? "no usage access"
                                : c.shields.notProtecting(Shields.USAGE_HISTORY))));

        out.add(new Probe(CAT, "apps.accounts",
                "Accounts on the phone (count and number of account types).",
                perms(GET_ACCOUNTS),
                c -> {
                    final Account[] a = AccountManager.get(c.app).getAccounts();
                    final Set<String> types = new HashSet<>();
                    for (Account x : a) {
                        types.add(x.type);
                    }
                    return Result.count("accounts", a.length).put("types", types.size());
                }));

        out.add(new Probe(CAT, "apps.accessibility",
                "Enabled and installed accessibility services (counts), TalkBack state.",
                Probe.NONE,
                c -> {
                    final AccessibilityManager am =
                            c.app.getSystemService(AccessibilityManager.class);
                    final int enabled = am.getEnabledAccessibilityServiceList(
                            AccessibilityServiceInfo.FEEDBACK_ALL_MASK).size();
                    final int installed = am.getInstalledAccessibilityServiceList().size();
                    return Result.visible().put("enabled", enabled).put("installed", installed)
                            .put("a11y_on", am.isEnabled())
                            .put("touch_exploration", am.isTouchExplorationEnabled());
                }));

        out.add(new Probe(CAT, "apps.keyboards",
                "Installed and enabled keyboards (counts) and the default keyboard (hash).",
                Probe.NONE,
                c -> {
                    final InputMethodManager imm =
                            c.app.getSystemService(InputMethodManager.class);
                    String def;
                    try {
                        def = Settings.Secure.getString(c.app.getContentResolver(),
                                Settings.Secure.DEFAULT_INPUT_METHOD);
                    } catch (SecurityException e) {
                        def = null;
                    }
                    return Result.visible().put("installed", imm.getInputMethodList().size())
                            .put("enabled", imm.getEnabledInputMethodList().size())
                            .put("default", Redact.text(def));
                }));

        out.add(new Probe(CAT, "apps.overlay",
                "Whether the app can draw over other apps (adds a 1 px overlay and removes it).",
                perms(SYSTEM_ALERT_WINDOW),
                c -> {
                    if (!Settings.canDrawOverlays(c.app)) {
                        return Result.blockedPermission("canDrawOverlays false");
                    }
                    final AtomicReference<String> res = new AtomicReference<>("not run");
                    c.onMain(() -> {
                        final WindowManager wm = c.app.getSystemService(WindowManager.class);
                        final View v = new View(c.app);
                        try {
                            wm.addView(v, new WindowManager.LayoutParams(1, 1,
                                    WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
                                    WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                                            | WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE,
                                    PixelFormat.TRANSLUCENT));
                            wm.removeView(v);
                            res.set("added");
                        } catch (RuntimeException e) {
                            res.set(Redact.exception(e));
                        }
                    }, 3000);
                    return "added".equals(res.get()) ? Result.visible().put("overlay", "added")
                            : Result.blockedPermission(res.get());
                }));

        out.add(new Probe(CAT, "apps.own_state",
                "This app's own install state: installer, suspended (Guard quarantine), "
                        + "standby bucket, background restriction.",
                Probe.NONE,
                c -> {
                    final PackageManager pm = c.app.getPackageManager();
                    final UsageStatsManager usm = c.app.getSystemService(UsageStatsManager.class);
                    final ActivityManager am = c.app.getSystemService(ActivityManager.class);
                    return Result.visible()
                            .put("installer", String.valueOf(pm.getInstallSourceInfo(
                                    c.app.getPackageName()).getInstallingPackageName()))
                            .put("suspended", pm.isPackageSuspended())
                            .put("standby_bucket", usm.getAppStandbyBucket())
                            .put("bg_restricted", am.isBackgroundRestricted());
                }));
    }
}
