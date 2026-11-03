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

import android.Manifest;
import android.app.Activity;
import android.app.AppOpsManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Process;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * What a probe gets to work with: the app context, the activity (for UI-bound calls), a looper
 * thread for callbacks, the shield state, run options from the launch intent, and a small
 * scratch map shared between probes of one run.
 */
public final class Ctx {
    public final Context app;
    public final Activity activity;
    public final Shields shields;
    public final Handler main;
    /** A looper thread for listeners and callbacks (sensors, location, scans). */
    public final Handler worker;
    public final String label;
    /** True while a probe runs from a real tap on its button. */
    public volatile boolean fromTap;
    /** True for a headless run started with {@code --ez autorun true}. */
    public volatile boolean autorun;
    /** SystemClock.uptimeMillis() of the last touch or key the activity saw. */
    public static volatile long sLastInputUptime;
    /** Shared between probes of one run (e.g. the clipboard nonce). */
    public final Map<String, Object> scratch = new ConcurrentHashMap<>();

    private final Bundle mExtras;

    Ctx(Activity activity, String label, Bundle extras) {
        this.activity = activity;
        this.app = activity.getApplicationContext();
        this.label = label;
        this.shields = new Shields(app);
        this.main = new Handler(Looper.getMainLooper());
        final HandlerThread t = new HandlerThread("probe-worker");
        t.start();
        this.worker = new Handler(t.getLooper());
        mExtras = extras == null ? new Bundle() : new Bundle(extras);
        // IchthysOS: in a Guard verification Guard's expect_shields is the authority on the
        // shield state (the settings lists are hidden from apps since 2026-10-28).
        final String expectShields = mExtras.getString(GuardRun.EXTRA_EXPECT_SHIELDS);
        if (expectShields != null) {
            shields.useGuardView(expectShields);
        }
    }

    void quit() {
        worker.getLooper().quitSafely();
    }

    /** Runtime or app-op backed permission state as the app sees it. */
    public boolean granted(String permission) {
        switch (permission) {
            case Manifest.permission.PACKAGE_USAGE_STATS:
                return opAllowed(AppOpsManager.OPSTR_GET_USAGE_STATS);
            case Manifest.permission.SYSTEM_ALERT_WINDOW:
                return android.provider.Settings.canDrawOverlays(app);
            case Manifest.permission.QUERY_ALL_PACKAGES:
                // Install-time (normal) permission; IchthysOS may still withhold it through an
                // app-op, which the packages probes measure directly.
                return app.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED;
            default:
                return app.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED;
        }
    }

    public boolean opAllowed(String op) {
        try {
            final AppOpsManager aom = app.getSystemService(AppOpsManager.class);
            final int mode = aom.unsafeCheckOpNoThrow(op, Process.myUid(), app.getPackageName());
            if (mode == AppOpsManager.MODE_DEFAULT) {
                // MODE_DEFAULT falls back to the permission itself (usage stats: the grant).
                return false;
            }
            return mode == AppOpsManager.MODE_ALLOWED;
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** A string option from the launch intent ({@code --es key value}). */
    public String option(String key) {
        return mExtras.getString(key);
    }

    /**
     * A ground-truth count handed in by the host script ({@code --ei truth_<name> N}, counted as
     * the exempt shell uid), or -1 when unknown. Lets a probe tell "shielded" from "really empty".
     */
    public int truth(String name) {
        final Object v = mExtras.get("truth_" + name);
        if (v instanceof Integer) {
            return (Integer) v;
        }
        if (v instanceof String) {
            try {
                return Integer.parseInt((String) v);
            } catch (NumberFormatException e) {
                return -1;
            }
        }
        return -1;
    }

    /** Runs {@code r} on the main thread and waits up to {@code ms}. */
    public void onMain(Runnable r, long ms) throws InterruptedException {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            r.run();
            return;
        }
        final java.util.concurrent.CountDownLatch done = new java.util.concurrent.CountDownLatch(1);
        main.post(() -> {
            try {
                r.run();
            } finally {
                done.countDown();
            }
        });
        done.await(ms, java.util.concurrent.TimeUnit.MILLISECONDS);
    }

    /** Sleeps without throwing; probes use it to give callbacks time to arrive. */
    public static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Waits until no user input happened for {@code quietMs}, so a no-tap clipboard read isn't
     * backed by the tap that started the run (the lockdown grants a read for 2 s after a tap).
     */
    public static void waitForQuiet(long quietMs) {
        for (int i = 0; i < 100; i++) {
            final long since = android.os.SystemClock.uptimeMillis() - sLastInputUptime;
            if (since >= quietMs) {
                return;
            }
            sleep(Math.min(quietMs - since + 50, 500));
        }
    }

    public boolean hasFeature(String feature) {
        return app.getPackageManager().hasSystemFeature(feature);
    }

    public Intent launchIntent() {
        return activity.getIntent();
    }
}
