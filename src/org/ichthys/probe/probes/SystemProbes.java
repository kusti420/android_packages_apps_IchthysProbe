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

import android.app.ActivityManager;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.res.Configuration;
import android.os.BatteryManager;
import android.os.Build;
import android.os.LocaleList;
import android.os.SystemClock;
import android.provider.Settings;
import android.text.format.DateFormat;

import org.ichthys.probe.Ctx;
import org.ichthys.probe.Expect;
import org.ichthys.probe.Outcome;
import org.ichthys.probe.Probe;
import org.ichthys.probe.Redact;
import org.ichthys.probe.Result;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;

/**
 * Device facts any app reads without a permission: Build fields, system properties, locale and
 * time zone, uptime, battery, memory, global settings. Build and boot-state values describe the
 * device, not the owner, so they are recorded as they are; anything user-chosen is redacted.
 */
public final class SystemProbes {
    static final String CAT = "Device & system";

    private static final String SRC_PROPS =
            "frameworks/base/core/java/com/android/internal/util/ichthys/PropImitationHooks.java"
                    + ":226-261 (only gms, droidguard, vending, Photos when spoof_pif_photos=1, and"
                    + " persist.sys.pif.test_package); ActivityThread.java:8176";

    private SystemProbes() {}

    /** Runs {@code getprop name}; null when the property can't be read. */
    static String getprop(String name) {
        try {
            final Process p = new ProcessBuilder("/system/bin/getprop", name)
                    .redirectErrorStream(true).start();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(),
                    StandardCharsets.UTF_8))) {
                final String line = r.readLine();
                p.waitFor(2, TimeUnit.SECONDS);
                return line == null ? "" : line.trim();
            }
        } catch (Exception e) {
            return null;
        }
    }

    public static void add(List<Probe> out) {
        out.add(new Probe(CAT, "build.fields",
                "android.os.Build: model, maker, SoC, fingerprint, tags, radio version.",
                Probe.NONE,
                c -> Result.visible()
                        .put("manufacturer", Build.MANUFACTURER)
                        .put("brand", Build.BRAND)
                        .put("model", Build.MODEL)
                        .put("device", Build.DEVICE)
                        .put("product", Build.PRODUCT)
                        .put("hardware", Build.HARDWARE)
                        .put("board", Build.BOARD)
                        .put("soc", Build.SOC_MANUFACTURER + " " + Build.SOC_MODEL)
                        .put("fingerprint", Build.FINGERPRINT)
                        .put("type_tags", Build.TYPE + "/" + Build.TAGS)
                        .put("radio", Redact.text(Build.getRadioVersion()))
                        .put("serial_field", Build.SERIAL)
                        .put("abis", String.join(",", Build.SUPPORTED_ABIS))));

        out.add(new Probe(CAT, "build.spoof_scope",
                "Whether this app sees the real Build values or a spoofed (Play Integrity) set.",
                Probe.NONE,
                c -> {
                    final String fp = getprop("ro.build.fingerprint");
                    final String model = getprop("ro.product.model");
                    if (fp == null || fp.isEmpty()) {
                        return Result.unavailable("getprop ro.build.fingerprint unreadable");
                    }
                    final boolean fpSame = fp.equals(Build.FINGERPRINT);
                    final boolean modelSame = model == null || model.isEmpty()
                            || model.equals(Build.MODEL);
                    return Result.visible().put("fingerprint_matches_prop", fpSame)
                            .put("model_matches_prop", modelSame)
                            .put("pif_test_package", Redact.length(
                                    getprop("persist.sys.pif.test_package")));
                })
                .expect(Expect.of("Play Integrity prop spoofing scope", SRC_PROPS,
                        "only GMS/Play/(Photos) get spoofed Build values; ordinary apps see the "
                                + "real ones")
                        .check((c, r) -> r.outcome != Outcome.VISIBLE ? null
                                : "true".equals(r.detail.get("fingerprint_matches_prop"))
                                        && "true".equals(r.detail.get("model_matches_prop"))
                                        ? null : "Build.* differs from ro.* props in this app")));

        out.add(new Probe(CAT, "system.props",
                "System properties readable with getprop: serial, boot state, debug flags, USB.",
                Probe.NONE,
                c -> {
                    final Result r = Result.visible();
                    r.put("ro.serialno", Redact.length(getprop("ro.serialno")));
                    r.put("ro.boot.serialno", Redact.length(getprop("ro.boot.serialno")));
                    r.put("verifiedbootstate", String.valueOf(
                            getprop("ro.boot.verifiedbootstate")));
                    r.put("flash.locked", String.valueOf(getprop("ro.boot.flash.locked")));
                    r.put("ro.debuggable", String.valueOf(getprop("ro.debuggable")));
                    r.put("build.type", String.valueOf(getprop("ro.build.type")));
                    r.put("usb.state", String.valueOf(getprop("sys.usb.state")));
                    r.put("gsm.operator.alpha", Redact.length(getprop("gsm.operator.alpha")));
                    r.put("bootloader", String.valueOf(getprop("ro.bootloader")));
                    r.put("selinux", String.valueOf(getprop("ro.boot.selinux")));
                    r.put("security_patch", Build.VERSION.SECURITY_PATCH);
                    return r;
                }));

        out.add(new Probe(CAT, "system.locale_time",
                "Languages, time zone and time format (languages hashed, zone as offset).",
                Probe.NONE,
                c -> {
                    final LocaleList ll = LocaleList.getDefault();
                    final TimeZone tz = TimeZone.getDefault();
                    final Configuration cfg = c.app.getResources().getConfiguration();
                    return Result.visible().put("languages", ll.size())
                            .put("language_list", Redact.hash(ll.toLanguageTags()))
                            .put("utc_offset_h", tz.getRawOffset() / 3_600_000)
                            .put("dst", tz.inDaylightTime(new java.util.Date()))
                            .put("zone_id", Redact.hash(tz.getID()))
                            .put("24h", DateFormat.is24HourFormat(c.app))
                            .put("font_scale", String.valueOf(cfg.fontScale))
                            .put("night", (cfg.uiMode & Configuration.UI_MODE_NIGHT_MASK)
                                    == Configuration.UI_MODE_NIGHT_YES);
                }));

        out.add(new Probe(CAT, "system.uptime",
                "Time since boot and boot count (identifies reboots across apps).",
                Probe.NONE,
                c -> {
                    int boots;
                    try {
                        boots = Settings.Global.getInt(c.app.getContentResolver(),
                                Settings.Global.BOOT_COUNT);
                    } catch (Settings.SettingNotFoundException | SecurityException e) {
                        boots = -1;
                    }
                    return Result.visible()
                            .put("uptime", Redact.age(SystemClock.elapsedRealtime()))
                            .put("awake_ratio_pct", SystemClock.uptimeMillis() * 100
                                    / Math.max(1, SystemClock.elapsedRealtime()))
                            .put("boot_count", boots < 0 ? "unreadable" : Redact.bucket(boots));
                }));

        out.add(new Probe(CAT, "system.battery",
                "Battery level (5% steps), charging, health, temperature, cycle count.",
                Probe.NONE,
                c -> {
                    final Intent b = c.app.registerReceiver(null,
                            new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
                    if (b == null) {
                        return Result.unavailable("no battery broadcast");
                    }
                    final int level = b.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
                    final int scale = b.getIntExtra(BatteryManager.EXTRA_SCALE, 100);
                    final BatteryManager bm = c.app.getSystemService(BatteryManager.class);
                    return Result.visible()
                            .put("level_pct", level < 0 ? "?" : (level * 100 / scale) / 5 * 5 + "")
                            .put("plugged", b.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1))
                            .put("status", b.getIntExtra(BatteryManager.EXTRA_STATUS, -1))
                            .put("health", b.getIntExtra(BatteryManager.EXTRA_HEALTH, -1))
                            .put("temp_c", b.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, 0) / 10)
                            .put("cycle_count", b.getIntExtra(BatteryManager.EXTRA_CYCLE_COUNT,
                                    -1))
                            .put("charge_counter", Redact.bucket(bm.getIntProperty(
                                    BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER)))
                            .put("technology", String.valueOf(
                                    b.getStringExtra(BatteryManager.EXTRA_TECHNOLOGY)));
                }));

        out.add(new Probe(CAT, "system.memory_cpu",
                "RAM size, low-RAM flag, CPU cores (hardware fingerprint inputs).",
                Probe.NONE,
                c -> {
                    final ActivityManager am = c.app.getSystemService(ActivityManager.class);
                    final ActivityManager.MemoryInfo mi = new ActivityManager.MemoryInfo();
                    am.getMemoryInfo(mi);
                    return Result.visible().put("ram", Redact.bytes(mi.totalMem))
                            .put("avail", Redact.bytes(mi.availMem))
                            .put("low_ram", am.isLowRamDevice())
                            .put("cores", Runtime.getRuntime().availableProcessors());
                }));

        out.add(new Probe(CAT, "system.global_settings",
                "Global settings any app can read: developer options, adb, airplane mode, "
                        + "auto time, stay awake.",
                Probe.NONE,
                c -> {
                    final Result r = Result.visible();
                    globalInt(c, r, "dev_options", Settings.Global.DEVELOPMENT_SETTINGS_ENABLED);
                    globalInt(c, r, "adb", Settings.Global.ADB_ENABLED);
                    globalInt(c, r, "airplane", Settings.Global.AIRPLANE_MODE_ON);
                    globalInt(c, r, "auto_time", Settings.Global.AUTO_TIME);
                    globalInt(c, r, "stay_on", Settings.Global.STAY_ON_WHILE_PLUGGED_IN);
                    globalInt(c, r, "data_roaming", Settings.Global.DATA_ROAMING);
                    return r;
                }));
    }

    private static void globalInt(Ctx c, Result r, String label, String key) {
        try {
            r.put(label, Settings.Global.getString(c.app.getContentResolver(), key));
        } catch (SecurityException e) {
            r.put(label, "unreadable");
        }
    }
}
