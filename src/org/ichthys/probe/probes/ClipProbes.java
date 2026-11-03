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

import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.SystemClock;
import android.provider.Settings;

import org.ichthys.probe.Ctx;
import org.ichthys.probe.Expect;
import org.ichthys.probe.Outcome;
import org.ichthys.probe.Probe;
import org.ichthys.probe.Redact;
import org.ichthys.probe.Result;
import org.ichthys.probe.Shields;

import java.security.SecureRandom;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Clipboard lockdown (kusti420/ichthysos-tracker#31). Another app's clip comes from the helper
 * app, so no personal clipboard content is ever needed; a clip that isn't the helper's or ours
 * is described by length and salted hash only.
 *
 * <p>Note: these probes overwrite the clipboard (helper clip, then a marker clip of this app).
 */
public final class ClipProbes {
    static final String CAT = "Clipboard";

    static final String SRC_CS =
            "frameworks/base/services/core/java/com/android/server/clipboard/"
                    + "ClipboardService.java";
    private static final String SRC_READ = SRC_CS + ":821-866 (getPrimaryClip returns null "
            + "without a paste grant), :1667-1708 (ichthysNeedsPasteProof), :1729-1740 "
            + "(ichthysMayReadLocked)";
    private static final String SRC_DESC = SRC_CS + ":868-905 (stripped description: no label,"
            + " no extras)";
    private static final String SRC_TAP = SRC_CS + ":740-800 (notePasteInput: verified UP "
            + "or paste key, at most 2 s old, one input = one paste, 500 ms after use); "
            + "core/java/android/content/ClipboardManager.java:270-286";
    private static final String SRC_FOCUS = SRC_CS + ":1634-1642 (focus on the top-focused "
            + "display only)";
    private static final String SRC_CLEAR = SRC_CS + " ichthysArmClearLocked / "
            + "ichthysExpireIfDueLocked (elapsed-realtime deadline from the copy, default 5 min, "
            + "Global ichthys_clipboard_clear_minutes); services-fixes.md C3";

    private static final String PREFS = "probe";
    private static final String K_TOKEN = "clip_marker_token";
    private static final String K_ELAPSED = "clip_marker_elapsed";
    private static final String K_BOOT = "clip_marker_boot";
    private static final String OWN_LABEL = "IchthysProbe";
    private static final String OWN_PREFIX = "IchthysProbe:";

    private ClipProbes() {}

    static String token() {
        final byte[] b = new byte[6];
        new SecureRandom().nextBytes(b);
        final StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x & 0xff));
        }
        return sb.toString();
    }

    /** What a clip is, without its content: helper's (token ok?), ours, or someone else's. */
    static String describe(Context ctx, ClipData clip, String helperToken) {
        if (clip == null) {
            return "null";
        }
        if (clip.getItemCount() == 0) {
            return "no items";
        }
        final CharSequence t = clip.getItemAt(0).coerceToText(ctx);
        final String s = t == null ? "" : t.toString();
        if (s.startsWith(Helper.CLIP_PREFIX)) {
            return "helper clip, token " + (helperToken != null
                    && s.equals(Helper.CLIP_PREFIX + helperToken) ? "matches" : "differs");
        }
        if (s.startsWith(OWN_PREFIX)) {
            return "own marker clip";
        }
        return "foreign clip, " + Redact.text(s);
    }

    private static ClipboardManager cm(Ctx c) {
        return c.app.getSystemService(ClipboardManager.class);
    }

    private static Expect lockdown(String promise, String source, Outcome... ok) {
        final Expect e = Expect.of("Clipboard lockdown", source, promise);
        if (ok.length == 1) {
            e.outcomes(ok[0]);
        } else {
            final Outcome[] rest = new Outcome[ok.length - 1];
            System.arraycopy(ok, 1, rest, 0, rest.length);
            e.outcomes(ok[0], rest);
        }
        return e.when(c -> !Helper.installed(c) ? "helper app not installed"
                : c.shields.notProtecting(Shields.CLIPBOARD));
    }

    /** Sets this app's own marker clip and remembers when, for the next run's auto-clear check. */
    static void setMarker(Ctx c) {
        final String tok = token();
        cm(c).setPrimaryClip(ClipData.newPlainText(OWN_LABEL, OWN_PREFIX + tok));
        int boot = -1;
        try {
            boot = Settings.Global.getInt(c.app.getContentResolver(), Settings.Global.BOOT_COUNT);
        } catch (Exception e) {
            // Unknown boot: the check treats it as a different boot.
        }
        c.app.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString(K_TOKEN, tok)
                .putLong(K_ELAPSED, SystemClock.elapsedRealtime())
                .putInt(K_BOOT, boot)
                .apply();
    }

    private static final String K_TAP_TOKEN = "tap_token";
    private static final String K_TAP_DONE = "tap_done";

    /**
     * Called on the tap button's ACTION_DOWN: asks the helper to copy a fresh clip right away,
     * before the UP that backs the paste arrives.
     */
    public static void prepareTap(Ctx c) {
        final String tok = token();
        final CountDownLatch done = new CountDownLatch(1);
        c.scratch.put(K_TAP_TOKEN, tok);
        c.scratch.put(K_TAP_DONE, done);
        new Thread(() -> {
            if (Helper.copy(c, tok)) {
                done.countDown();
            }
        }, "tap-prepare").start();
    }

    private static String awaitPrepared(Ctx c) throws InterruptedException {
        Object done = c.scratch.remove(K_TAP_DONE);
        Object tok = c.scratch.remove(K_TAP_TOKEN);
        if (!(done instanceof CountDownLatch)) {
            prepareTap(c);
            done = c.scratch.remove(K_TAP_DONE);
            tok = c.scratch.remove(K_TAP_TOKEN);
        }
        return ((CountDownLatch) done).await(1500, TimeUnit.MILLISECONDS) ? (String) tok : null;
    }

    /** No-tap read of a fresh helper clip: the core lockdown check. */
    static Result readForeign(Ctx c) {
        if (!Helper.installed(c)) {
            return Result.skipped("helper app org.ichthys.probe.helper not installed");
        }
        final String tok = token();
        if (!Helper.copy(c, tok)) {
            return Result.skipped("helper didn't answer (quarantined or stopped?)");
        }
        Ctx.sleep(300);
        final ClipboardManager cm = cm(c);
        final boolean has = cm.hasPrimaryClip();
        final ClipData clip = cm.getPrimaryClip();
        final String what = describe(c.app, clip, tok);
        if (clip == null) {
            return (has && c.shields.protects(Shields.CLIPBOARD)
                    ? Result.blockedIchthys("getPrimaryClip null while a clip exists")
                    : Result.empty()).put("has_clip", has).put("read", what);
        }
        return Result.visible().put("has_clip", has).put("read", what);
    }

    public static void add(List<Probe> out) {
        out.add(new Probe(CAT, "clip.autoclear",
                "Whether a clip this app copied in an earlier run was cleared after the "
                        + "auto-clear time (default 5 min, counted in real time incl. sleep).",
                Probe.NONE,
                c -> {
                    final SharedPreferences p =
                            c.app.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
                    final String tok = p.getString(K_TOKEN, null);
                    if (tok == null) {
                        return Result.skipped("no marker clip from an earlier run yet");
                    }
                    final Shields.Read minutes = c.shields.read("ichthys_clipboard_clear_minutes",
                            true);
                    int clearMin = 5;
                    if (minutes.readable && minutes.value != null) {
                        try {
                            clearMin = Integer.parseInt(minutes.value.trim());
                        } catch (NumberFormatException e) {
                            // Keep the default.
                        }
                    }
                    if (clearMin <= 0) {
                        return Result.skipped("auto-clear set to platform default (0)");
                    }
                    int boot = -1;
                    try {
                        boot = Settings.Global.getInt(c.app.getContentResolver(),
                                Settings.Global.BOOT_COUNT);
                    } catch (Exception e) {
                        // Unknown.
                    }
                    if (boot < 0 || boot != p.getInt(K_BOOT, -2)) {
                        return Result.skipped("rebooted since the marker clip was set");
                    }
                    final long age = SystemClock.elapsedRealtime() - p.getLong(K_ELAPSED, 0);
                    if (age < (clearMin + 1) * 60_000L) {
                        return Result.skipped("not due yet: copied " + Redact.age(age)
                                + " ago, clears after " + clearMin + " min");
                    }
                    Ctx.waitForQuiet(2600);
                    final ClipboardManager cm = cm(c);
                    final ClipData clip = cm.getPrimaryClip();
                    final String what = describe(c.app, clip, null);
                    if (clip != null && what.equals("own marker clip")) {
                        final CharSequence t = clip.getItemAt(0).coerceToText(c.app);
                        if (t != null && t.toString().equals(OWN_PREFIX + tok)) {
                            return Result.visible().put("marker", "still there after "
                                    + Redact.age(age)).put("clear_min", clearMin);
                        }
                    }
                    if (!cm.hasPrimaryClip()) {
                        return Result.blockedIchthys("cleared").put("age", Redact.age(age))
                                .put("clear_min", clearMin);
                    }
                    return Result.skipped("inconclusive: another clip replaced the marker ("
                            + what + ")");
                })
                .expect(Expect.of("Clipboard auto-clear", SRC_CLEAR,
                        "a copied clip is cleared the set minutes after the copy, sleep "
                                + "included")
                        .outcomes(Outcome.BLOCKED_ICHTHYS)
                        .when(c -> c.shields.notProtecting(Shields.CLIPBOARD))));

        out.add(new Probe(CAT, "clip.listener",
                "Clip-change callback while focused, and whether the callback can read the "
                        + "new clip without a tap.",
                Probe.NONE,
                c -> {
                    if (!Helper.installed(c)) {
                        return Result.skipped("helper app not installed");
                    }
                    Ctx.waitForQuiet(2600);
                    final ClipboardManager cm = cm(c);
                    final String tok = token();
                    final AtomicReference<String> inCallback = new AtomicReference<>();
                    final CountDownLatch fired = new CountDownLatch(1);
                    final ClipboardManager.OnPrimaryClipChangedListener l = () -> {
                        inCallback.set(describe(c.app, cm.getPrimaryClip(), tok));
                        fired.countDown();
                    };
                    c.onMain(() -> cm.addPrimaryClipChangedListener(l), 2000);
                    try {
                        if (!Helper.copy(c, tok)) {
                            return Result.skipped("helper didn't answer (quarantined?)");
                        }
                        fired.await(3, TimeUnit.SECONDS);
                    } finally {
                        c.onMain(() -> cm.removePrimaryClipChangedListener(l), 2000);
                    }
                    final String got = inCallback.get();
                    if (got == null) {
                        return Result.empty().put("callback", "not fired");
                    }
                    if ("null".equals(got)) {
                        return Result.blockedIchthys("callback fired, contents withheld")
                                .put("callback", "fired").put("read_in_callback", got);
                    }
                    return Result.visible().put("callback", "fired").put("read_in_callback", got);
                })
                .timeout(12_000)
                .expect(lockdown("a clip-change listener learns that the clip changed, never what "
                        + "it is", SRC_READ, Outcome.BLOCKED_ICHTHYS, Outcome.EMPTY)));

        out.add(new Probe(CAT, "clip.read_no_tap",
                "Reading another app's clip while in front but without a tap (a poller).",
                Probe.NONE,
                c -> {
                    Ctx.waitForQuiet(2600);
                    return readForeign(c);
                })
                .timeout(10_000)
                .expect(lockdown("a read without a fresh user tap returns nothing", SRC_READ,
                        Outcome.BLOCKED_ICHTHYS)));

        out.add(new Probe(CAT, "clip.description",
                "The clip description (label, MIME types) of another app's clip, without a tap.",
                Probe.NONE,
                c -> {
                    if (!Helper.installed(c)) {
                        return Result.skipped("helper app not installed");
                    }
                    Ctx.waitForQuiet(2600);
                    if (!Helper.copy(c, token())) {
                        return Result.skipped("helper didn't answer");
                    }
                    Ctx.sleep(300);
                    final ClipDescription d = cm(c).getPrimaryClipDescription();
                    if (d == null) {
                        return Result.empty().put("description", "null");
                    }
                    final CharSequence label = d.getLabel();
                    final boolean labelled = label != null && label.length() > 0;
                    final Result r = labelled ? Result.visible()
                            : Result.blockedIchthys("label and extras stripped");
                    return r.put("label", labelled ? (Helper.CLIP_LABEL.contentEquals(label)
                                    ? "helper label" : Redact.text(label)) : "empty")
                            .put("mime_types", d.getMimeTypeCount())
                            .put("extras", d.getExtras() != null);
                })
                .timeout(10_000)
                .expect(lockdown("without a grant the description carries MIME types only (no "
                        + "label, no extras)", SRC_DESC, Outcome.BLOCKED_ICHTHYS)));

        out.add(new Probe(CAT, "clip.has_clip",
                "Whether something is on the clipboard (presence only; not gated by design).",
                Probe.NONE,
                c -> Result.visible().put("has_clip", cm(c).hasPrimaryClip())
                        .put("has_text", cm(c).hasText())));

        out.add(new Probe(CAT, "clip.own_clip",
                "Reading back a clip this app copied itself.",
                Probe.NONE,
                c -> {
                    Ctx.waitForQuiet(2600);
                    final String tok = token();
                    final ClipboardManager cm = cm(c);
                    cm.setPrimaryClip(ClipData.newPlainText(OWN_LABEL, OWN_PREFIX + tok));
                    final ClipData clip = cm.getPrimaryClip();
                    if (clip == null) {
                        return Result.empty().put("read", "null");
                    }
                    final CharSequence t = clip.getItemAt(0).coerceToText(c.app);
                    final boolean same = t != null && t.toString().equals(OWN_PREFIX + tok);
                    c.scratch.put("own_token", tok);
                    return (same ? Result.visible() : Result.of(Outcome.ERROR))
                            .put("read", same ? "own clip, token matches" : "different clip");
                })
                .expect(Expect.of("Clipboard lockdown", SRC_READ,
                        "an app can always read the clip it copied itself")
                        .outcomes(Outcome.VISIBLE)));

        out.add(new Probe(CAT, "clip.other_app_bg_read",
                "Whether another app (the helper, in the background) can read this app's clip.",
                Probe.NONE,
                c -> {
                    if (!Helper.installed(c)) {
                        return Result.skipped("helper app not installed");
                    }
                    final Object tok = c.scratch.get("own_token");
                    if (tok == null) {
                        return Result.skipped("clip.own_clip didn't run");
                    }
                    final String answer = Helper.readInBackground(c, OWN_PREFIX + tok);
                    if (answer == null) {
                        return Result.skipped("helper didn't answer");
                    }
                    if (answer.startsWith("match")) {
                        return Result.visible().put("helper_read", answer);
                    }
                    return (answer.startsWith("null") ? Result.blockedPermission(
                            "background read refused") : Result.empty())
                            .put("helper_read", answer);
                })
                .expect(Expect.of("Clipboard lockdown", SRC_READ + "; stock background rule",
                        "an app in the background can't read another app's clip")
                        .outcomes(Outcome.BLOCKED_PERMISSION, Outcome.BLOCKED_ICHTHYS,
                                Outcome.EMPTY)));

        out.add(new Probe(CAT, "clip.background_self",
                "Reading another app's clip while this app is in the background (autorun only:"
                        + " moves the task to the back first).",
                Probe.NONE,
                c -> {
                    if (!c.autorun) {
                        return Result.skipped("runs in the headless autorun only");
                    }
                    if (!Helper.installed(c)) {
                        return Result.skipped("helper app not installed");
                    }
                    c.onMain(() -> c.activity.moveTaskToBack(true), 2000);
                    Ctx.sleep(1500);
                    final Result r = readForeign(c);
                    if (r.outcome == Outcome.BLOCKED_ICHTHYS || r.outcome == Outcome.EMPTY) {
                        // Refused in the background: stock rule plus the lockdown.
                        final Result b = Result.blockedPermission("background read refused");
                        b.detail.putAll(r.detail);
                        setMarker(c);
                        return b;
                    }
                    setMarker(c);
                    return r;
                })
                .timeout(15_000)
                .expect(Expect.of("Clipboard lockdown", SRC_READ + "; " + SRC_FOCUS,
                        "a background app never reads the clipboard")
                        .outcomes(Outcome.BLOCKED_PERMISSION, Outcome.BLOCKED_ICHTHYS)
                        .when(c -> !c.autorun ? "autorun only" : !Helper.installed(c)
                                ? "helper app not installed" : null)));

        out.add(new Probe(CAT, "clip.tap_read",
                "Paste after a real tap on this probe's button: the first read works, a "
                        + "second read 1 s later (same tap) doesn't.",
                Probe.NONE,
                c -> {
                    if (!c.fromTap) {
                        return Result.skipped("needs a real tap on \"Tap: paste test\"");
                    }
                    if (!Helper.installed(c)) {
                        return Result.skipped("helper app not installed");
                    }
                    // The button's ACTION_DOWN already asked the helper to copy (prepareTap),
                    // so the read lands well inside the 2 s the tap's UP allows.
                    final String tok = awaitPrepared(c);
                    if (tok == null) {
                        return Result.skipped("helper didn't copy in time (quarantined or "
                                + "stopped?); tap again");
                    }
                    final ClipboardManager cm = cm(c);
                    final long msAfterTap = SystemClock.uptimeMillis() - Ctx.sLastInputUptime;
                    final String first = describe(c.app, cm.getPrimaryClip(), tok);
                    if ("null".equals(first) && msAfterTap > 1900) {
                        return Result.skipped("read came " + msAfterTap + " ms after the tap "
                                + "(> 2 s grant); helper too slow, tap again");
                    }
                    Ctx.sleep(1000);
                    final String second = describe(c.app, cm.getPrimaryClip(), tok);
                    setMarker(c);
                    final Result r = first.startsWith("helper clip") ? Result.visible()
                            : Result.empty();
                    return r.put("first_read", first).put("second_read_1s", second)
                            .put("ms_after_tap", msAfterTap);
                })
                .needsTap()
                .timeout(12_000)
                .expect(lockdown("a read right after a real tap works, once (one tap backs one "
                        + "paste)", SRC_TAP, Outcome.VISIBLE)
                        .check((c, r) -> "null".equals(r.detail.get("second_read_1s")) ? null
                                : "second read 1 s after the same tap still got the clip ("
                                        + r.detail.get("second_read_1s") + ")")));
    }
}
