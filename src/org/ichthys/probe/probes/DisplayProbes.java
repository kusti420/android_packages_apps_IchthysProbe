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

import android.app.ActivityOptions;
import android.content.Intent;
import android.hardware.display.DisplayManager;
import android.view.Display;

import org.ichthys.probe.Ctx;
import org.ichthys.probe.Expect;
import org.ichthys.probe.Outcome;
import org.ichthys.probe.Probe;
import org.ichthys.probe.Redact;
import org.ichthys.probe.Result;
import org.ichthys.probe.TargetActivity;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Displays, including IchthysOS Backstage's hidden displays. Backstage keeps each hidden app
 * on its own private virtual display ("IchthysBackstage", created by system_server without
 * VIRTUAL_DISPLAY_FLAG_PUBLIC); an ordinary app must neither see nor reach it.
 */
public final class DisplayProbes {
    static final String CAT = "Display & Backstage";

    static final String SRC_BACKSTAGE =
            "frameworks/base/services/core/java/com/android/server/IchthysBackstageService.java"
                    + ":842-855 (private virtual display \"IchthysBackstage\": TRUSTED, "
                    + "OWN_DISPLAY_GROUP, OWN_FOCUS, no PUBLIC flag; one per hidden app, only "
                    + "while hidden)";

    private DisplayProbes() {}

    static Set<Integer> visibleIds(Ctx c) {
        final Set<Integer> ids = new HashSet<>();
        for (Display d : c.app.getSystemService(DisplayManager.class).getDisplays()) {
            ids.add(d.getDisplayId());
        }
        return ids;
    }

    public static void add(List<Probe> out) {
        out.add(new Probe(CAT, "display.list",
                "Displays the app can enumerate: count, names, flags, size and refresh rates.",
                Probe.NONE,
                c -> {
                    final DisplayManager dm = c.app.getSystemService(DisplayManager.class);
                    final Display[] all = dm.getDisplays();
                    final Result r = Result.count("displays", all.length);
                    boolean backstage = false;
                    for (Display d : all) {
                        final String name = String.valueOf(d.getName());
                        backstage |= name.toLowerCase().contains("backstage");
                        final Display.Mode m = d.getMode();
                        r.put("display" + d.getDisplayId(), name + ", flags=0x"
                                + Integer.toHexString(d.getFlags()) + ", " + m.getPhysicalWidth()
                                + "x" + m.getPhysicalHeight() + ", modes="
                                + d.getSupportedModes().length + ", state=" + d.getState());
                    }
                    final Display main = dm.getDisplay(Display.DEFAULT_DISPLAY);
                    r.put("hdr_types", main.getHdrCapabilities() == null ? 0
                            : main.getHdrCapabilities().getSupportedHdrTypes().length);
                    r.put("cutout", main.getCutout() != null);
                    r.put("backstage_listed", backstage);
                    return r;
                })
                .expect(Expect.of("Backstage hidden display", SRC_BACKSTAGE,
                        "the Backstage display is not listed to apps")
                        .check((c, r) -> "true".equals(r.detail.get("backstage_listed"))
                                ? "a display named Backstage is listed" : null)));

        out.add(new Probe(CAT, "display.id_scan",
                "Display ids 1-64 that resolve with getDisplay() although getDisplays() hid them.",
                Probe.NONE,
                c -> {
                    final DisplayManager dm = c.app.getSystemService(DisplayManager.class);
                    final Set<Integer> visible = visibleIds(c);
                    int hiddenButResolvable = 0;
                    boolean backstage = false;
                    for (int id = 1; id <= 64; id++) {
                        if (visible.contains(id)) {
                            continue;
                        }
                        final Display d = dm.getDisplay(id);
                        if (d != null) {
                            hiddenButResolvable++;
                            backstage |= String.valueOf(d.getName()).toLowerCase()
                                    .contains("backstage");
                        }
                    }
                    final Result r = hiddenButResolvable == 0
                            ? Result.blockedPermission("no unlisted display resolves")
                            : Result.visible();
                    return r.put("unlisted_resolvable", hiddenButResolvable)
                            .put("backstage_resolvable", backstage);
                })
                .expect(Expect.of("Backstage hidden display", SRC_BACKSTAGE,
                        "no unlisted display (Backstage) can be looked up by id")
                        .outcomes(Outcome.BLOCKED_PERMISSION)));

        out.add(new Probe(CAT, "display.launch_scan",
                "Whether the app can start its own activity on an unlisted display id (1-16).",
                Probe.NONE,
                c -> {
                    final Set<Integer> visible = visibleIds(c);
                    int refused = 0;
                    int landed = 0;
                    int fellBack = 0;
                    for (int id = 1; id <= 16; id++) {
                        if (visible.contains(id)) {
                            continue;
                        }
                        TargetActivity.reset();
                        final int target = id;
                        final AtomicReference<Throwable> err = new AtomicReference<>();
                        c.onMain(() -> {
                            try {
                                final ActivityOptions o = ActivityOptions.makeBasic()
                                        .setLaunchDisplayId(target);
                                c.activity.startActivity(new Intent(c.app, TargetActivity.class)
                                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                                                | Intent.FLAG_ACTIVITY_MULTIPLE_TASK),
                                        o.toBundle());
                            } catch (Throwable t) {
                                err.set(t);
                            }
                        }, 2000);
                        if (err.get() != null) {
                            refused++;
                            continue;
                        }
                        final int shown = TargetActivity.awaitDisplay(1500);
                        if (shown == target) {
                            landed++;
                        } else if (shown < 0) {
                            refused++;
                        } else {
                            fellBack++;
                        }
                    }
                    final Result r = landed > 0 ? Result.visible() : Result.blockedPermission(
                            "every unlisted id refused or fell back to a visible display");
                    return r.put("refused", refused).put("landed_on_unlisted", landed)
                            .put("fell_back", fellBack);
                })
                .timeout(45_000)
                .expect(Expect.of("Backstage hidden display", SRC_BACKSTAGE,
                        "the Backstage display is not reachable: launches onto it are refused")
                        .outcomes(Outcome.BLOCKED_PERMISSION)));

        out.add(new Probe(CAT, "display.backstage_list",
                "Which apps are in Backstage (Secure ichthys_backstage_pkgs; count only).",
                Probe.NONE,
                c -> {
                    final org.ichthys.probe.Shields.Read r =
                            c.shields.read("ichthys_backstage_pkgs", false);
                    if (!r.readable) {
                        return Result.blockedPermission(r.error);
                    }
                    if (r.value == null || r.value.trim().isEmpty()) {
                        // IchthysOS hides the key from apps as absent (an error would itself give
                        // the OS away): judge it with an app in Backstage, then empty is a pass.
                        return Result.empty().put("readable", true).put("entries", 0);
                    }
                    return Result.visible().put("entries", r.value.split(",").length)
                            .put("value", Redact.length(r.value));
                })
                .expect(Expect.of("Backstage privacy",
                        "services.md B11-B13 / services-fixes.md \"Not done\": "
                                + "ichthys_backstage_pkgs is an undeclared Secure key, readable by"
                                + " every app (SettingsProvider.java:2666)",
                        "other apps can't find out which apps are kept in Backstage")
                        .outcomes(Outcome.BLOCKED_PERMISSION, Outcome.BLOCKED_ICHTHYS,
                                Outcome.EMPTY)
                        // IchthysOS: an empty list proves nothing either way (the service
                        // clears it at every boot), and a fix may hide the value instead of
                        // refusing the read. Only judge it with an app in Backstage.
                        .when(c -> {
                            final org.ichthys.probe.Shields.Read r =
                                    c.shields.read("ichthys_backstage_pkgs", false);
                            return r.readable && (r.value == null || r.value.trim().isEmpty())
                                    ? "nothing in Backstage (cleared at boot); send an app to "
                                            + "Backstage and run again"
                                    : null;
                        })));
    }
}
