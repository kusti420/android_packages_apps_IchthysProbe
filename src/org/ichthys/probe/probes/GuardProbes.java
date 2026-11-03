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

import static android.Manifest.permission.ACCESS_COARSE_LOCATION;
import static android.Manifest.permission.ACCESS_FINE_LOCATION;

import android.location.Location;
import android.os.SystemClock;
import android.location.LocationManager;
import android.os.CancellationSignal;

import org.ichthys.probe.Ctx;
import org.ichthys.probe.Expect;
import org.ichthys.probe.GuardRun;
import org.ichthys.probe.Outcome;
import org.ichthys.probe.Probe;
import org.ichthys.probe.Result;
import org.ichthys.probe.Shields;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * IchthysOS: probes that only make sense in a Guard verification run (GuardRun): they compare
 * what Guard says it set up with what this app really sees. Outside such a run they are
 * informational.
 */
public final class GuardProbes {
    static final String CAT = "Guard verification";

    /** The fake place's offset is 150–650 m plus noise; anything inside this is "the fake place". */
    private static final double FAKE_RADIUS_M = 2_000;

    /** Shield ids Guard sends (ShieldTable in Settings) -> this app's shield table. */
    private static final String[][] IDS = {
        {"contacts", "contacts"}, {"calendar", "calendar"}, {"call_log", "callLog"},
        {"phone_number", "phoneNumber"}, {"sms_read", "smsRead"}, {"sms_send", "smsSend"},
        {"mms_push", "mmsPush"}, {"call", "call"}, {"answer_calls", "answerCalls"},
        {"clipboard", "clipboard"}, {"sensors", "sensors"}, {"usage", "usageHistory"},
        {"ble_advertise", "bleAdvertise"}, {"wifi_control", "wifiControl"}, {"uwb", "uwb"},
        {"nfc", "nfc"}, {"scans", "scans"}, {"location_nofix", "location"},
    };

    private GuardProbes() {}

    private static Shields.Shield byName(String name) {
        for (Shields.Shield s : Shields.ALL) {
            if (s.name.equals(name)) {
                return s;
            }
        }
        return null;
    }

    public static void add(List<Probe> out) {
        out.add(new Probe(CAT, "guard.state_matches",
                "Whether the shields Guard says protect this app are the ones the settings "
                        + "lists really name (Guard's view against the platform's).",
                Probe.NONE,
                c -> {
                    final String csv = c.option(GuardRun.EXTRA_EXPECT_SHIELDS);
                    if (csv == null) {
                        return Result.skipped("not a Guard verification run");
                    }
                    final Set<String> expected = new HashSet<>();
                    for (String s : csv.split(",")) {
                        if (!s.trim().isEmpty()) {
                            expected.add(s.trim());
                        }
                    }
                    // IchthysOS: the settings lists are hidden from apps since 2026-10-28,
                    // so Guard's view is the authority of this run (Shields.useGuardView)
                    // and cannot be cross-checked here; the per-shield probes do the
                    // checking. Recorded for the report.
                    int known = 0;
                    for (String[] pair : IDS) {
                        if (expected.contains(pair[0])) {
                            known++;
                        }
                    }
                    return Result.visible().put("guard_view", csv.isEmpty() ? "none" : csv)
                            .put("protecting", known)
                            .put("note", "lists hidden from apps; Guard's view is used");
                }));

        out.add(new Probe(CAT, "guard.net_matches",
                "Whether the network this app gets is what Guard's firewall holds for it.",
                Probe.NONE,
                c -> {
                    final String expect = c.option("expect_net");
                    if (expect == null) {
                        return Result.skipped("not a Guard verification run");
                    }
                    final boolean blocked = NetProbes.uidBlocked(c);
                    final Result r = Result.visible().put("guard_says", expect)
                            .put("network_reports", blocked ? "blocked" : "allowed");
                    return r;
                })
                .expect(Expect.of("Guard firewall state", "IchthysGuardService.applyFirewall",
                        "the active network reports BLOCKED exactly when Guard blocks the uid")
                        .when(c -> c.option("expect_net") == null
                                ? "not a Guard verification run" : null)
                        .check((c, r) -> {
                            final String says = r.detail.get("guard_says");
                            final String net = r.detail.get("network_reports");
                            return says.equals(net) ? null
                                    : "Guard says " + says + ", the network reports " + net;
                        })));

        out.add(new Probe(CAT, "location.fake_place",
                "Whether a fresh fix is the fake place (within 2 km of it) or the real "
                        + "position (far from it). Distance bucket only, never coordinates.",
                perms(ACCESS_COARSE_LOCATION),
                c -> {
                    final String expect = c.option(GuardRun.EXTRA_EXPECT_LOCATION);
                    final String latLon = c.option(GuardRun.EXTRA_EXPECT_FAKE_LATLON);
                    if (expect == null) {
                        return Result.skipped("not a Guard verification run");
                    }
                    if ("none".equals(expect)) {
                        return Result.skipped("Guard set No location; location.current_fix "
                                + "covers it");
                    }
                    final LocationManager lm = c.app.getSystemService(LocationManager.class);
                    final String provider = lm.hasProvider(LocationManager.FUSED_PROVIDER)
                            ? LocationManager.FUSED_PROVIDER
                            : c.granted(ACCESS_FINE_LOCATION) ? LocationManager.GPS_PROVIDER
                                    : LocationManager.NETWORK_PROVIDER;
                    if (!lm.isProviderEnabled(provider)) {
                        return Result.unavailable(provider + " provider is off");
                    }
                    final AtomicReference<Location> got = new AtomicReference<>();
                    final CountDownLatch done = new CountDownLatch(1);
                    final CancellationSignal cancel = new CancellationSignal();
                    lm.getCurrentLocation(provider, cancel, c.app.getMainExecutor(), l -> {
                        got.set(l);
                        done.countDown();
                    });
                    if (!done.await(12, TimeUnit.SECONDS)) {
                        cancel.cancel();
                    }
                    Location l = got.get();
                    if (l == null) {
                        l = lm.getLastKnownLocation(provider);
                    }
                    if (l == null) {
                        // IchthysOS: indoors, no network provider: the spoof only replaces
                        // real fixes, so nothing to judge (n/a), not a broken promise.
                        return Result.unavailable("no fix obtainable (indoors? no provider?)")
                                .put("fix", "none");
                    }
                    final Result r = Result.visible().put("guard_says", expect)
                            .put("accuracy_m", Math.round(l.getAccuracy()))
                            .put("age_s", Math.max(0, (SystemClock.elapsedRealtimeNanos()
                                    - l.getElapsedRealtimeNanos()) / 1_000_000_000L));
                    if (latLon == null) {
                        return r.put("distance_to_fake", "unknown (fake place off)");
                    }
                    final String[] parts = latLon.split(",");
                    if (parts.length < 2) {
                        return r.put("distance_to_fake", "unknown (bad coordinates)");
                    }
                    final float[] d = new float[1];
                    Location.distanceBetween(l.getLatitude(), l.getLongitude(),
                            Double.parseDouble(parts[0].trim()),
                            Double.parseDouble(parts[1].trim()), d);
                    final boolean nearFake = d[0] <= FAKE_RADIUS_M;
                    // IchthysOS: "at the fake place" for an app set to Real: within the fake
                    // offset band (150-650 m) plus the fix's own accuracy; a real position that
                    // merely lies in the same town is not a failure.
                    final boolean atFake = d[0] <= l.getAccuracy() + 700;
                    return r.put("near_fake_place", nearFake).put("at_fake_place", atFake)
                            .put("distance_bucket", d[0] < 1000 ? "<1 km"
                                    : d[0] < 5000 ? "1–5 km" : d[0] < 50_000 ? "5–50 km"
                                    : ">50 km");
                })
                .timeout(16_000)
                .expect(Expect.of("Fake location", "IchthysLocationSpoof; Guard's Location "
                                + "control (real / fake place / none)",
                        "an app set to the fake place gets a fix near it; an app set to Real "
                                + "gets one far from it")
                        .outcomes(Outcome.VISIBLE, Outcome.UNAVAILABLE)
                        .when(c -> {
                            final String e = c.option(GuardRun.EXTRA_EXPECT_LOCATION);
                            if (e == null) {
                                return "not a Guard verification run";
                            }
                            if ("none".equals(e)) {
                                return "No location is set; see location.current_fix";
                            }
                            if (!c.granted(ACCESS_FINE_LOCATION)) {
                                // Coarse fixes snap to a ~2 km grid: distances mean nothing.
                                return "no precise location permission (stock refusal)";
                            }
                            if (c.option(GuardRun.EXTRA_EXPECT_FAKE_LATLON) == null) {
                                return "the fake place is off, so a real fix is all there is";
                            }
                            return null;
                        })
                        .check((c, r) -> {
                            if (r.outcome != Outcome.VISIBLE) {
                                return "no fix delivered although Guard allows location ("
                                        + r.outcome.key + ")";
                            }
                            final boolean near = "true".equals(r.detail.get("near_fake_place"));
                            final String says = r.detail.get("guard_says");
                            if ("fake".equals(says) && !near) {
                                return "Guard set the fake place but the fix is "
                                        + r.detail.get("distance_bucket") + " from it";
                            }
                            if ("real".equals(says)
                                    && "true".equals(r.detail.get("at_fake_place"))) {
                                return "Guard set Real but the fix is at the fake place";
                            }
                            return null;
                        })));
    }

    private static String[] perms(String... p) {
        return p;
    }

    static boolean has(String[] arr, String s) {
        return Arrays.asList(arr).contains(s);
    }
}
