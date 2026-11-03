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

import static android.Manifest.permission.ACCESS_BACKGROUND_LOCATION;
import static android.Manifest.permission.ACCESS_COARSE_LOCATION;
import static android.Manifest.permission.ACCESS_FINE_LOCATION;

import static org.ichthys.probe.Probe.perms;

import android.location.GnssStatus;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.location.OnNmeaMessageListener;
import android.os.CancellationSignal;
import android.os.SystemClock;

import org.ichthys.probe.Ctx;
import org.ichthys.probe.Expect;
import org.ichthys.probe.Outcome;
import org.ichthys.probe.Probe;
import org.ichthys.probe.Redact;
import org.ichthys.probe.Result;
import org.ichthys.probe.Shields;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Location: last known, a fresh fix, providers, GNSS status and NMEA. Never coordinates. */
public final class LocationProbes {
    static final String CAT = "Location";

    static final String SRC_NOFIX =
            "frameworks/base/services/core/java/com/android/server/location/"
                    + "IchthysLocationNoFix.java; provider/LocationProviderManager.java:960-962,"
                    + "1376-1380,1854-1857; gnss/GnssNmeaProvider.java:107; "
                    + "IchthysShields.LOCATION (\"never get a location fix, as if indoors\")";

    private LocationProbes() {}

    /** Expectation: an app on the "No location" list gets no fix, whatever it holds. */
    static Expect noFix(String promise) {
        return noFix(promise, ACCESS_COARSE_LOCATION);
    }

    static Expect noFix(String promise, String permission) {
        return Expect.of("Location shield (No location list)", SRC_NOFIX, promise)
                .outcomes(Outcome.EMPTY, Outcome.BLOCKED_ICHTHYS)
                .when(c -> !c.granted(permission)
                        ? "no " + permission.substring(permission.lastIndexOf('.') + 1)
                                + " (stock refusal)"
                        : c.shields.notProtecting(Shields.LOCATION));
    }

    /** "Empty" from a location probe becomes blocked-by-IchthysOS when the shield lists us. */
    static Result markNoFix(Ctx c, Result r) {
        if (r.outcome == Outcome.EMPTY && c.shields.protects(Shields.LOCATION)) {
            final Result b = Result.blockedIchthys("on ichthys_location_nofix_pkgs");
            b.detail.putAll(r.detail);
            return b;
        }
        return r;
    }

    static String describe(Location l) {
        final StringBuilder sb = new StringBuilder();
        sb.append("fix, provider=").append(l.getProvider());
        if (l.hasAccuracy()) {
            sb.append(", accuracy ").append(Math.round(l.getAccuracy())).append(" m");
        }
        final long ageMs = (SystemClock.elapsedRealtimeNanos() - l.getElapsedRealtimeNanos())
                / 1_000_000L;
        sb.append(", age ").append(Redact.age(ageMs));
        sb.append(", altitude=").append(l.hasAltitude() ? "yes" : "no");
        sb.append(", speed=").append(l.hasSpeed() ? "yes" : "no");
        sb.append(", mock=").append(l.isMock());
        return sb.toString();
    }

    public static void add(List<Probe> out) {
        out.add(new Probe(CAT, "location.permission_state",
                "Which location grants the app holds (fine, approximate, all the time).",
                perms(ACCESS_COARSE_LOCATION),
                c -> {
                    final LocationManager lm = c.app.getSystemService(LocationManager.class);
                    return Result.visible()
                            .put("fine", c.granted(ACCESS_FINE_LOCATION))
                            .put("coarse", c.granted(ACCESS_COARSE_LOCATION))
                            .put("background", c.granted(ACCESS_BACKGROUND_LOCATION))
                            .put("location_on", lm.isLocationEnabled());
                }));

        out.add(new Probe(CAT, "location.providers",
                "Which location providers exist and are on (no permission needed).",
                Probe.NONE,
                c -> {
                    final LocationManager lm = c.app.getSystemService(LocationManager.class);
                    final List<String> all = lm.getAllProviders();
                    final List<String> on = lm.getProviders(true);
                    return Result.count("providers", all.size())
                            .put("all", String.join("/", all))
                            .put("enabled", String.join("/", on))
                            .put("gnss_hw", String.valueOf(lm.getGnssHardwareModelName() != null));
                }));

        out.add(new Probe(CAT, "location.last_known",
                "The last fix any app got, per provider (no fresh request needed).",
                perms(ACCESS_COARSE_LOCATION),
                c -> {
                    final LocationManager lm = c.app.getSystemService(LocationManager.class);
                    int found = 0;
                    final Result r = Result.visible();
                    for (String p : lm.getAllProviders()) {
                        final Location l = lm.getLastKnownLocation(p);
                        if (l != null) {
                            found++;
                            r.put(p, describe(l));
                        } else {
                            r.put(p, "none");
                        }
                    }
                    if (found == 0) {
                        final Result e = Result.empty();
                        e.detail.putAll(r.detail);
                        return markNoFix(c, e);
                    }
                    return r;
                })
                .expect(noFix("getLastKnownLocation returns null for a listed app")));

        out.add(new Probe(CAT, "location.current_fix",
                "A fresh fix within 12 s (accuracy and provider only, never coordinates).",
                perms(ACCESS_COARSE_LOCATION),
                c -> {
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
                    final boolean answered = done.await(12, TimeUnit.SECONDS);
                    if (!answered) {
                        cancel.cancel();
                    }
                    final Location l = got.get();
                    if (l == null) {
                        return markNoFix(c, Result.empty().put("provider", provider)
                                .put("fix", answered ? "null" : "none within 12 s"));
                    }
                    return Result.visible().put("fix", describe(l));
                })
                .timeout(16_000)
                .expect(noFix("a listed app never gets a fresh fix (getCurrentLocation null)")));

        out.add(new Probe(CAT, "location.updates",
                "Fixes delivered to a GPS listener within 10 s.",
                perms(ACCESS_FINE_LOCATION),
                c -> {
                    final LocationManager lm = c.app.getSystemService(LocationManager.class);
                    if (!lm.isProviderEnabled(LocationManager.GPS_PROVIDER)) {
                        return Result.unavailable("gps provider is off");
                    }
                    final AtomicInteger n = new AtomicInteger();
                    final LocationListener l = loc -> n.incrementAndGet();
                    lm.requestLocationUpdates(LocationManager.GPS_PROVIDER, 1000, 0, l,
                            c.worker.getLooper());
                    Ctx.sleep(10_000);
                    lm.removeUpdates(l);
                    if (n.get() == 0) {
                        return markNoFix(c, Result.empty().put("fixes", 0));
                    }
                    return Result.visible().put("fixes", n.get());
                })
                .timeout(14_000)
                .expect(noFix("requestLocationUpdates never delivers a fix to a listed app",
                        ACCESS_FINE_LOCATION)));

        out.add(new Probe(CAT, "location.gnss_status",
                "Satellites in view and their signal (a coarse location side channel).",
                perms(ACCESS_FINE_LOCATION),
                c -> {
                    final LocationManager lm = c.app.getSystemService(LocationManager.class);
                    final AtomicInteger sats = new AtomicInteger(-1);
                    final GnssStatus.Callback cb = new GnssStatus.Callback() {
                        @Override
                        public void onSatelliteStatusChanged(GnssStatus status) {
                            sats.set(status.getSatelliteCount());
                        }
                    };
                    if (!lm.registerGnssStatusCallback(c.app.getMainExecutor(), cb)) {
                        return Result.empty().put("registered", false);
                    }
                    Ctx.sleep(6000);
                    lm.unregisterGnssStatusCallback(cb);
                    if (sats.get() < 0) {
                        return Result.empty().put("callbacks", 0);
                    }
                    return Result.visible().put("satellites", sats.get())
                            .put("note", "not gated by the No-location shield");
                })
                .timeout(10_000));

        out.add(new Probe(CAT, "location.nmea",
                "Raw NMEA sentences from the GNSS chip within 6 s (count only).",
                perms(ACCESS_FINE_LOCATION),
                c -> {
                    final LocationManager lm = c.app.getSystemService(LocationManager.class);
                    final AtomicInteger n = new AtomicInteger();
                    final OnNmeaMessageListener l = (msg, ts) -> n.incrementAndGet();
                    final CountDownLatch reg = new CountDownLatch(1);
                    final boolean[] ok = new boolean[1];
                    final AtomicReference<SecurityException> denied = new AtomicReference<>();
                    c.main.post(() -> {
                        try {
                            ok[0] = lm.addNmeaListener(c.app.getMainExecutor(), l);
                        } catch (SecurityException e) {
                            denied.set(e);
                        } finally {
                            reg.countDown();
                        }
                    });
                    reg.await(2, TimeUnit.SECONDS);
                    if (denied.get() != null) {
                        return Result.fromSecurity(denied.get());
                    }
                    Ctx.sleep(6000);
                    lm.removeNmeaListener(l);
                    if (n.get() == 0) {
                        return markNoFix(c, Result.empty().put("registered", ok[0])
                                .put("sentences", 0));
                    }
                    return Result.visible().put("sentences", n.get());
                })
                .timeout(10_000)
                .expect(noFix("NMEA is suppressed for a listed app", ACCESS_FINE_LOCATION)));
    }
}
