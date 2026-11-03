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

import static android.Manifest.permission.ACTIVITY_RECOGNITION;
import static android.Manifest.permission.BODY_SENSORS;

import static org.ichthys.probe.Probe.perms;

import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.os.SystemClock;

import org.ichthys.probe.Ctx;
import org.ichthys.probe.Expect;
import org.ichthys.probe.Outcome;
import org.ichthys.probe.Probe;
import org.ichthys.probe.Redact;
import org.ichthys.probe.Result;
import org.ichthys.probe.Shields;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Sensors: the list and its identifying fields, sampling rates and value precision. The
 * IchthysOS sensor shield promises a generic list, capped rates and rounded values so that the
 * sensors can't identify the phone.
 */
public final class SensorProbes {
    static final String CAT = "Sensors";

    private static final String SRC_SENSORS =
            "frameworks/native/services/sensorservice/SensorService.cpp:1580-1588,2895-2967,"
                    + "3021-3041; SensorService.h:83 (ICHTHYS_FP_SAMPLING_PERIOD_NS 20 ms); "
                    + "SensorEventConnection.cpp:405-519,782-841; IchthysShields.SENSORS "
                    + "(\"generic sensor list, capped rates and rounded values\")";

    /** 50 Hz cap plus slack for timer jitter. */
    private static final double RATE_CAP_HZ = 56;

    private SensorProbes() {}

    private static Expect shield(String promise, Expect.Check check) {
        return Expect.of("Sensor shield", SRC_SENSORS, promise)
                .when(c -> c.shields.notProtecting(Shields.SENSORS))
                .check(check);
    }

    /** What one sampling run measured. */
    static final class Sample {
        int events;
        double hz;
        final List<float[]> values = new ArrayList<>();
        boolean registered;
    }

    static Sample sample(Ctx c, Sensor s, int periodUs, long ms) {
        final SensorManager sm = c.app.getSystemService(SensorManager.class);
        final Sample out = new Sample();
        final long[] first = {0};
        final long[] last = {0};
        final SensorEventListener l = new SensorEventListener() {
            @Override
            public void onSensorChanged(SensorEvent e) {
                synchronized (out) {
                    if (out.events == 0) {
                        first[0] = e.timestamp;
                    }
                    last[0] = e.timestamp;
                    out.events++;
                    if (out.values.size() < 200) {
                        out.values.add(e.values.clone());
                    }
                }
            }

            @Override
            public void onAccuracyChanged(Sensor sensor, int accuracy) {}
        };
        out.registered = sm.registerListener(l, s, periodUs, c.worker);
        if (out.registered) {
            final long end = SystemClock.elapsedRealtime() + ms;
            while (SystemClock.elapsedRealtime() < end) {
                Ctx.sleep(50);
            }
            sm.unregisterListener(l);
        }
        synchronized (out) {
            if (out.events > 1 && last[0] > first[0]) {
                out.hz = (out.events - 1) * 1e9 / (last[0] - first[0]);
            }
        }
        return out;
    }

    /** Largest distance of any value from a multiple of {@code step}, in steps (0 = exact). */
    static double gridError(List<float[]> values, double step) {
        double worst = 0;
        for (float[] v : values) {
            for (int i = 0; i < Math.min(3, v.length); i++) {
                final double k = v[i] / step;
                worst = Math.max(worst, Math.abs(k - Math.rint(k)));
            }
        }
        return worst;
    }

    /** Smallest non-zero difference between successive values of axis 0. */
    static double smallestStep(List<float[]> values) {
        final TreeSet<Float> distinct = new TreeSet<>();
        for (float[] v : values) {
            distinct.add(v[0]);
        }
        double min = Double.MAX_VALUE;
        Float prev = null;
        for (Float f : distinct) {
            if (prev != null) {
                min = Math.min(min, f - prev);
            }
            prev = f;
        }
        return min == Double.MAX_VALUE ? 0 : min;
    }

    private static Probe motion(String id, int type, String name, double step) {
        return new Probe(CAT, id,
                name + ": fastest delivered rate and value precision (fingerprinting inputs).",
                Probe.NONE,
                c -> {
                    final SensorManager sm = c.app.getSystemService(SensorManager.class);
                    final Sensor s = sm.getDefaultSensor(type);
                    if (s == null) {
                        return Result.unavailable("no " + name);
                    }
                    final Sample a = sample(c, s, SensorManager.SENSOR_DELAY_FASTEST, 2000);
                    if (!a.registered) {
                        return Result.blockedPermission("registerListener returned false");
                    }
                    if (a.events == 0) {
                        return Result.empty().put("events", 0);
                    }
                    final Result r = Result.visible()
                            .put("rate_hz", String.format("%.1f", a.hz))
                            .put("events_2s", a.events)
                            .put("min_delay_us", s.getMinDelay())
                            .put("grid_error_steps", String.format("%.3f", gridError(a.values,
                                    step)))
                            .put("smallest_step", String.format("%.5f", smallestStep(a.values)));
                    r.put("_step", String.valueOf(step));
                    return r;
                })
                .timeout(6000)
                .expect(shield("rate capped at 50 Hz, values rounded to a " + step + " grid",
                        (c, r) -> {
                            if (r.outcome != Outcome.VISIBLE) {
                                return r.outcome == Outcome.UNAVAILABLE ? null
                                        : "no events to check (" + r.outcome.key + ")";
                            }
                            final double hz = Double.parseDouble(r.detail.get("rate_hz"));
                            if (hz > RATE_CAP_HZ) {
                                return "rate " + r.detail.get("rate_hz")
                                        + " Hz above the 50 Hz cap";
                            }
                            final double err = Double.parseDouble(
                                    r.detail.get("grid_error_steps"));
                            if (err > 0.05) {
                                return "values are not on the " + step + " grid (error "
                                        + r.detail.get("grid_error_steps") + " steps)";
                            }
                            return null;
                        }));
    }

    public static void add(List<Probe> out) {
        out.add(new Probe(CAT, "sensors.list",
                "The sensor list: types, names, vendors, versions (hashes of the name strings).",
                Probe.NONE,
                c -> {
                    final SensorManager sm = c.app.getSystemService(SensorManager.class);
                    final List<Sensor> all = sm.getSensorList(Sensor.TYPE_ALL);
                    final Set<String> vendors = new TreeSet<>();
                    final Set<Integer> types = new TreeSet<>();
                    final StringBuilder names = new StringBuilder();
                    for (Sensor s : all) {
                        vendors.add(s.getVendor());
                        types.add(s.getType());
                        names.append(s.getName()).append('|');
                    }
                    final Sensor acc = sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER);
                    final Result r = Result.count("sensors", all.size())
                            .put("types", types.size())
                            .put("vendors", vendors.size())
                            .put("vendor_set", Redact.hash(vendors.toString()))
                            .put("names", Redact.hash(names.toString()))
                            .put("accel_uncalibrated_listed", sm.getDefaultSensor(
                                    Sensor.TYPE_ACCELEROMETER_UNCALIBRATED) != null)
                            .put("gyro_uncalibrated_listed", sm.getDefaultSensor(
                                    Sensor.TYPE_GYROSCOPE_UNCALIBRATED) != null)
                            .put("mag_uncalibrated_listed", sm.getDefaultSensor(
                                    Sensor.TYPE_MAGNETIC_FIELD_UNCALIBRATED) != null);
                    if (acc != null) {
                        // Generic values are not identifying: record them as they are.
                        final boolean generic = "Android".equals(acc.getVendor());
                        r.put("accel_vendor", generic ? "Android" : Redact.text(acc.getVendor()));
                        r.put("accel_name", generic ? acc.getName() : Redact.text(acc.getName()));
                        r.put("accel_version", acc.getVersion());
                        r.put("accel_min_delay_us", acc.getMinDelay());
                    }
                    return r;
                })
                .expect(shield("generic accelerometer identity (vendor \"Android\", name "
                        + "\"Accelerometer\", version 1, min delay >= 20000 us) and no "
                        + "uncalibrated motion sensors",
                        (c, r) -> {
                            if (!"Android".equals(r.detail.get("accel_vendor"))) {
                                return "accelerometer vendor is the real one ("
                                        + r.detail.get("accel_vendor") + ")";
                            }
                            if (!"Accelerometer".equals(r.detail.get("accel_name"))) {
                                return "accelerometer name not generic";
                            }
                            if (!"1".equals(r.detail.get("accel_version"))) {
                                return "accelerometer version " + r.detail.get("accel_version");
                            }
                            final String md = r.detail.get("accel_min_delay_us");
                            if (md != null && Integer.parseInt(md) < 20000) {
                                return "accelerometer min delay " + md + " us < 20000";
                            }
                            if ("true".equals(r.detail.get("accel_uncalibrated_listed"))
                                    || "true".equals(r.detail.get("gyro_uncalibrated_listed"))
                                    || "true".equals(r.detail.get("mag_uncalibrated_listed"))) {
                                return "uncalibrated motion sensors are listed";
                            }
                            return null;
                        })));

        out.add(motion("sensors.accelerometer", Sensor.TYPE_ACCELEROMETER, "Accelerometer",
                0.02));
        out.add(motion("sensors.gyroscope", Sensor.TYPE_GYROSCOPE, "Gyroscope", 0.002));
        out.add(motion("sensors.magnetometer", Sensor.TYPE_MAGNETIC_FIELD, "Magnetometer",
                0.25));

        out.add(new Probe(CAT, "sensors.uncalibrated_register",
                "Whether an uncalibrated accelerometer (raw bias, a strong fingerprint) delivers.",
                Probe.NONE,
                c -> {
                    final SensorManager sm = c.app.getSystemService(SensorManager.class);
                    final List<Sensor> l = sm.getSensorList(Sensor.TYPE_ACCELEROMETER_UNCALIBRATED);
                    if (l.isEmpty()) {
                        return c.shields.protects(Shields.SENSORS)
                                ? Result.blockedIchthys("hidden from the sensor list")
                                : Result.unavailable("not on this device");
                    }
                    final Sample s = sample(c, l.get(0), SensorManager.SENSOR_DELAY_GAME, 1000);
                    return s.events > 0 ? Result.visible().put("events_1s", s.events)
                            : Result.empty().put("registered", s.registered);
                })
                .timeout(5000)
                .expect(Expect.of("Sensor shield", SRC_SENSORS,
                        "uncalibrated accelerometer is hidden and refused")
                        .outcomes(Outcome.BLOCKED_ICHTHYS, Outcome.EMPTY)
                        .when(c -> c.shields.notProtecting(Shields.SENSORS))));

        out.add(new Probe(CAT, "sensors.light",
                "Ambient light level (coarse) and rate: reveals room lighting and screen use.",
                Probe.NONE,
                c -> environmental(c, Sensor.TYPE_LIGHT, "lux")));

        out.add(new Probe(CAT, "sensors.proximity",
                "Proximity sensor: reveals when the phone is at the ear or in a pocket.",
                Probe.NONE,
                c -> environmental(c, Sensor.TYPE_PROXIMITY, "cm")));

        out.add(new Probe(CAT, "sensors.pressure",
                "Barometer: altitude and floor level.",
                Probe.NONE,
                c -> environmental(c, Sensor.TYPE_PRESSURE, "hPa")));

        out.add(new Probe(CAT, "sensors.step_counter",
                "Steps since boot (activity recognition).",
                perms(ACTIVITY_RECOGNITION),
                c -> {
                    final SensorManager sm = c.app.getSystemService(SensorManager.class);
                    final Sensor s = sm.getDefaultSensor(Sensor.TYPE_STEP_COUNTER);
                    if (s == null) {
                        return Result.unavailable("no step counter");
                    }
                    final Sample a = sample(c, s, SensorManager.SENSOR_DELAY_NORMAL, 2500);
                    if (!a.registered) {
                        return Result.blockedPermission("registerListener returned false");
                    }
                    return a.values.isEmpty() ? Result.empty().put("events", 0)
                            : Result.visible().put("steps", Redact.bucket(
                                    (long) a.values.get(0)[0]));
                })
                .timeout(6000));

        out.add(new Probe(CAT, "sensors.heart_rate",
                "Heart-rate sensor presence and whether it delivers (body sensors).",
                perms(BODY_SENSORS),
                c -> {
                    final SensorManager sm = c.app.getSystemService(SensorManager.class);
                    final Sensor s = sm.getDefaultSensor(Sensor.TYPE_HEART_RATE);
                    if (s == null) {
                        return Result.unavailable("no heart-rate sensor");
                    }
                    final Sample a = sample(c, s, SensorManager.SENSOR_DELAY_NORMAL, 2000);
                    return !a.registered ? Result.blockedPermission("registerListener false")
                            : Result.count("events", a.events);
                })
                .timeout(5000));
    }

    private static Result environmental(Ctx c, int type, String unit) {
        final SensorManager sm = c.app.getSystemService(SensorManager.class);
        final Sensor s = sm.getDefaultSensor(type);
        if (s == null) {
            return Result.unavailable("no sensor");
        }
        final Sample a = sample(c, s, SensorManager.SENSOR_DELAY_FASTEST, 1500);
        if (!a.registered) {
            return Result.blockedPermission("registerListener returned false");
        }
        if (a.values.isEmpty()) {
            return Result.empty().put("events", 0);
        }
        return Result.visible()
                .put("events_1_5s", a.events)
                .put("rate_hz", String.format("%.1f", a.hz))
                .put("value_" + unit, Redact.bucket(Math.round(a.values.get(0)[0])))
                .put("vendor", "Android".equals(s.getVendor()) ? "Android"
                        : Redact.text(s.getVendor()));
    }
}
