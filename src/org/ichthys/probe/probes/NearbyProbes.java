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

import static android.Manifest.permission.ACCESS_FINE_LOCATION;
import static android.Manifest.permission.BLUETOOTH_ADVERTISE;
import static android.Manifest.permission.BLUETOOTH_CONNECT;
import static android.Manifest.permission.BLUETOOTH_SCAN;
import static android.Manifest.permission.NEARBY_WIFI_DEVICES;
import static android.Manifest.permission.UWB_RANGING;

import static org.ichthys.probe.Probe.perms;

import android.annotation.SuppressLint;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.AdvertiseCallback;
import android.bluetooth.le.AdvertiseData;
import android.bluetooth.le.AdvertiseSettings;
import android.bluetooth.le.BluetoothLeAdvertiser;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanResult;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.net.wifi.ScanResult.InformationElement;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.nfc.NfcAdapter;

import org.ichthys.probe.Ctx;
import org.ichthys.probe.Expect;
import org.ichthys.probe.Outcome;
import org.ichthys.probe.Probe;
import org.ichthys.probe.Redact;
import org.ichthys.probe.Result;
import org.ichthys.probe.Shields;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** Bluetooth, Wi-Fi, UWB and NFC: what the radios reveal about the surroundings. */
@SuppressLint("MissingPermission")
public final class NearbyProbes {
    static final String CAT_BT = "Bluetooth";
    static final String CAT_WIFI = "Wi-Fi";
    static final String CAT_OTHER = "UWB & NFC";

    private static final String SRC_SCANS =
            "packages/modules/Wifi/service/java/com/android/server/wifi/util/"
                    + "IchthysRadioPolicy.java (WifiServiceImpl getScanResults :5391); "
                    + "packages/modules/Bluetooth/android/app/src/com/android/bluetooth/ichthys/"
                    + "RadioPolicy.java (ScanController :372,653,690,757; AdapterService :2843,"
                    + "5502); IchthysShields.SCANS + LOCATION (M2: \"never get a location\" also "
                    + "covers scans)";
    private static final String SRC_ADVERTISE =
            "packages/modules/Bluetooth/android/app/src/com/android/bluetooth/ichthys/"
                    + "RadioPolicy.java; gatt/AdvertiseManager.java:290-297 "
                    + "(ADVERTISE_FAILED_FEATURE_UNSUPPORTED); IchthysShields.BLE_ADVERTISE";
    private static final String SRC_UWB =
            "packages/modules/Uwb/service/java/com/android/server/uwb/IchthysRangingPolicy.java;"
                    + " UwbServiceImpl.openRanging :349-360; IchthysShields.UWB";
    private static final String SRC_NFC =
            "packages/modules/Nfc/NfcNci/src/com/android/nfc/IchthysNfcPolicy.java; "
                    + "IchthysShields.NFC";

    private NearbyProbes() {}

    /** Scans find nothing for an app on the scan list or the No-location list. */
    private static Expect scanShield(String promise, String permission) {
        return Expect.of("Scan shield / No-location shield", SRC_SCANS, promise)
                .outcomes(Outcome.EMPTY, Outcome.BLOCKED_ICHTHYS)
                .when(c -> {
                    if (!c.granted(permission)) {
                        return "permission not granted";
                    }
                    if (c.shields.protects(Shields.SCANS)
                            || c.shields.protects(Shields.LOCATION)) {
                        return null;
                    }
                    return "app is on neither ichthys_scan_empty_pkgs nor "
                            + "ichthys_location_nofix_pkgs";
                });
    }

    private static Result markScan(Ctx c, Result r) {
        if (r.outcome == Outcome.EMPTY && (c.shields.protects(Shields.SCANS)
                || c.shields.protects(Shields.LOCATION))) {
            final Result b = Result.blockedIchthys("scan/No-location list");
            b.detail.putAll(r.detail);
            return b;
        }
        return r;
    }

    private static BluetoothAdapter adapter(Ctx c) {
        final BluetoothManager bm = c.app.getSystemService(BluetoothManager.class);
        return bm == null ? null : bm.getAdapter();
    }

    public static void add(List<Probe> out) {
        // ---- Bluetooth ----
        out.add(new Probe(CAT_BT, "bt.adapter",
                "Whether Bluetooth exists and is on (no permission needed).",
                Probe.NONE,
                c -> {
                    final BluetoothAdapter a = adapter(c);
                    if (a == null) {
                        return Result.unavailable("no Bluetooth");
                    }
                    return Result.visible().put("enabled", a.isEnabled())
                            .put("le_supported", c.hasFeature(PackageManager.FEATURE_BLUETOOTH_LE));
                }));

        out.add(new Probe(CAT_BT, "bt.identity",
                "The phone's Bluetooth name (often the owner's name) and MAC address.",
                perms(BLUETOOTH_CONNECT),
                c -> {
                    final BluetoothAdapter a = adapter(c);
                    if (a == null) {
                        return Result.unavailable("no Bluetooth");
                    }
                    final String name = a.getName();
                    final String mac = a.getAddress();
                    final boolean masked = mac == null || "02:00:00:00:00:00".equals(mac);
                    return Result.visible().put("name", Redact.text(name))
                            .put("mac", masked ? "masked (02:00:00:00:00:00)" : Redact.text(mac));
                }));

        out.add(new Probe(CAT_BT, "bt.bonded",
                "Paired Bluetooth devices (count and device classes).",
                perms(BLUETOOTH_CONNECT),
                c -> {
                    final BluetoothAdapter a = adapter(c);
                    if (a == null) {
                        return Result.unavailable("no Bluetooth");
                    }
                    final Set<BluetoothDevice> bonded = a.getBondedDevices();
                    if (bonded == null || bonded.isEmpty()) {
                        return Result.empty().put("paired", 0);
                    }
                    final Set<Integer> classes = new HashSet<>();
                    for (BluetoothDevice d : bonded) {
                        if (d.getBluetoothClass() != null) {
                            classes.add(d.getBluetoothClass().getMajorDeviceClass());
                        }
                    }
                    return Result.visible().put("paired", bonded.size())
                            .put("major_classes", classes.size());
                }));

        out.add(new Probe(CAT_BT, "bt.le_scan",
                "BLE devices around the phone in 6 s (distinct device count).",
                perms(BLUETOOTH_SCAN),
                c -> {
                    final BluetoothAdapter a = adapter(c);
                    if (a == null || !a.isEnabled()) {
                        return Result.unavailable("Bluetooth off or missing");
                    }
                    final BluetoothLeScanner s = a.getBluetoothLeScanner();
                    if (s == null) {
                        return Result.unavailable("no LE scanner");
                    }
                    final Set<String> seen = new HashSet<>();
                    final AtomicInteger failed = new AtomicInteger(-1);
                    final ScanCallback cb = new ScanCallback() {
                        @Override
                        public void onScanResult(int type, ScanResult r) {
                            synchronized (seen) {
                                seen.add(r.getDevice().getAddress());
                            }
                        }

                        @Override
                        public void onBatchScanResults(List<ScanResult> results) {
                            synchronized (seen) {
                                for (ScanResult r : results) {
                                    seen.add(r.getDevice().getAddress());
                                }
                            }
                        }

                        @Override
                        public void onScanFailed(int errorCode) {
                            failed.set(errorCode);
                        }
                    };
                    s.startScan(cb);
                    Ctx.sleep(6000);
                    s.stopScan(cb);
                    if (failed.get() >= 0) {
                        return Result.of(Outcome.ERROR).put("scan_failed", failed.get());
                    }
                    synchronized (seen) {
                        return markScan(c, Result.count("devices", seen.size()));
                    }
                })
                .timeout(10_000)
                .expect(scanShield("BLE scans find nothing for a listed app", BLUETOOTH_SCAN)));

        out.add(new Probe(CAT_BT, "bt.discovery",
                "Classic Bluetooth discovery for 8 s (devices found, count only).",
                perms(BLUETOOTH_SCAN),
                c -> {
                    final BluetoothAdapter a = adapter(c);
                    if (a == null || !a.isEnabled()) {
                        return Result.unavailable("Bluetooth off or missing");
                    }
                    final Set<String> found = new HashSet<>();
                    final CountDownLatch finished = new CountDownLatch(1);
                    final BroadcastReceiver rx = new BroadcastReceiver() {
                        @Override
                        public void onReceive(Context ctx, Intent i) {
                            if (BluetoothDevice.ACTION_FOUND.equals(i.getAction())) {
                                final BluetoothDevice d = i.getParcelableExtra(
                                        BluetoothDevice.EXTRA_DEVICE, BluetoothDevice.class);
                                if (d != null) {
                                    synchronized (found) {
                                        found.add(d.getAddress());
                                    }
                                }
                            } else {
                                finished.countDown();
                            }
                        }
                    };
                    final IntentFilter f = new IntentFilter(BluetoothDevice.ACTION_FOUND);
                    f.addAction(BluetoothAdapter.ACTION_DISCOVERY_FINISHED);
                    c.app.registerReceiver(rx, f, null, c.worker, Context.RECEIVER_EXPORTED);
                    boolean started = false;
                    try {
                        started = a.startDiscovery();
                        if (!started) {
                            return Result.empty().put("started", false);
                        }
                        finished.await(8, TimeUnit.SECONDS);
                    } finally {
                        // IchthysOS: also when the wait is interrupted (probe timeout), so
                        // discovery never keeps the radio busy after the probe.
                        if (started) {
                            a.cancelDiscovery();
                        }
                        c.app.unregisterReceiver(rx);
                    }
                    synchronized (found) {
                        return markScan(c, Result.count("devices", found.size()));
                    }
                })
                .timeout(12_000)
                .expect(scanShield("discovery finds nothing for a listed app", BLUETOOTH_SCAN)));

        out.add(new Probe(CAT_BT, "bt.advertise",
                "Whether the app can make the phone a BLE beacon (started, then stopped).",
                perms(BLUETOOTH_ADVERTISE),
                c -> {
                    final BluetoothAdapter a = adapter(c);
                    if (a == null || !a.isEnabled()) {
                        return Result.unavailable("Bluetooth off or missing");
                    }
                    final BluetoothLeAdvertiser adv = a.getBluetoothLeAdvertiser();
                    if (adv == null) {
                        return Result.unavailable("no LE advertiser");
                    }
                    final boolean multi = a.isMultipleAdvertisementSupported();
                    final AtomicInteger code = new AtomicInteger(-1);
                    final CountDownLatch done = new CountDownLatch(1);
                    final AdvertiseCallback cb = new AdvertiseCallback() {
                        @Override
                        public void onStartSuccess(AdvertiseSettings settings) {
                            code.set(0);
                            done.countDown();
                        }

                        @Override
                        public void onStartFailure(int errorCode) {
                            code.set(errorCode);
                            done.countDown();
                        }
                    };
                    adv.startAdvertising(new AdvertiseSettings.Builder()
                                    .setConnectable(false).setTimeout(3000).build(),
                            new AdvertiseData.Builder().setIncludeDeviceName(false).build(), cb);
                    done.await(5, TimeUnit.SECONDS);
                    adv.stopAdvertising(cb);
                    final int e = code.get();
                    if (e == 0) {
                        return Result.visible().put("advertising", "started");
                    }
                    if (e == AdvertiseCallback.ADVERTISE_FAILED_FEATURE_UNSUPPORTED && multi) {
                        return Result.blockedIchthys("FEATURE_UNSUPPORTED on hardware that "
                                + "supports advertising").put("error", e);
                    }
                    return Result.of(e < 0 ? Outcome.ERROR : Outcome.EMPTY)
                            .put("error", e).put("multi_adv_supported", multi);
                })
                .timeout(8000)
                .expect(Expect.of("BLE advertising shield", SRC_ADVERTISE,
                        "apps can't make the phone a beacon")
                        .outcomes(Outcome.BLOCKED_ICHTHYS)
                        .when(c -> !c.granted(BLUETOOTH_ADVERTISE) ? "permission not granted"
                                : c.shields.notProtecting(Shields.BLE_ADVERTISE))));

        // ---- Wi-Fi ----
        out.add(new Probe(CAT_WIFI, "wifi.state",
                "Wi-Fi on/off and radio capabilities (ACCESS_WIFI_STATE, a normal permission).",
                Probe.NONE,
                c -> {
                    final WifiManager wm = c.app.getSystemService(WifiManager.class);
                    if (wm == null) {
                        return Result.unavailable("no Wi-Fi");
                    }
                    return Result.visible().put("enabled", wm.isWifiEnabled())
                            .put("5ghz", wm.is5GHzBandSupported())
                            .put("6ghz", wm.is6GHzBandSupported())
                            .put("scan_always", wm.isScanAlwaysAvailable());
                }));

        out.add(new Probe(CAT_WIFI, "wifi.connection",
                "The connected network: SSID and BSSID (lengths/hashes), signal, band.",
                perms(ACCESS_FINE_LOCATION),
                c -> {
                    final WifiManager wm = c.app.getSystemService(WifiManager.class);
                    @SuppressWarnings("deprecation")
                    final WifiInfo wi = wm.getConnectionInfo();
                    if (wi == null || wi.getNetworkId() == -1 && wi.getRssi() < -126) {
                        return Result.empty().put("connected", false);
                    }
                    String ssid = wi.getSSID();
                    final boolean ssidHidden = ssid == null
                            || WifiManager.UNKNOWN_SSID.equals(ssid);
                    if (!ssidHidden && ssid.startsWith("\"") && ssid.endsWith("\"")) {
                        ssid = ssid.substring(1, ssid.length() - 1);
                    }
                    final String bssid = wi.getBSSID();
                    final boolean bssidHidden = bssid == null
                            || "02:00:00:00:00:00".equals(bssid);
                    final Result r = ssidHidden && bssidHidden ? Result.empty()
                            : Result.visible();
                    r.put("ssid", ssidHidden ? "hidden" : "visible, " + Redact.text(ssid));
                    r.put("bssid", bssidHidden ? "hidden" : "visible, " + Redact.hash(bssid));
                    r.put("rssi", wi.getRssi() / 10 * 10 + " dBm (10 dB steps)");
                    r.put("band_mhz", wi.getFrequency() / 1000 + " GHz");
                    r.put("link_mbps", Redact.bucket(wi.getLinkSpeed()));
                    return LocationProbes.markNoFix(c, r);
                })
                .expect(LocationProbes.noFix("a listed app doesn't see the SSID/BSSID (a "
                        + "location; known gap M2)", ACCESS_FINE_LOCATION)));

        out.add(new Probe(CAT_WIFI, "wifi.scan_results",
                "Wi-Fi networks around the phone (count only): a location without GPS.",
                perms(ACCESS_FINE_LOCATION),
                c -> {
                    final WifiManager wm = c.app.getSystemService(WifiManager.class);
                    if (wm == null || !wm.isWifiEnabled() && !wm.isScanAlwaysAvailable()) {
                        return Result.unavailable("Wi-Fi off and scanning off");
                    }
                    final List<android.net.wifi.ScanResult> res = wm.getScanResults();
                    int withVendorIe = 0;
                    for (android.net.wifi.ScanResult s : res) {
                        final List<InformationElement> ies = s.getInformationElements();
                        if (ies != null && !ies.isEmpty()) {
                            withVendorIe++;
                        }
                    }
                    return markScan(c, Result.count("networks", res.size())
                            .put("with_ies", withVendorIe));
                })
                .expect(scanShield("Wi-Fi scan results are empty for a listed app",
                        ACCESS_FINE_LOCATION)));

        out.add(new Probe(CAT_WIFI, "wifi.nearby_permission",
                "NEARBY_WIFI_DEVICES grant (Wi-Fi Aware/Direct without location).",
                perms(NEARBY_WIFI_DEVICES),
                c -> Result.visible().put("granted", c.granted(NEARBY_WIFI_DEVICES))));

        out.add(new Probe(CAT_WIFI, "wifi.control",
                "Whether the app may switch Wi-Fi (setWifiEnabled to its current state).",
                Probe.NONE,
                c -> {
                    final WifiManager wm = c.app.getSystemService(WifiManager.class);
                    @SuppressWarnings("deprecation")
                    final boolean ok = wm.setWifiEnabled(wm.isWifiEnabled());
                    return ok ? Result.visible().put("setWifiEnabled", true)
                            : Result.blockedPermission("setWifiEnabled false (stock: apps "
                                    + "targeting Q+ can't; IchthysOS wifiControl shield as well)");
                }));

        // ---- UWB / NFC ----
        out.add(new Probe(CAT_OTHER, "uwb.ranging",
                "UWB distance measurement to nearby devices.",
                perms(UWB_RANGING),
                c -> c.hasFeature("android.hardware.uwb")
                        ? Result.skipped("manual: needs a UWB peer; see README")
                        : Result.unavailable("no UWB hardware"))
                .expect(Expect.of("UWB shield", SRC_UWB,
                        "apps can't use UWB ranging (onOpenFailed REASON_SYSTEM_POLICY)")
                        .outcomes(Outcome.BLOCKED_ICHTHYS, Outcome.UNAVAILABLE)
                        .when(c -> c.shields.notProtecting(Shields.UWB))));

        out.add(new Probe(CAT_OTHER, "nfc.adapter",
                "NFC presence and state (no permission needed).",
                Probe.NONE,
                c -> {
                    final NfcAdapter a = NfcAdapter.getDefaultAdapter(c.app);
                    if (a == null) {
                        return Result.unavailable("no NFC");
                    }
                    return Result.visible().put("enabled", a.isEnabled());
                }));

        out.add(new Probe(CAT_OTHER, "nfc.reader",
                "Whether the app can read NFC tags (reader mode).",
                perms(android.Manifest.permission.NFC),
                c -> NfcAdapter.getDefaultAdapter(c.app) == null
                        ? Result.unavailable("no NFC")
                        : Result.skipped("manual: needs a tag; see README"))
                .expect(Expect.of("NFC shield", SRC_NFC,
                        "a listed app can't read tags or emulate cards")
                        .outcomes(Outcome.BLOCKED_ICHTHYS, Outcome.UNAVAILABLE)
                        .when(c -> c.shields.notProtecting(Shields.NFC))));
    }
}
