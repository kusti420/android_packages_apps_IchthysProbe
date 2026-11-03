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
import static android.Manifest.permission.ANSWER_PHONE_CALLS;
import static android.Manifest.permission.CALL_PHONE;
import static android.Manifest.permission.READ_PHONE_NUMBERS;
import static android.Manifest.permission.READ_PHONE_STATE;

import static org.ichthys.probe.Probe.perms;

import android.media.AudioManager;
import android.media.MediaDrm;
import android.os.Build;
import android.provider.Settings;
import android.telecom.TelecomManager;
import android.telephony.CellInfo;
import android.telephony.SubscriptionInfo;
import android.telephony.SubscriptionManager;
import android.telephony.TelephonyManager;

import org.ichthys.probe.Ctx;
import org.ichthys.probe.Expect;
import org.ichthys.probe.Outcome;
import org.ichthys.probe.Probe;
import org.ichthys.probe.Redact;
import org.ichthys.probe.Result;
import org.ichthys.probe.Shields;

import java.util.List;
import java.util.TreeMap;
import java.util.UUID;

/** Telephony state, phone number, hardware identifiers and other stable device ids. */
public final class PhoneProbes {
    static final String CAT = "Phone & identifiers";

    private static final String SRC_NUMBER =
            "frameworks/opt/telephony/src/java/com/android/internal/telephony/IchthysShield.java;"
                    + " PhoneSubInfoController.java:299-303,328-331; "
                    + "subscription/SubscriptionManagerService.java:1105-1187,4342-4344; "
                    + "IchthysShields.PHONE_NUMBER (\"apps get no phone number\")";
    private static final String SRC_ANSWER =
            "packages/services/Telecomm/src/com/android/server/telecom/TelecomServiceImpl.java:"
                    + "1684-1685,3595-3633; IchthysShields.ANSWER_CALLS (\"apps can't answer or "
                    + "end calls\")";
    private static final String SRC_CALL =
            "packages/services/Telecomm/src/com/android/server/telecom/IchthysShield.java, "
                    + "TelecomServiceImpl.java:2366-2371,3644-3725; IchthysCallConfirmActivity";

    private PhoneProbes() {}

    private static Expect numberShield(String promise) {
        return Expect.of("Phone number shield", SRC_NUMBER, promise)
                .outcomes(Outcome.EMPTY, Outcome.BLOCKED_ICHTHYS)
                .when(c -> !c.granted(READ_PHONE_NUMBERS) ? "READ_PHONE_NUMBERS not granted"
                        : c.shields.notProtecting(Shields.PHONE_NUMBER));
    }

    /** Stock identifier lockdown (Android 10+): non-privileged apps get a SecurityException. */
    private static Expect stockIdentifier(String what) {
        return Expect.of("Stock device identifier lockdown",
                "frameworks/base/telephony TelephonyPermissions.checkReadDeviceIdentifiers (stock;"
                        + " no IchthysOS change)",
                what + " is refused to ordinary apps even with READ_PHONE_STATE")
                .outcomes(Outcome.BLOCKED_PERMISSION, Outcome.EMPTY, Outcome.UNAVAILABLE);
    }

    private static Result idCall(IdSupplier s) {
        try {
            final String v = s.get();
            if (v == null || v.isEmpty()) {
                return Result.empty().put("value", Redact.text(v));
            }
            return Result.visible().put("value", Redact.text(v));
        } catch (SecurityException e) {
            return Result.fromSecurity(e);
        } catch (UnsupportedOperationException e) {
            return Result.unavailable(Redact.exception(e));
        }
    }

    private interface IdSupplier {
        String get();
    }

    public static void add(List<Probe> out) {
        out.add(new Probe(CAT, "phone.network_basics",
                "SIM state, operator and country, roaming, carrier id (no permission needed).",
                Probe.NONE,
                c -> {
                    final TelephonyManager tm = c.app.getSystemService(TelephonyManager.class);
                    if (tm == null) {
                        return Result.unavailable("no telephony");
                    }
                    return Result.visible()
                            .put("sim_state", tm.getSimState())
                            .put("phone_type", tm.getPhoneType())
                            .put("modems", tm.getActiveModemCount())
                            .put("operator_name", Redact.text(tm.getNetworkOperatorName()))
                            .put("sim_operator_name", Redact.text(tm.getSimOperatorName()))
                            .put("operator_mccmnc", Redact.length(tm.getNetworkOperator()))
                            .put("country", Redact.length(tm.getNetworkCountryIso()))
                            .put("roaming", tm.isNetworkRoaming())
                            .put("carrier_id", tm.getSimCarrierId() > 0 ? "visible" : "none")
                            .put("data_enabled", tm.isDataEnabled());
                }));

        out.add(new Probe(CAT, "phone.state",
                "Call state, data network type and voicemail number (READ_PHONE_STATE).",
                perms(READ_PHONE_STATE),
                c -> {
                    final TelephonyManager tm = c.app.getSystemService(TelephonyManager.class);
                    return Result.visible()
                            .put("call_state", tm.getCallStateForSubscription())
                            .put("data_network_type", tm.getDataNetworkType())
                            .put("voicemail_number", Redact.length(tm.getVoiceMailNumber()))
                            .put("service_state", tm.getServiceState() == null ? "null"
                                    : String.valueOf(tm.getServiceState().getState()));
                }));

        out.add(new Probe(CAT, "phone.subscriptions",
                "Active SIM subscriptions and the number stored on each (length only).",
                perms(READ_PHONE_STATE),
                c -> {
                    final SubscriptionManager sm =
                            c.app.getSystemService(SubscriptionManager.class);
                    final List<SubscriptionInfo> subs = sm.getActiveSubscriptionInfoList();
                    if (subs == null || subs.isEmpty()) {
                        return Result.empty().put("subscriptions", 0);
                    }
                    final Result r = Result.visible().put("subscriptions", subs.size());
                    int i = 0;
                    for (SubscriptionInfo s : subs) {
                        r.put("sub" + i + "_number", Redact.length(s.getNumber()));
                        r.put("sub" + i + "_display_name", Redact.length(s.getDisplayName()));
                        r.put("sub" + i + "_iccid", Redact.length(s.getIccId()));
                        i++;
                    }
                    return r;
                }));

        out.add(new Probe(CAT, "phone.line1_number",
                "The phone's own number via TelephonyManager.getLine1Number (length only).",
                perms(READ_PHONE_NUMBERS),
                c -> {
                    final TelephonyManager tm = c.app.getSystemService(TelephonyManager.class);
                    final String n = tm.getLine1Number();
                    if (n == null || n.isEmpty()) {
                        final Result r = Result.empty().put("number", Redact.length(n));
                        return c.shields.protects(Shields.PHONE_NUMBER)
                                ? Result.blockedIchthys("null under the phone number shield")
                                        .put("number", Redact.length(n)) : r;
                    }
                    return Result.visible().put("number", Redact.text(n));
                })
                .expect(numberShield("getLine1Number returns null")));

        out.add(new Probe(CAT, "phone.subscription_number",
                "The phone's own number via SubscriptionManager.getPhoneNumber (length only).",
                perms(READ_PHONE_NUMBERS),
                c -> {
                    final SubscriptionManager sm =
                            c.app.getSystemService(SubscriptionManager.class);
                    final int sub = SubscriptionManager.getDefaultSubscriptionId();
                    if (sub == SubscriptionManager.INVALID_SUBSCRIPTION_ID) {
                        return Result.unavailable("no default subscription");
                    }
                    final String n = sm.getPhoneNumber(sub);
                    if (n == null || n.isEmpty()) {
                        return c.shields.protects(Shields.PHONE_NUMBER)
                                ? Result.blockedIchthys("\"\" under the phone number shield")
                                : Result.empty().put("number", Redact.length(n));
                    }
                    return Result.visible().put("number", Redact.text(n));
                })
                .expect(numberShield("SubscriptionManager.getPhoneNumber returns \"\"")));

        out.add(new Probe(CAT, "phone.imei", "The IMEI (hardware id).", perms(READ_PHONE_STATE),
                c -> idCall(() -> c.app.getSystemService(TelephonyManager.class).getImei()))
                .expect(stockIdentifier("The IMEI")));

        out.add(new Probe(CAT, "phone.subscriber_id", "The IMSI (SIM subscriber id).",
                perms(READ_PHONE_STATE),
                c -> idCall(() -> c.app.getSystemService(TelephonyManager.class)
                        .getSubscriberId()))
                .expect(stockIdentifier("The IMSI")));

        out.add(new Probe(CAT, "phone.sim_serial", "The SIM serial number (ICCID).",
                perms(READ_PHONE_STATE),
                c -> idCall(() -> c.app.getSystemService(TelephonyManager.class)
                        .getSimSerialNumber()))
                .expect(stockIdentifier("The ICCID")));

        out.add(new Probe(CAT, "phone.build_serial", "The device serial number (Build.getSerial).",
                perms(READ_PHONE_STATE),
                c -> idCall(Build::getSerial))
                .expect(stockIdentifier("The serial number")));

        out.add(new Probe(CAT, "phone.cell_info",
                "Nearby cell towers (count and radio types): a location without GPS.",
                perms(ACCESS_FINE_LOCATION),
                c -> {
                    final TelephonyManager tm = c.app.getSystemService(TelephonyManager.class);
                    final List<CellInfo> cells = tm.getAllCellInfo();
                    if (cells == null || cells.isEmpty()) {
                        return LocationProbes.markNoFix(c, Result.empty().put("cells", 0));
                    }
                    final TreeMap<String, Integer> types = new TreeMap<>();
                    for (CellInfo ci : cells) {
                        types.merge(ci.getClass().getSimpleName().replace("CellInfo", ""), 1,
                                Integer::sum);
                    }
                    return Result.visible().put("cells", cells.size())
                            .put("types", types.toString());
                })
                .expect(LocationProbes.noFix("a listed app gets no cell info either (\"never "
                        + "get a location\"; known gap M2 in services.md)", ACCESS_FINE_LOCATION)));

        out.add(new Probe(CAT, "phone.end_call",
                "Whether the app may end calls (TelecomManager.endCall with no call in progress).",
                perms(ANSWER_PHONE_CALLS),
                c -> {
                    // IchthysOS: endCall() ends (or rejects) a real call whenever the shield
                    // lets this app through (run d, or a broken shield). Never call it while
                    // a call rings or is in progress; the audio mode needs no permission.
                    final AudioManager am = c.app.getSystemService(AudioManager.class);
                    if (am != null && am.getMode() != AudioManager.MODE_NORMAL) {
                        return Result.skipped("a call is ringing or in progress (audio mode "
                                + am.getMode() + "); endCall() is never tried then");
                    }
                    final TelecomManager tm = c.app.getSystemService(TelecomManager.class);
                    try {
                        @SuppressWarnings("deprecation")
                        final boolean ended = tm.endCall();
                        return Result.visible().put("endCall", ended)
                                .put("meaning", "call control allowed (no call to end)");
                    } catch (SecurityException e) {
                        if (c.granted(ANSWER_PHONE_CALLS)) {
                            return Result.blockedIchthys("SecurityException while holding "
                                    + "ANSWER_PHONE_CALLS").put("error", Redact.exception(e));
                        }
                        return Result.fromSecurity(e);
                    }
                })
                .expect(Expect.of("Answer/end calls shield", SRC_ANSWER,
                        "an app holding ANSWER_PHONE_CALLS still can't end calls")
                        .outcomes(Outcome.BLOCKED_ICHTHYS)
                        .when(c -> !c.granted(ANSWER_PHONE_CALLS) ? "permission not granted"
                                : c.shields.notProtecting(Shields.ANSWER_CALLS))));

        out.add(new Probe(CAT, "phone.place_call",
                "Whether the app can place a call without the user confirming it.",
                perms(CALL_PHONE),
                c -> Result.skipped("manual: placing a real call is never automated; see README"))
                .expect(Expect.of("Call shield", SRC_CALL,
                        "every call an app places needs the user's OK in a system dialog")
                        .outcomes(Outcome.BLOCKED_ICHTHYS)));

        out.add(new Probe(CAT, "id.android_id",
                "Settings.Secure.ANDROID_ID: the per-app, per-signer stable id.",
                Probe.NONE,
                c -> {
                    final String id = Settings.Secure.getString(c.app.getContentResolver(),
                            Settings.Secure.ANDROID_ID);
                    return id == null ? Result.empty() : Result.visible()
                            .put("android_id", Redact.text(id))
                            .put("note", "Guard \"Reset identity\" changes it; compare hashes");
                }));

        out.add(new Probe(CAT, "id.widevine",
                "MediaDrm Widevine device-unique id: a stable cross-app fingerprint.",
                Probe.NONE,
                c -> {
                    final UUID widevine = new UUID(0xEDEF8BA979D64ACEL, 0xA3C827DCD51D21EDL);
                    if (!MediaDrm.isCryptoSchemeSupported(widevine)) {
                        return Result.unavailable("no Widevine");
                    }
                    try (MediaDrm drm = new MediaDrm(widevine)) {
                        final byte[] id =
                                drm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID);
                        final StringBuilder hex = new StringBuilder();
                        for (byte b : id) {
                            hex.append(String.format("%02x", b & 0xff));
                        }
                        return Result.visible().put("id", id.length + " bytes, "
                                + Redact.hash(hex.toString()))
                                .put("security_level", drm.getPropertyString("securityLevel"));
                    }
                }));

        out.add(new Probe(CAT, "id.device_name",
                "The user-visible device name (often contains the owner's name).",
                Probe.NONE,
                c -> {
                    final String n = Settings.Global.getString(c.app.getContentResolver(),
                            Settings.Global.DEVICE_NAME);
                    return n == null ? Result.empty() : Result.visible()
                            .put("device_name", Redact.text(n));
                }));
    }
}
