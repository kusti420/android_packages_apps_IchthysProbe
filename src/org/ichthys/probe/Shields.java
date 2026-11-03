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

import android.content.ContentResolver;
import android.content.Context;
import android.provider.Settings;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * The app-side copy of the IchthysOS shield table
 * (frameworks/base/core/java/com/android/internal/ichthys/config/IchthysShields.java), used to
 * decide which protected answer this app should get right now.
 *
 * <p>Since 2026-10-28 SettingsProvider hides every shield list, switch and lockdown key from
 * apps (they read as unset), so this app cannot see its own shield state any more. Two modes:
 *
 * <ul>
 *   <li><b>Guard view</b> ({@link #useGuardView}): in a Guard verification run Guard passes the
 *       ids of the shields that protect this app ({@code expect_shields}); that is the authority
 *       and every promise is judged against it.</li>
 *   <li><b>Unknown</b> (a manual run): nothing is assumed. {@link #protects} is false,
 *       {@link #notProtecting} says the lists are hidden, so shield promises are "not tested"
 *       instead of judged on a guess. Nothing is ever written to the user's data on a guess.</li>
 * </ul>
 *
 * The report still records whether each key was readable (never the list contents).
 */
public final class Shields {

    /** Listed apps get the real data (ALLOW) or the protected answer (PROTECT). */
    public enum Polarity { ALLOW, PROTECT }

    /** One shield: switch (null = always on) and per-app list. */
    public static final class Shield {
        public final String name;
        public final String switchKey;
        public final boolean switchGlobal;
        public final String listKey;
        public final Polarity polarity;

        Shield(String name, String switchKey, boolean switchGlobal, String listKey,
                Polarity polarity) {
            this.name = name;
            this.switchKey = switchKey;
            this.switchGlobal = switchGlobal;
            this.listKey = listKey;
            this.polarity = polarity;
        }
    }

    public static final Shield CONTACTS = new Shield("contacts",
            "ichthys_contacts_lockdown", true, "ichthys_contacts_allowed_pkgs", Polarity.ALLOW);
    public static final Shield CLIPBOARD = new Shield("clipboard",
            "ichthys_clipboard_lockdown", true, "ichthys_clipboard_allowed_pkgs", Polarity.ALLOW);
    public static final Shield SENSORS = new Shield("sensors",
            "ichthys_sensor_fingerprint_protection", true, "ichthys_sensor_exempt_pkgs",
            Polarity.ALLOW);
    public static final Shield CONTACTS_WRITE = feature("contactsWrite", "contacts_write");
    public static final Shield CALENDAR = new Shield("calendar",
            "ichthys_calendar_shield", false, "ichthys_calendar_allowed_pkgs", Polarity.ALLOW);
    public static final Shield CALENDAR_WRITE = feature("calendarWrite", "calendar_write");
    public static final Shield CALL_LOG = feature("callLog", "call_log");
    public static final Shield CALL_LOG_WRITE = feature("callLogWrite", "call_log_write");
    public static final Shield SMS_READ = feature("smsRead", "sms_read");
    public static final Shield SMS_SEND = feature("smsSend", "sms_send");
    public static final Shield MMS_PUSH = feature("mmsPush", "mms_push");
    public static final Shield PHONE_NUMBER = feature("phoneNumber", "phone_number");
    public static final Shield CALL = feature("call", "call");
    public static final Shield ANSWER_CALLS = feature("answerCalls", "answer_calls");
    public static final Shield USAGE_HISTORY = new Shield("usageHistory", null, false,
            "ichthys_usage_full_pkgs", Polarity.ALLOW);
    public static final Shield BLE_ADVERTISE = new Shield("bleAdvertise", null, false,
            "ichthys_ble_advertise_pkgs", Polarity.ALLOW);
    public static final Shield WIFI_CONTROL = new Shield("wifiControl", null, false,
            "ichthys_wifi_control_pkgs", Polarity.ALLOW);
    public static final Shield UWB = new Shield("uwb", null, false, "ichthys_uwb_pkgs",
            Polarity.ALLOW);
    public static final Shield SCANS = new Shield("scans", null, false,
            "ichthys_scan_empty_pkgs", Polarity.PROTECT);
    public static final Shield LOCATION = new Shield("location", null, false,
            "ichthys_location_nofix_pkgs", Polarity.PROTECT);
    public static final Shield NFC = new Shield("nfc", null, false, "ichthys_nfc_blocked_pkgs",
            Polarity.PROTECT);

    public static final Shield[] ALL = {
        CONTACTS, CONTACTS_WRITE, CALENDAR, CALENDAR_WRITE, CALL_LOG, CALL_LOG_WRITE, SMS_READ,
        SMS_SEND, MMS_PUSH, PHONE_NUMBER, CALL, ANSWER_CALLS, CLIPBOARD, SENSORS, USAGE_HISTORY,
        BLE_ADVERTISE, WIFI_CONTROL, UWB, SCANS, LOCATION, NFC,
    };

    /**
     * Guard's shield ids (Settings ShieldTable, the {@code expect_shields} extra) mapped to the
     * shields here. Guard's one "writes" row stands for the three write shields.
     */
    private static final Map<String, String[]> GUARD_IDS = new HashMap<>();

    static {
        GUARD_IDS.put("contacts", new String[] {"contacts"});
        GUARD_IDS.put("calendar", new String[] {"calendar"});
        GUARD_IDS.put("call_log", new String[] {"callLog"});
        GUARD_IDS.put("writes", new String[] {"contactsWrite", "calendarWrite", "callLogWrite"});
        GUARD_IDS.put("phone_number", new String[] {"phoneNumber"});
        GUARD_IDS.put("sms_read", new String[] {"smsRead"});
        GUARD_IDS.put("sms_send", new String[] {"smsSend"});
        GUARD_IDS.put("mms_push", new String[] {"mmsPush"});
        GUARD_IDS.put("call", new String[] {"call"});
        GUARD_IDS.put("answer_calls", new String[] {"answerCalls"});
        GUARD_IDS.put("clipboard", new String[] {"clipboard"});
        GUARD_IDS.put("sensors", new String[] {"sensors"});
        GUARD_IDS.put("usage", new String[] {"usageHistory"});
        GUARD_IDS.put("ble_advertise", new String[] {"bleAdvertise"});
        GUARD_IDS.put("wifi_control", new String[] {"wifiControl"});
        GUARD_IDS.put("uwb", new String[] {"uwb"});
        GUARD_IDS.put("nfc", new String[] {"nfc"});
        GUARD_IDS.put("scans", new String[] {"scans"});
        GUARD_IDS.put("location_nofix", new String[] {"location"});
        // "location_real" (the fake place) is carried by expect_location, not a shield here.
    }

    private static Shield feature(String name, String feature) {
        return new Shield(name, "ichthys_" + feature + "_shield", false,
                "ichthys_" + feature + "_allowed_pkgs", Polarity.ALLOW);
    }

    /** What a settings read gave: the value, or why there is none. */
    public static final class Read {
        public final boolean readable;
        public final String value;
        public final String error;

        Read(boolean readable, String value, String error) {
            this.readable = readable;
            this.value = value;
            this.error = error;
        }
    }

    private final Context mContext;
    private final String mPackage;
    private final Map<String, Read> mCache = new LinkedHashMap<>();
    /** Shield names that protect this app according to Guard; null outside a Guard run. */
    private Set<String> mGuard;
    /** The raw ids Guard sent, for the report. */
    private String mGuardIds = "";

    Shields(Context context) {
        mContext = context;
        mPackage = context.getPackageName();
    }

    /**
     * Takes Guard's view ({@code expect_shields}: comma-separated ShieldTable ids of the shields
     * that protect this app) as the authority for every judgement of this run.
     */
    public synchronized void useGuardView(String expectShields) {
        final Set<String> protecting = new HashSet<>();
        for (String id : expectShields.split(",")) {
            final String[] names = GUARD_IDS.get(id.trim());
            if (names != null) {
                for (String n : names) {
                    protecting.add(n);
                }
            }
        }
        mGuard = protecting;
        mGuardIds = expectShields.trim();
    }

    /** True when Guard's view backs this run; false when the state is unknown (hidden lists). */
    public synchronized boolean authoritative() {
        return mGuard != null;
    }

    /** Reads a Secure (or Global) key the way any app can. Cached per run. */
    public synchronized Read read(String key, boolean global) {
        final String cacheKey = (global ? "g:" : "s:") + key;
        Read r = mCache.get(cacheKey);
        if (r != null) {
            return r;
        }
        final ContentResolver cr = mContext.getContentResolver();
        try {
            final String v = global ? Settings.Global.getString(cr, key)
                    : Settings.Secure.getString(cr, key);
            r = new Read(true, v, null);
        } catch (SecurityException e) {
            r = new Read(false, null, Redact.exception(e));
        } catch (RuntimeException e) {
            r = new Read(false, null, Redact.exception(e));
        }
        mCache.put(cacheKey, r);
        return r;
    }

    /** Whether the shield's switch is on (unset or unreadable counts as on, like the platform). */
    public synchronized boolean switchOn(Shield s) {
        if (s.switchKey == null) {
            return true;
        }
        final Read r = read(s.switchKey, s.switchGlobal);
        return !r.readable || r.value == null || !"0".equals(r.value.trim());
    }

    /**
     * Whether this app is on the shield's list (a ":picked" entry doesn't count). With Guard's
     * view: what Guard's answer implies for the list.
     */
    public synchronized boolean listed(Shield s) {
        if (mGuard != null) {
            final boolean protects = mGuard.contains(s.name);
            return s.polarity == Polarity.PROTECT ? protects : !protects;
        }
        if (s.listKey == null) {
            return false;
        }
        final Read r = read(s.listKey, false);
        if (!r.readable || r.value == null) {
            return false;
        }
        for (String e : r.value.split(",")) {
            if (mPackage.equals(e.trim())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether this app should get the protected answer from {@code s} right now. False when the
     * state is unknown: a protected answer is only ever claimed on Guard's word.
     */
    public synchronized boolean protects(Shield s) {
        if (mGuard != null) {
            return mGuard.contains(s.name);
        }
        return false;
    }

    /** Null when {@code s} protects this app; otherwise why not (for Expect conditions). */
    public synchronized String notProtecting(Shield s) {
        if (mGuard == null) {
            return "shield " + s.name + ": the shield lists are hidden from apps, so it is "
                    + "judged only in a Guard verification";
        }
        if (protects(s)) {
            return null;
        }
        if (s.polarity == Polarity.PROTECT) {
            return "shield " + s.name + ": Guard says this app is not on " + s.listKey;
        }
        return "shield " + s.name + ": Guard says this app is allowed the real data ("
                + s.listKey + ")";
    }

    /** Redacted state of every shield, for the report header. */
    public synchronized Map<String, String> describe() {
        final Map<String, String> out = new LinkedHashMap<>();
        out.put("_source", mGuard != null ? "guard:" + mGuardIds : "unknown (lists hidden)");
        for (Shield s : ALL) {
            final StringBuilder sb = new StringBuilder();
            if (s.switchKey != null) {
                final Read r = read(s.switchKey, s.switchGlobal);
                sb.append("switch=").append(!r.readable ? "unreadable(default on)"
                        : r.value == null ? "unset(on)" : r.value.trim());
            } else {
                sb.append("switch=none");
            }
            if (s.listKey != null) {
                final Read r = read(s.listKey, false);
                int n = 0;
                if (r.readable && r.value != null) {
                    for (String e : r.value.split(",")) {
                        if (!e.trim().isEmpty()) {
                            n++;
                        }
                    }
                }
                sb.append(", list=").append(r.readable ? n + " entries" : "unreadable")
                        .append(", listed=").append(listed(s));
            }
            sb.append(", protects=").append(protects(s));
            out.put(s.name, sb.toString());
        }
        return out;
    }
}
