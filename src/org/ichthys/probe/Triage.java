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

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * IchthysOS: turns a run's results into "what is wrong and what do I do about it". The
 * {@link #TABLE} gives every probe group a severity, a plain-language title, one line on why it
 * matters, the shield it belongs to and where it is fixed. {@link #analyse} then sorts the
 * results into problems (a broken promise, or a shield switched off), gaps (a leak no IchthysOS
 * feature covers yet), checks that couldn't run (and why), and the passed checks per category.
 *
 * <p>Severity: High when real data leaves (contacts, call log, SMS, real location, the clipboard,
 * identifiers), Medium for metadata (scans, sensors, usage, the local network), Low for the
 * environment (keybox, microG, hosts blocklist).
 */
public final class Triage {

    public enum Severity {
        HIGH("High"), MEDIUM("Medium"), LOW("Low");

        public final String label;

        Severity(String label) {
            this.label = label;
        }
    }

    public enum Kind {
        /** A FAIL: an IchthysOS promise didn't hold. */
        BROKEN("Broken promise", "fail"),
        /** A shield's master switch is off: every app with the permission gets the real data. */
        SHIELD_OFF("Shield off", "off"),
        /** Real data with no IchthysOS feature in the way (stock behaviour). */
        GAP("Not covered", "gap");

        public final String label;
        final String keyPrefix;

        Kind(String label, String keyPrefix) {
            this.label = label;
            this.keyPrefix = keyPrefix;
        }
    }

    /** Why a check didn't test anything, with the one action that would let it. */
    public enum Reason {
        PERMISSION("Needs a permission", Fix.GRANT),
        USAGE_ACCESS("Needs usage access", Fix.USAGE_ACCESS),
        TAP("Needs your tap", Fix.TAP),
        HELPER("Needs IchthysProbeHelper (adb install it)", Fix.NONE),
        ALLOWED("IchthysProbe is allowed the real data", Fix.GUARD_APP),
        NOT_LISTED("Shield not set for IchthysProbe", Fix.GUARD_APP),
        GUARD_ONLY("Only in a Guard verification", Fix.VERIFY),
        MANUAL("Checked by hand (README)", Fix.NONE),
        OTHER("Couldn't run", Fix.NONE);

        public final String label;
        public final Fix fix;

        Reason(String label, Fix fix) {
            this.label = label;
            this.fix = fix;
        }
    }

    /** One row of the table: a probe group. */
    public static final class Rule {
        /** Exact ids, or prefixes ending in '.', ':' or '/'. The first one names the group. */
        final String[] match;
        public final Severity severity;
        /** What goes wrong, in plain words ("Apps can read your call log"). */
        public final String title;
        /** One line: why it matters. */
        public final String why;
        /** The shield that should stop it, or null. */
        public final Shields.Shield shield;
        /** Where it is set; {@link Fix#NONE} when only a code change fixes it. */
        public final Fix fix;
        /** VISIBLE without a judging expectation is a leak nobody covers (a gap). */
        final boolean gap;

        Rule(Severity severity, String title, String why, Shields.Shield shield, Fix fix,
                boolean gap, String... match) {
            this.match = match;
            this.severity = severity;
            this.title = title;
            this.why = why;
            this.shield = shield;
            this.fix = fix;
            this.gap = gap;
        }

        String group() {
            return match[0];
        }

        boolean matches(String id) {
            for (String m : match) {
                final char last = m.charAt(m.length() - 1);
                if (last == '.' || last == ':' || last == '/' ? id.startsWith(m) : id.equals(m)) {
                    return true;
                }
            }
            return false;
        }
    }

    private static Rule r(Severity s, String title, String why, Shields.Shield shield, Fix fix,
            String... match) {
        return new Rule(s, title, why, shield, fix, false, match);
    }

    private static Rule gap(Severity s, String title, String why, String... match) {
        return new Rule(s, title, why, null, Fix.NONE, true, match);
    }

    private static final Severity H = Severity.HIGH;
    private static final Severity M = Severity.MEDIUM;
    private static final Severity L = Severity.LOW;

    /**
     * The severity table. First match wins, so specific ids come before the prefixes that
     * would also match them. A FAIL no row matches counts as Medium.
     */
    static final Rule[] TABLE = {
        // ---- High: real data leaves the phone ----
        r(M, "Apps can secretly save contacts", "A planted contact can put a scammer's number "
                + "under a name you trust.", Shields.CONTACTS_WRITE, Fix.SHIELDS,
                "contacts.write"),
        r(H, "Apps can read your contacts", "Names and numbers of everyone you know leave the "
                + "phone.", Shields.CONTACTS, Fix.SHIELDS, "contacts."),
        r(M, "Apps can secretly add calendar events", "Fake events carry phishing links into "
                + "your day.", Shields.CALENDAR_WRITE, Fix.SHIELDS, "calendar.write"),
        r(H, "Apps can read your calendar", "Your calendar says where you'll be and who you "
                + "meet.", Shields.CALENDAR, Fix.SHIELDS, "calendar."),
        r(M, "Apps can change your call log", "A forged call history hides or invents calls.",
                Shields.CALL_LOG_WRITE, Fix.SHIELDS, "calllog.write"),
        r(H, "Apps can read your call log", "Who you call and when maps your relationships.",
                Shields.CALL_LOG, Fix.SHIELDS, "calllog."),
        r(H, "Apps can send texts without asking", "Premium-rate texts cost money and sign you "
                + "up to services.", Shields.SMS_SEND, Fix.SHIELDS, "sms.send"),
        r(H, "Apps receive your incoming MMS", "Messages reach apps that aren't your SMS app.",
                Shields.MMS_PUSH, Fix.SHIELDS, "sms.mms_push"),
        r(H, "Apps can read your messages", "Texts carry one-time codes and private "
                + "conversations.", Shields.SMS_READ, Fix.SHIELDS, "sms."),
        r(H, "Apps can read your phone number", "Your number ties the phone to you by name.",
                Shields.PHONE_NUMBER, Fix.SHIELDS, "phone.line1_number",
                "phone.subscription_number"),
        r(H, "Apps can read hardware IDs", "A permanent ID follows you across apps and factory "
                + "resets.", null, Fix.NONE, "phone.imei", "phone.subscriber_id",
                "phone.sim_serial", "phone.build_serial"),
        r(H, "Apps can place calls without asking", "Calls to premium numbers cost money.",
                Shields.CALL, Fix.SHIELDS, "phone.place_call"),
        r(M, "Apps can end your calls", "An app can hang up a call you're on.",
                Shields.ANSWER_CALLS, Fix.SHIELDS, "phone.end_call"),
        r(H, "Apps see your real location instead of the fake place", "An app set to the fake "
                + "place should never learn where you are.", null, Fix.FAKE_PLACE,
                "location.fake_place"),
        r(H, "Apps get your real location", "An app set to No location still learns where you "
                + "are.", Shields.LOCATION, Fix.GUARD_APP, "location."),
        r(M, "Apps see your Wi-Fi network and cell towers", "Network names and towers locate "
                + "you without GPS.", Shields.LOCATION, Fix.GUARD_APP, "wifi.connection",
                "phone.cell_info"),
        r(M, "Apps can scan Wi-Fi and Bluetooth around you", "Nearby networks and devices give "
                + "away where you are.", Shields.SCANS, Fix.GUARD_APP, "wifi.scan_results",
                "bt.le_scan", "bt.discovery"),
        r(L, "Apps can't paste what they copied", "A usability break, not a leak.",
                Shields.CLIPBOARD, Fix.NONE, "clip.own_clip"),
        r(M, "Copied text isn't cleared", "Passwords you copy stay on the clipboard.",
                Shields.CLIPBOARD, Fix.SHIELDS, "clip.autoclear"),
        r(M, "Apps can see what kind of thing you copied", "Labels and types hint at what's on "
                + "the clipboard.", Shields.CLIPBOARD, Fix.SHIELDS, "clip.description"),
        r(H, "Apps can read your clipboard without a tap", "Copied passwords and codes leak to "
                + "any app that polls.", Shields.CLIPBOARD, Fix.SHIELDS, "clip."),
        gap(H, "Any app can read a device-wide DRM ID", "Widevine's device ID is a tracking ID "
                + "no app reset changes.", "id.widevine"),
        gap(H, "Any app can read a hardware serial or MAC", "A permanent ID follows you across "
                + "apps and resets.", "fs.read:/sys/class/net/wlan0/address",
                "fs.read:/sys/devices/soc0/serial_number",
                "fs.read:/sys/block/mmcblk0/device/cid"),
        r(H, "Guard's firewall doesn't match its setting", "A blocked app that gets online can "
                + "send whatever it collected.", null, Fix.GUARD_APP, "net.https",
                "net.dns_control", "guard.net_matches"),

        // ---- Medium: metadata ----
        r(M, "Apps can fingerprint your phone through its sensors", "Raw sensor readings "
                + "identify this exact phone across apps.", Shields.SENSORS, Fix.SHIELDS,
                "sensors."),
        r(M, "Apps with usage access see what you use", "Your app history shows your routine, "
                + "hour by hour.", Shields.USAGE_HISTORY, Fix.GUARD_APP, "apps.usage_"),
        r(M, "Apps can list every app you have", "Your app list reveals banks, health, dating "
                + "and faith.", null, Fix.GUARD_APP, "apps.installed"),
        r(M, "New apps can reach devices on your home network", "TVs, cameras and routers are "
                + "easy targets.", null, Fix.GUARD_APP, "net.lan"),
        r(M, "Apps can turn your phone into a beacon", "A beacon lets shops and trackers "
                + "follow the phone.", Shields.BLE_ADVERTISE, Fix.GUARD_APP, "bt.advertise"),
        r(M, "Apps can measure distance to nearby devices", "UWB ranging places you to within "
                + "centimetres.", Shields.UWB, Fix.GUARD_APP, "uwb."),
        r(M, "Apps can read NFC tags", "Cards and tags held to the phone are readable.",
                Shields.NFC, Fix.GUARD_APP, "nfc."),
        r(M, "Apps can see which apps you keep in Backstage", "The hidden list is exactly what "
                + "you meant to hide.", null, Fix.NONE, "display.backstage_list"),
        r(M, "Apps can find the hidden Backstage display", "Apps running there could be "
                + "watched or reached.", null, Fix.NONE, "display."),
        r(M, "Apps can read your configuration history", "Past ichthys.nix generations "
                + "describe your setup.", null, Fix.NONE, "fs.list:/data/system/ichthys"),
        r(M, "Guard and the system disagree about the shields", "What Guard shows isn't what "
                + "apps get.", null, Fix.VERIFY, "guard.state_matches"),
        r(M, "Guard doesn't block the trackers it shows", "Tracker hosts still answer for "
                + "apps Guard marks.", null, Fix.TRACKERS, "net.dns_trackers_guard"),
        gap(M, "Any app can read which apps you trust", "The shield lists name the apps you "
                + "gave real data to.", "settings.shield_lists"),
        gap(M, "Any app can read a per-boot ID", "The same ID in every app until you reboot.",
                "fs.read:/proc/sys/kernel/random/boot_id"),
        gap(M, "Any app can see the phone's network connections", "Other apps' connections and "
                + "LAN neighbours are visible.", "fs.read:/proc/net/tcp",
                "fs.read:/proc/net/arp", "fs.read:/proc/net/unix"),
        gap(M, "Any app can list installed apps through the file system", "That gets around "
                + "the app-list control.", "fs.list:/data/data", "fs.list:/data/app",
                "fs.read:/data/system/packages.list"),

        // ---- Low: environment ----
        r(L, "The tracker blocklist isn't working", "Known tracker hosts resolve normally.",
                null, Fix.NONE, "net.dns_trackers_hosts", "fs.hosts_blocklist"),
        r(L, "microG signature spoofing isn't right", "Apps that check Google's signature break, "
                + "or a fake one gets through.", null, Fix.NONE, "apps.gms_signature"),
        r(L, "Ordinary apps see spoofed build values", "Play Integrity spoofing should stay "
                + "inside Google's apps.", null, Fix.NONE, "build.spoof_scope"),
        r(L, "Apps can read the attestation keybox", "A leaked keybox gets revoked and "
                + "integrity fails.", null, Fix.NONE, "settings.keybox"),
    };

    /** The table row of {@code id}, or null. */
    public static Rule rule(String id) {
        for (Rule rule : TABLE) {
            if (rule.matches(id)) {
                return rule;
            }
        }
        return null;
    }

    /** Severity of a FAIL of {@code id} (Medium when the table has no row for it). */
    public static Severity severity(String id) {
        final Rule rule = rule(id);
        return rule == null ? Severity.MEDIUM : rule.severity;
    }

    // ---- the analysis ----------------------------------------------------------------------

    /** One card on the screen. */
    public static final class Problem {
        /** Stable across runs ("fail:contacts.", "off:contacts", "gap:id.widevine"). */
        public final String key;
        public final Kind kind;
        public final Severity severity;
        public final String title;
        public final String why;
        /** The affected rule or shield, with its settings keys. */
        public final String ruleLine;
        public final Fix fix;
        /** The checks behind it, in run order. */
        public final List<String> ids = new ArrayList<>();

        Problem(String key, Kind kind, Severity severity, String title, String why,
                String ruleLine, Fix fix) {
            this.key = key;
            this.kind = kind;
            this.severity = severity;
            this.title = title;
            this.why = why;
            this.ruleLine = ruleLine;
            this.fix = fix;
        }
    }

    /** The checks of one category that aren't problems. */
    public static final class Tally {
        public int pass;
        public int fail;
        public int info;
        public int skip;
        public final List<String> ids = new ArrayList<>();
    }

    /** Checks that didn't test anything, for one reason. */
    public static final class Group {
        public final Reason reason;
        public final List<String> ids = new ArrayList<>();
        /** What they are about (categories, shields), for the one-line summary. */
        public final Set<String> subjects = new LinkedHashSet<>();

        Group(Reason reason) {
            this.reason = reason;
        }
    }

    public static final class Analysis {
        /** Broken promises and shields switched off, worst first. */
        public final List<Problem> problems = new ArrayList<>();
        /** Leaks no IchthysOS feature covers yet. */
        public final List<Problem> gaps = new ArrayList<>();
        public final Map<Reason, Group> notTested = new EnumMap<>(Reason.class);
        /** Category -> its checks, in run order. */
        public final Map<String, Tally> categories = new LinkedHashMap<>();
        public int checks;
        public int passed;

        public Severity worst() {
            Severity w = null;
            for (Problem p : problems) {
                if (w == null || p.severity.ordinal() < w.ordinal()) {
                    w = p.severity;
                }
            }
            return w;
        }

        public int notTestedCount() {
            int n = 0;
            for (Group g : notTested.values()) {
                n += g.ids.size();
            }
            return n;
        }

        /** Every problem and gap key, for History. */
        public List<Problem> all() {
            final List<Problem> out = new ArrayList<>(problems);
            out.addAll(gaps);
            return out;
        }
    }

    private static final Pattern SHIELD_NAME = Pattern.compile("shield (\\w+)");

    private Triage() {}

    /** Whether a shield's master switch is off, from a {@link Shields#describe()} map. */
    static boolean switchOff(Map<String, String> shields, Shields.Shield s) {
        if (s == null || s.switchKey == null || shields == null) {
            return false;
        }
        final String d = shields.get(s.name);
        return d != null && (d.equals("switch=0") || d.startsWith("switch=0,"));
    }

    /**
     * Sorts {@code results} (probe id -> result, run order). {@code shields} is the shield state
     * the run saw ({@link Shields#describe()}, or the report's "shields" block). {@code guard}
     * groups the passed checks by Guard's rule categories.
     */
    public static Analysis analyse(Map<String, Result> results, Map<String, String> shields,
            boolean guard) {
        final Analysis a = new Analysis();
        final Map<String, Problem> cards = new LinkedHashMap<>();

        // Shields switched off: one card per shield, whatever its checks found.
        for (Shields.Shield s : Shields.ALL) {
            if (switchOff(shields, s)) {
                // The shield's worst row names the card (clipboard: the background read).
                Rule example = null;
                for (Rule rule : TABLE) {
                    if (rule.shield == s && (example == null
                            || rule.severity.ordinal() < example.severity.ordinal())) {
                        example = rule;
                    }
                }
                final Problem p = new Problem(Kind.SHIELD_OFF.keyPrefix + ":" + s.name,
                        Kind.SHIELD_OFF, example == null ? Severity.MEDIUM : example.severity,
                        example == null ? "The " + s.name + " shield is off" : example.title,
                        "Switched off, so every app with the permission gets the real data.",
                        shieldLine(s), Fix.SHIELDS);
                cards.put(p.key, p);
            }
        }

        for (Map.Entry<String, Result> e : results.entrySet()) {
            final String id = e.getKey();
            final Result res = e.getValue();
            final Probe probe = Registry.byId(id);
            if (probe == null) {
                continue;
            }
            a.checks++;
            final Rule rule = rule(id);
            final Expect x = probe.expectation();
            final String cat = guard ? GuardRun.category(probe) : probe.category;
            final Tally t = a.categories.computeIfAbsent(cat, k -> new Tally());
            t.ids.add(id);

            if (res.verdict == Verdict.FAIL) {
                t.fail++;
                final String key = Kind.BROKEN.keyPrefix + ":" + (rule == null ? id : rule.group());
                Problem p = cards.get(key);
                if (p == null) {
                    p = rule != null
                            ? new Problem(key, Kind.BROKEN, rule.severity, rule.title, rule.why,
                                    ruleLine(rule, x), rule.fix)
                            : new Problem(key, Kind.BROKEN, Severity.MEDIUM,
                                    (x == null ? id : x.feature) + " doesn't hold",
                                    x == null ? probe.reveals : "Promised: " + x.promise + ".",
                                    x == null ? id : x.feature, Fix.NONE);
                    cards.put(key, p);
                }
                p.ids.add(id);
                continue;
            }
            if (res.verdict == Verdict.PASS) {
                t.pass++;
                a.passed++;
                continue;
            }

            // An off switch already has its card: its checks join it.
            if (rule != null && rule.shield != null && switchOff(shields, rule.shield)) {
                cards.get(Kind.SHIELD_OFF.keyPrefix + ":" + rule.shield.name).ids.add(id);
            }

            if (res.verdict == Verdict.SKIP || res.outcome == Outcome.SKIPPED) {
                t.skip++;
                notTested(a, skipReason(probe, res), probe, null);
                continue;
            }
            t.info++;
            if (rule != null && rule.gap && res.outcome == Outcome.VISIBLE) {
                final String key = Kind.GAP.keyPrefix + ":" + rule.group();
                Problem p = cards.get(key);
                if (p == null) {
                    p = new Problem(key, Kind.GAP, rule.severity, rule.title, rule.why,
                            "No IchthysOS shield covers this (stock Android behaviour)",
                            Fix.NONE);
                    cards.put(key, p);
                }
                p.ids.add(id);
                continue;
            }
            if (x != null && res.verdictWhy.startsWith("n/a: ")) {
                final Reason reason = naReason(res.verdictWhy);
                if (reason != null) {
                    notTested(a, reason, probe, res.verdictWhy);
                }
            } else if (x != null && res.verdictWhy.startsWith("condition failed")) {
                notTested(a, Reason.OTHER, probe, null);
            }
        }

        for (Problem p : cards.values()) {
            (p.kind == Kind.GAP ? a.gaps : a.problems).add(p);
        }
        final java.util.Comparator<Problem> order = (p, q) -> p.severity != q.severity
                ? p.severity.ordinal() - q.severity.ordinal() : p.kind.ordinal() - q.kind.ordinal();
        Collections.sort(a.problems, order);
        Collections.sort(a.gaps, order);
        return a;
    }

    private static void notTested(Analysis a, Reason reason, Probe probe, String why) {
        final Group g = a.notTested.computeIfAbsent(reason, Group::new);
        g.ids.add(probe.id);
        String subject = probe.category;
        if (why != null && (reason == Reason.ALLOWED || reason == Reason.NOT_LISTED)) {
            final Matcher m = SHIELD_NAME.matcher(why);
            if (m.find()) {
                subject = m.group(1);
            }
        }
        g.subjects.add(subject);
    }

    private static Reason skipReason(Probe p, Result r) {
        if (p.isTapProbe()) {
            return Reason.TAP;
        }
        final String why = String.valueOf(r.detail.get("why"));
        if (why.startsWith("manual")) {
            return Reason.MANUAL;
        }
        if (why.contains("Guard verification")) {
            return Reason.GUARD_ONLY;
        }
        if (why.contains("helper")) {
            return Reason.HELPER;
        }
        return Reason.OTHER;
    }

    /** Why an expectation didn't apply; null when it's simply n/a here (no hardware, ...). */
    private static Reason naReason(String why) {
        if (why.contains("switched off")) {
            return null; // the shield-off card covers it
        }
        if (why.contains("usage access")) {
            return Reason.USAGE_ACCESS;
        }
        if (why.contains("permission") || why.contains("not granted")
                || why.contains("stock refusal")) {
            return Reason.PERMISSION;
        }
        if (why.contains("helper app not installed")) {
            return Reason.HELPER;
        }
        if (why.contains("is allowed") || why.contains("lifts the write shield")) {
            return Reason.ALLOWED;
        }
        if (why.contains("is not on ") || why.contains("neither")) {
            return Reason.NOT_LISTED;
        }
        if (why.contains("Guard verification") || why.contains("expect_net")) {
            return Reason.GUARD_ONLY;
        }
        if (why.contains("autorun only")) {
            return Reason.OTHER;
        }
        return null;
    }

    private static String shieldLine(Shields.Shield s) {
        final StringBuilder sb = new StringBuilder("Shield ").append(s.name);
        if (s.switchKey != null) {
            sb.append(" · ").append(s.switchKey);
        }
        if (s.listKey != null) {
            sb.append(" · ").append(s.listKey);
        }
        return sb.toString();
    }

    private static String ruleLine(Rule rule, Expect x) {
        if (rule.shield != null) {
            return (x == null ? "" : x.feature + " · ") + shieldLine(rule.shield);
        }
        return x == null ? rule.group() : x.feature;
    }

    /**
     * Whether the run behind {@code results} could have found problem {@code key} again, so its
     * absence means it is fixed (a Guard run skips most groups; a skipped check proves nothing).
     */
    public static boolean evaluated(String key, Map<String, Result> results) {
        final int colon = key.indexOf(':');
        if (colon < 0) {
            return false;
        }
        final String kind = key.substring(0, colon);
        final String group = key.substring(colon + 1);
        if (kind.equals(Kind.SHIELD_OFF.keyPrefix)) {
            return true; // the shield table is read on every run
        }
        for (Map.Entry<String, Result> e : results.entrySet()) {
            if (e.getValue().verdict == Verdict.SKIP) {
                continue;
            }
            final Rule rule = rule(e.getKey());
            if (rule == null ? e.getKey().equals(group) : rule.group().equals(group)) {
                return true;
            }
        }
        return false;
    }

    /** The problem key a FAIL of {@code id} files under (for runs recorded before keys). */
    static String failKey(String id) {
        final Rule rule = rule(id);
        return Kind.BROKEN.keyPrefix + ":" + (rule == null ? id : rule.group());
    }
}
