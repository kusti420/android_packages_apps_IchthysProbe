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

import static android.Manifest.permission.READ_PHONE_STATE;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.net.ConnectivityManager;
import android.net.DhcpInfo;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.wifi.WifiManager;
import android.os.LocaleList;
import android.system.Os;
import android.telephony.CellIdentity;
import android.telephony.CellIdentityGsm;
import android.telephony.CellIdentityLte;
import android.telephony.CellIdentityNr;
import android.telephony.CellIdentityTdscdma;
import android.telephony.CellIdentityWcdma;
import android.telephony.NetworkRegistrationInfo;
import android.telephony.ServiceState;
import android.telephony.TelephonyCallback;
import android.telephony.TelephonyManager;

import org.ichthys.probe.Ctx;
import org.ichthys.probe.Outcome;
import org.ichthys.probe.Probe;
import org.ichthys.probe.Redact;
import org.ichthys.probe.Result;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.time.ZoneId;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TimeZone;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * IchthysOS "Spoofed values" (Guard gear > Spoofed values, tracker#60): everything beside the GPS
 * fix that tells an app which country the phone is in. These probes report the values RAW:
 * the 2-letter country ISO, PLMN (MCC/MNC), carrier/operator name, carrier id, time zone id
 * and locale tag are coarse region values that describe a country of hundreds of millions of
 * people, not the owner; and Guard's Verify has to compare them with the profile it wrote, so a
 * hash would be useless. Everything else (IP addresses, SSIDs, DNS servers) stays redacted as in
 * every other probe: presence and counts only. The Mullvad check reports only the country name
 * and the {@code mullvad_exit_ip} boolean.
 *
 * <p>No expectation is encoded here: the app can't read the profile (SettingsProvider hides every
 * {@code ichthys_location_*} key from apps), so Settings judges the raw values itself. Every
 * probe is time-boxed and never throws: callbacks and receivers get 2 s, the HTTP check 10 s.
 */
public final class SpoofProbes {
    static final String CAT = "Spoofed values";

    static final String MULLVAD_URL = "https://am.i.mullvad.net/json";

    /** The gsm.* / debug / persist properties the spoof profile rewrites in the app process. */
    static final String[] SPOOFED_PROPS = {
        "gsm.sim.operator.iso-country", "gsm.operator.iso-country",
        "gsm.sim.operator.numeric", "gsm.operator.numeric",
        "gsm.sim.operator.alpha", "gsm.operator.alpha",
        "gsm.operator.isroaming", "debug.tracing.mcc", "debug.tracing.mnc",
        "persist.sys.locale", "ro.boot.sales_code",
    };

    private SpoofProbes() {}

    /** "empty" for null or "", otherwise the value itself (callers pass coarse values only). */
    static String raw(CharSequence s) {
        return s == null || s.length() == 0 ? "empty" : s.toString();
    }

    /**
     * android.os.SystemProperties.get(String) through reflection (it is a SystemApi, not in the
     * SDK stubs). This is the in-process read every library uses, and the one the spoof profile
     * rewrites. Returns "empty" for an unset property and "blocked (Exception)" when the hidden-API
     * policy refuses the call.
     */
    static String sysprop(String key) {
        try {
            final Class<?> sp = Class.forName("android.os.SystemProperties");
            final Method get = sp.getMethod("get", String.class);
            final Object v = get.invoke(null, key);
            return raw(v == null ? null : v.toString());
        } catch (Throwable t) {
            return "blocked (" + t.getClass().getSimpleName() + ")";
        }
    }

    /** The same property through the getprop binary: a child process, so no in-process hook. */
    static String getpropRaw(String key) {
        final String v = SystemProbes.getprop(key);
        return v == null ? "unreadable" : raw(v);
    }

    private static String mcc(CellIdentity ci) {
        if (ci instanceof CellIdentityLte) {
            return ((CellIdentityLte) ci).getMccString();
        }
        if (ci instanceof CellIdentityNr) {
            return ((CellIdentityNr) ci).getMccString();
        }
        if (ci instanceof CellIdentityWcdma) {
            return ((CellIdentityWcdma) ci).getMccString();
        }
        if (ci instanceof CellIdentityGsm) {
            return ((CellIdentityGsm) ci).getMccString();
        }
        if (ci instanceof CellIdentityTdscdma) {
            return ((CellIdentityTdscdma) ci).getMccString();
        }
        return null;
    }

    private static String mnc(CellIdentity ci) {
        if (ci instanceof CellIdentityLte) {
            return ((CellIdentityLte) ci).getMncString();
        }
        if (ci instanceof CellIdentityNr) {
            return ((CellIdentityNr) ci).getMncString();
        }
        if (ci instanceof CellIdentityWcdma) {
            return ((CellIdentityWcdma) ci).getMncString();
        }
        if (ci instanceof CellIdentityGsm) {
            return ((CellIdentityGsm) ci).getMncString();
        }
        if (ci instanceof CellIdentityTdscdma) {
            return ((CellIdentityTdscdma) ci).getMncString();
        }
        return null;
    }

    private static String join(Set<String> s) {
        return s.isEmpty() ? "none" : String.join(",", s);
    }

    /** Fills {@code r} with the PLMN-bearing fields of a ServiceState. */
    @SuppressWarnings("deprecation") // isRegistered: its SystemApi replacement isn't in the SDK
    private static void describe(ServiceState ss, Result r) {
        r.put("state", ss.getState());
        r.put("operator_numeric", raw(ss.getOperatorNumeric()));
        r.put("operator_alpha_long", raw(ss.getOperatorAlphaLong()));
        r.put("operator_alpha_short", raw(ss.getOperatorAlphaShort()));
        r.put("roaming", ss.getRoaming());
        final List<NetworkRegistrationInfo> nris = ss.getNetworkRegistrationInfoList();
        r.put("nri_count", nris.size());
        final Set<String> plmns = new LinkedHashSet<>();
        final Set<String> cells = new LinkedHashSet<>();
        int i = 0;
        for (NetworkRegistrationInfo nri : nris) {
            final String plmn = nri.getRegisteredPlmn();
            if (plmn != null && !plmn.isEmpty()) {
                plmns.add(plmn);
            }
            final CellIdentity ci = nri.getCellIdentity();
            String cell = "null";
            if (ci != null) {
                final String m = mcc(ci);
                final String n = mnc(ci);
                cell = m == null && n == null ? "no-plmn" : String.valueOf(m) + String.valueOf(n);
                if (m != null || n != null) {
                    cells.add(cell);
                }
            }
            r.put("nri" + i, "domain=" + nri.getDomain() + " transport=" + nri.getTransportType()
                    + " registered=" + nri.isRegistered() + " rat="
                    + nri.getAccessNetworkTechnology() + " plmn=" + raw(plmn) + " cell=" + cell);
            i++;
        }
        r.put("nri_plmns", join(plmns));
        r.put("cell_mccmnc", join(cells));
    }

    private static boolean vpn(ConnectivityManager cm, Network n) {
        final NetworkCapabilities nc = cm.getNetworkCapabilities(n);
        return nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
    }

    private static String transports(NetworkCapabilities nc) {
        if (nc == null) {
            return "?";
        }
        final StringBuilder sb = new StringBuilder();
        if (nc.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
            sb.append("wifi ");
        }
        if (nc.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
            sb.append("cell ");
        }
        if (nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            sb.append("vpn ");
        }
        if (nc.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
            sb.append("eth ");
        }
        if (nc.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) {
            sb.append("bt ");
        }
        return sb.length() == 0 ? "other" : sb.toString().trim();
    }

    /** Country-detector source constants (android.location.Country, hidden). */
    private static String sourceName(int source) {
        switch (source) {
            case 0: return "network";
            case 1: return "location";
            case 2: return "sim";
            case 3: return "locale";
            default: return "unknown";
        }
    }

    public static void add(List<Probe> out) {
        out.add(new Probe(CAT, "spoof.telephony_country",
                "Country, PLMN, operator and carrier id from TelephonyManager (no permission; "
                        + "raw coarse values).",
                Probe.NONE,
                c -> {
                    final TelephonyManager tm = c.app.getSystemService(TelephonyManager.class);
                    if (tm == null || !c.hasFeature(PackageManager.FEATURE_TELEPHONY)) {
                        return Result.unavailable("no telephony");
                    }
                    final String simCountry = tm.getSimCountryIso();
                    final String netCountry = tm.getNetworkCountryIso();
                    final Result r = (simCountry != null && !simCountry.isEmpty())
                            || (netCountry != null && !netCountry.isEmpty())
                            ? Result.visible() : Result.empty();
                    r.put("sim_state", tm.getSimState());
                    r.put("sim_country", raw(simCountry));
                    r.put("network_country", raw(netCountry));
                    int modems = 1;
                    try {
                        modems = tm.getActiveModemCount();
                    } catch (RuntimeException e) {
                        // Keep the single-slot value.
                    }
                    for (int slot = 0; slot < modems; slot++) {
                        try {
                            r.put("network_country_slot" + slot,
                                    raw(tm.getNetworkCountryIso(slot)));
                        } catch (RuntimeException e) {
                            r.put("network_country_slot" + slot, Redact.exception(e));
                        }
                    }
                    r.put("sim_operator", raw(tm.getSimOperator()));
                    r.put("network_operator", raw(tm.getNetworkOperator()));
                    r.put("sim_operator_name", raw(tm.getSimOperatorName()));
                    r.put("network_operator_name", raw(tm.getNetworkOperatorName()));
                    r.put("roaming", tm.isNetworkRoaming());
                    r.put("sim_carrier_id", tm.getSimCarrierId());
                    r.put("sim_carrier_id_name", raw(tm.getSimCarrierIdName()));
                    return r;
                }));

        out.add(new Probe(CAT, "spoof.service_state",
                "Registered PLMNs, operator and cell MCC/MNC from a ServiceState callback "
                        + "(no permission; raw coarse values).",
                Probe.NONE,
                c -> {
                    final TelephonyManager tm = c.app.getSystemService(TelephonyManager.class);
                    if (tm == null || !c.hasFeature(PackageManager.FEATURE_TELEPHONY)) {
                        return Result.unavailable("no telephony");
                    }
                    final AtomicReference<ServiceState> got = new AtomicReference<>();
                    final CountDownLatch done = new CountDownLatch(1);
                    final class Cb extends TelephonyCallback
                            implements TelephonyCallback.ServiceStateListener {
                        @Override
                        public void onServiceStateChanged(ServiceState ss) {
                            got.compareAndSet(null, ss);
                            done.countDown();
                        }
                    }
                    final Cb cb = new Cb();
                    boolean registered = false;
                    boolean delivered = false;
                    String regError = null;
                    try {
                        tm.registerTelephonyCallback(task -> c.worker.post(task), cb);
                        registered = true;
                        delivered = done.await(2, TimeUnit.SECONDS);
                    } catch (SecurityException | IllegalStateException e) {
                        regError = Redact.exception(e);
                    } finally {
                        if (registered) {
                            try {
                                tm.unregisterTelephonyCallback(cb);
                            } catch (RuntimeException e) {
                                // Already gone.
                            }
                        }
                    }
                    ServiceState ss = got.get();
                    String source = delivered ? "callback" : "none";
                    if (ss == null && c.granted(READ_PHONE_STATE)) {
                        try {
                            ss = tm.getServiceState();
                            if (ss != null) {
                                source = "getServiceState";
                            }
                        } catch (SecurityException e) {
                            regError = Redact.exception(e);
                        }
                    }
                    final Result r;
                    if (ss == null) {
                        r = regError != null && !registered
                                ? Result.blockedPermission(regError)
                                : Result.empty().put("why", "no ServiceState within 2 s");
                    } else {
                        r = Result.visible();
                    }
                    r.put("registered", registered);
                    r.put("delivered", delivered);
                    r.put("source", source);
                    if (regError != null) {
                        r.put("error", regError);
                    }
                    if (ss != null) {
                        describe(ss, r);
                    }
                    return r;
                })
                .timeout(8000));

        out.add(new Probe(CAT, "spoof.configuration",
                "Configuration mcc/mnc, default locales, and the gsm.*/debug.tracing properties "
                        + "as SystemProperties.get and getprop report them.",
                Probe.NONE,
                c -> {
                    final Configuration cfg = c.app.getResources().getConfiguration();
                    final Result r = cfg.mcc != 0 ? Result.visible() : Result.empty();
                    r.put("config_mcc", cfg.mcc);
                    r.put("config_mnc", cfg.mnc);
                    r.put("config_mnc_zero", cfg.mnc == Configuration.MNC_ZERO);
                    r.put("config_locales", raw(cfg.getLocales().toLanguageTags()));
                    r.put("default_locales", raw(LocaleList.getDefault().toLanguageTags()));
                    r.put("locale_default", raw(Locale.getDefault().toLanguageTag()));
                    for (String key : SPOOFED_PROPS) {
                        r.put("prop_" + key, sysprop(key));
                    }
                    // The getprop binary runs outside the process: it bypasses any in-process
                    // rewrite and shows what the system itself holds.
                    r.put("getprop_gsm.sim.operator.iso-country",
                            getpropRaw("gsm.sim.operator.iso-country"));
                    r.put("getprop_gsm.operator.iso-country",
                            getpropRaw("gsm.operator.iso-country"));
                    r.put("getprop_gsm.sim.operator.numeric",
                            getpropRaw("gsm.sim.operator.numeric"));
                    r.put("getprop_gsm.operator.numeric", getpropRaw("gsm.operator.numeric"));
                    r.put("getprop_ro.boot.sales_code", getpropRaw("ro.boot.sales_code"));
                    return r;
                })
                .timeout(15_000));

        out.add(new Probe(CAT, "spoof.timezone",
                "The default time zone as java.util, android.icu, java.time, the TZ environment "
                        + "(bionic) and persist.sys.timezone report it.",
                Probe.NONE,
                c -> {
                    final String javaTz = TimeZone.getDefault().getID();
                    final Result r = Result.visible();
                    r.put("java_tz", raw(javaTz));
                    String icu;
                    try {
                        icu = android.icu.util.TimeZone.getDefault().getID();
                    } catch (RuntimeException e) {
                        icu = Redact.exception(e);
                    }
                    r.put("icu_tz", raw(icu));
                    String zone;
                    try {
                        zone = ZoneId.systemDefault().getId();
                    } catch (RuntimeException e) {
                        zone = Redact.exception(e);
                    }
                    r.put("zone_id", raw(zone));
                    String env;
                    try {
                        env = Os.getenv("TZ");
                    } catch (RuntimeException e) {
                        env = Redact.exception(e);
                    }
                    r.put("env_TZ", env == null ? "unset" : raw(env));
                    r.put("prop_persist.sys.timezone", sysprop("persist.sys.timezone"));
                    r.put("getprop_persist.sys.timezone", getpropRaw("persist.sys.timezone"));
                    final TimeZone tz = TimeZone.getDefault();
                    r.put("raw_offset_min", tz.getRawOffset() / 60_000);
                    r.put("dst", tz.inDaylightTime(new Date()));
                    r.put("zone_name", raw(new SimpleDateFormat("zzzz", Locale.US)
                            .format(new Date())));
                    r.put("consistent", javaTz != null && javaTz.equals(icu)
                            && javaTz.equals(zone));
                    return r;
                }));

        out.add(new Probe(CAT, "spoof.emergency",
                "Which of 911, 999, 112, 000 the phone treats as emergency numbers "
                        + "(the list depends on the country).",
                Probe.NONE,
                c -> {
                    final TelephonyManager tm = c.app.getSystemService(TelephonyManager.class);
                    if (tm == null || !c.hasFeature(PackageManager.FEATURE_TELEPHONY)) {
                        return Result.unavailable("no telephony");
                    }
                    final Result r = Result.visible();
                    final StringBuilder yes = new StringBuilder();
                    for (String n : new String[] {"911", "999", "112", "000", "110", "119"}) {
                        try {
                            final boolean e = tm.isEmergencyNumber(n);
                            r.put("emergency_" + n, e);
                            if (e) {
                                yes.append(yes.length() == 0 ? "" : ",").append(n);
                            }
                        } catch (IllegalStateException | SecurityException e) {
                            r.put("emergency_" + n, Redact.exception(e));
                        }
                    }
                    r.put("emergency_numbers", yes.length() == 0 ? "none" : yes.toString());
                    return r;
                }));

        out.add(new Probe(CAT, "spoof.country_detector",
                "CountryDetectorService's answer (hidden API, reflection): country iso and its "
                        + "source, or blocked.",
                Probe.NONE,
                c -> {
                    final Object cd;
                    try {
                        cd = c.app.getSystemService("country_detector");
                    } catch (RuntimeException e) {
                        return Result.unavailable(Redact.exception(e));
                    }
                    if (cd == null) {
                        return Result.unavailable("no country_detector service")
                                .put("country_iso", "unavailable");
                    }
                    final Object country;
                    try {
                        final Method detect = cd.getClass().getMethod("detectCountry");
                        country = detect.invoke(cd);
                    } catch (Throwable t) {
                        return Result.blockedPermission("hidden API refused: "
                                + Redact.exception(t)).put("country_iso", "blocked");
                    }
                    if (country == null) {
                        return Result.empty().put("country_iso", "null")
                                .put("source", "none");
                    }
                    try {
                        final Object iso = country.getClass().getMethod("getCountryIso")
                                .invoke(country);
                        final Object src = country.getClass().getMethod("getSource")
                                .invoke(country);
                        final int source = src instanceof Integer ? (Integer) src : -1;
                        return Result.visible()
                                .put("country_iso", raw(iso == null ? null : iso.toString()))
                                .put("source", source)
                                .put("source_name", sourceName(source));
                    } catch (Throwable t) {
                        return Result.blockedPermission("hidden API refused: "
                                + Redact.exception(t)).put("country_iso", "blocked");
                    }
                })
                .timeout(6000));

        out.add(new Probe(CAT, "spoof.network_visibility",
                "Networks and DNS the app can see (counts only), DHCP info, and the public IP's "
                        + "country via am.i.mullvad.net (country and exit-ip flag only).",
                Probe.NONE,
                c -> {
                    final ConnectivityManager cm =
                            c.app.getSystemService(ConnectivityManager.class);
                    final Result r = Result.visible();
                    int networks = 0;
                    int vpns = 0;
                    int nonVpnDns = 0;
                    int vpnDns = 0;
                    try {
                        @SuppressWarnings("deprecation")
                        final Network[] all = cm.getAllNetworks();
                        networks = all.length;
                        int i = 0;
                        for (Network n : all) {
                            final NetworkCapabilities nc = cm.getNetworkCapabilities(n);
                            final boolean isVpn = nc != null
                                    && nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
                            final LinkProperties lp = cm.getLinkProperties(n);
                            final int dns = lp == null ? 0 : lp.getDnsServers().size();
                            if (isVpn) {
                                vpns++;
                                vpnDns += dns;
                            } else {
                                nonVpnDns += dns;
                            }
                            r.put("net" + i, transports(nc) + " dns=" + dns
                                    + " addrs=" + (lp == null ? 0 : lp.getLinkAddresses().size())
                                    + " routes=" + (lp == null ? 0 : lp.getRoutes().size())
                                    + " iface=" + (lp == null ? "absent"
                                            : Redact.length(lp.getInterfaceName())));
                            i++;
                        }
                    } catch (RuntimeException e) {
                        r.put("networks_error", Redact.exception(e));
                    }
                    r.put("networks", networks);
                    r.put("vpn_networks", vpns);
                    r.put("non_vpn_dns_servers", nonVpnDns);
                    r.put("vpn_dns_servers", vpnDns);
                    final Network active = cm.getActiveNetwork();
                    r.put("active_network", active != null);
                    r.put("active_is_vpn", active != null && vpn(cm, active));
                    final LinkProperties alp = active == null ? null : cm.getLinkProperties(active);
                    r.put("active_dns_servers", alp == null ? 0 : alp.getDnsServers().size());

                    try {
                        final WifiManager wm = c.app.getSystemService(WifiManager.class);
                        @SuppressWarnings("deprecation")
                        final DhcpInfo d = wm == null ? null : wm.getDhcpInfo();
                        if (d == null) {
                            r.put("dhcp", "null");
                        } else {
                            r.put("dhcp", "present");
                            r.put("dhcp_dns1_set", d.dns1 != 0);
                            r.put("dhcp_dns2_set", d.dns2 != 0);
                            r.put("dhcp_gateway_set", d.gateway != 0);
                            r.put("dhcp_ip_set", d.ipAddress != 0);
                        }
                    } catch (RuntimeException e) {
                        r.put("dhcp", Redact.exception(e));
                    }

                    // The public-IP check: only the country name and the Mullvad flag.
                    HttpURLConnection h = null;
                    try {
                        h = (HttpURLConnection) new URL(MULLVAD_URL).openConnection();
                        h.setConnectTimeout(10_000);
                        h.setReadTimeout(10_000);
                        h.setInstanceFollowRedirects(false);
                        h.setRequestProperty("Accept", "application/json");
                        final int code = h.getResponseCode();
                        r.put("ip_check_status", code);
                        if (code != 200) {
                            r.put("ip_check", "error");
                            r.put("ip_check_error", "HTTP " + code);
                        } else {
                            final StringBuilder sb = new StringBuilder();
                            try (BufferedReader br = new BufferedReader(new InputStreamReader(
                                    h.getInputStream(), StandardCharsets.UTF_8))) {
                                String line;
                                while ((line = br.readLine()) != null && sb.length() < 64_000) {
                                    sb.append(line);
                                }
                            }
                            final JSONObject j = new JSONObject(sb.toString());
                            r.put("ip_check", "ok");
                            r.put("ip_country", raw(j.optString("country", "")));
                            r.put("mullvad_exit_ip", j.optBoolean("mullvad_exit_ip", false));
                        }
                    } catch (Exception e) {
                        final boolean blocked = NetProbes.uidBlocked(c);
                        r.put("ip_check", blocked || active == null ? "offline" : "error");
                        r.put("ip_check_error", Redact.exception(e));
                        r.put("uid_blocked", blocked);
                    } finally {
                        if (h != null) {
                            h.disconnect();
                        }
                    }
                    if (!"ok".equals(r.detail.get("ip_check"))) {
                        final Result o = "offline".equals(r.detail.get("ip_check"))
                                ? (NetProbes.uidBlocked(c)
                                        ? Result.blockedIchthys("network reports this uid BLOCKED")
                                        : Result.empty().put("why", "offline: no usable network"))
                                : Result.of(Outcome.VISIBLE);
                        o.detail.putAll(r.detail);
                        return o;
                    }
                    return r;
                })
                .timeout(30_000));

        out.add(new Probe(CAT, "spoof.broadcasts",
                "Whether a network-country or time-zone changed broadcast reaches the app within "
                        + "2 s (informational; they are not sticky).",
                Probe.NONE,
                c -> {
                    final AtomicInteger country = new AtomicInteger();
                    final AtomicInteger timezone = new AtomicInteger();
                    final AtomicReference<String> countryExtra = new AtomicReference<>();
                    final AtomicReference<String> tzExtra = new AtomicReference<>();
                    final BroadcastReceiver rx = new BroadcastReceiver() {
                        @Override
                        public void onReceive(Context ctx, Intent intent) {
                            final String a = intent == null ? null : intent.getAction();
                            if (TelephonyManager.ACTION_NETWORK_COUNTRY_CHANGED.equals(a)) {
                                country.incrementAndGet();
                                countryExtra.compareAndSet(null, raw(intent.getStringExtra(
                                        TelephonyManager.EXTRA_NETWORK_COUNTRY)));
                            } else if (Intent.ACTION_TIMEZONE_CHANGED.equals(a)) {
                                timezone.incrementAndGet();
                                tzExtra.compareAndSet(null, raw(intent.getStringExtra(
                                        Intent.EXTRA_TIMEZONE)));
                            }
                        }
                    };
                    final IntentFilter f = new IntentFilter();
                    f.addAction(TelephonyManager.ACTION_NETWORK_COUNTRY_CHANGED);
                    f.addAction(Intent.ACTION_TIMEZONE_CHANGED);
                    boolean registered = false;
                    String error = null;
                    try {
                        final Intent sticky = c.app.registerReceiver(rx, f, null, c.worker,
                                Context.RECEIVER_NOT_EXPORTED);
                        registered = true;
                        if (sticky != null) {
                            rx.onReceive(c.app, sticky);
                        }
                        Ctx.sleep(2000);
                    } catch (RuntimeException e) {
                        error = Redact.exception(e);
                    } finally {
                        if (registered) {
                            try {
                                c.app.unregisterReceiver(rx);
                            } catch (RuntimeException e) {
                                // Already gone.
                            }
                        }
                    }
                    final boolean any = country.get() > 0 || timezone.get() > 0;
                    final Result r = error != null ? Result.of(Outcome.ERROR).put("error", error)
                            : any ? Result.visible() : Result.empty();
                    r.put("registered", registered);
                    r.put("waited_ms", 2000);
                    r.put("country_broadcasts", country.get());
                    r.put("timezone_broadcasts", timezone.get());
                    r.put("country_extra", countryExtra.get() == null ? "none"
                            : countryExtra.get());
                    r.put("timezone_extra", tzExtra.get() == null ? "none" : tzExtra.get());
                    r.put("note", "nothing within 2 s is normal; a spoofed app must never get "
                            + "the real country or zone");
                    return r;
                })
                .timeout(6000));
    }
}
