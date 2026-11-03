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

import static org.ichthys.probe.Probe.perms;

import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.RouteInfo;
import android.os.SystemClock;

import org.ichthys.probe.Ctx;
import org.ichthys.probe.Expect;
import org.ichthys.probe.GuardRun;
import org.ichthys.probe.Outcome;
import org.ichthys.probe.Probe;
import org.ichthys.probe.Redact;
import org.ichthys.probe.Result;

import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.List;

/**
 * Network: what the app learns about the connection, whether it gets out at all (Guard's
 * per-app firewall), and what DNS answers for trackers (hosts blocklist and Guard trackers).
 */
public final class NetProbes {
    static final String CAT = "Network";

    static final String ACCESS_LOCAL_NETWORK = "android.permission.ACCESS_LOCAL_NETWORK";

    private static final String SRC_GUARD_NET =
            "frameworks/base/services/core/java/com/android/server/ichthys/guard/"
                    + "IchthysGuardService.java:378-443 (DENY -> FIREWALL_CHAIN_OEM_DENY_3; DNS "
                    + "EAI_FAIL via DnsResolver, NetworkInfo BLOCKED)";
    private static final String SRC_HOSTS =
            "device/samsung/a52sxq/configs/hosts/hosts -> /system/etc/hosts (0.0.0.0 entries); "
                    + "Guard notification \"The system-wide blocklist stops common trackers.\"";
    private static final String SRC_GUARD_TRACKERS =
            "packages/apps/Settings/src/com/android/settings/ichthys/guard/model/Rules.kt:124"
                    + " (HostRules.ENFORCED = false: tracker and host rules are saved and shown,"
                    + " not applied), res/raw/ichthys_guard_trackers.json; services-fixes.md G5"
                    + " (not implemented)";
    private static final String SRC_LAN =
            "IchthysGuardService.java:572-645,1339-1355 (new user apps: ACCESS_LOCAL_NETWORK "
                    + "revoked and USER_FIXED)";

    /** Trackers the hosts file lists (checked in the tree). */
    static final String[] HOSTS_TRACKERS = {
        "app-measurement.com", "t.appsflyer.com", "api.branch.io", "analytics.google.com",
        "api.mixpanel.com",
    };
    /** Guard tracker-list domains the hosts file does not list: only Guard could block them. */
    static final String[] GUARD_TRACKERS = {
        "doubleclick.net", "googleadservices.com", "graph.facebook.com", "adjust.com",
        "firebase-settings.crashlytics.com", "ingest.sentry.io",
    };
    static final String[] CONTROL_HOSTS = {"example.com", "wikipedia.org", "kernel.org"};

    private NetProbes() {}

    /** Guard network expectation, from the host's {@code --es expect_net allowed|blocked}. */
    private static Expect guardNet(String promise) {
        return Expect.of("Guard per-app network block", SRC_GUARD_NET, promise)
                .when(c -> c.option("expect_net") == null
                        ? "Guard policy unknown to the app (--es expect_net allowed|blocked)"
                        : null)
                .check((c, r) -> {
                    final boolean blocked = "blocked".equals(c.option("expect_net"));
                    if (blocked && r.outcome == Outcome.VISIBLE) {
                        return "network reachable although Guard blocks this app";
                    }
                    if (!blocked && r.outcome != Outcome.VISIBLE) {
                        return "network not reachable although Guard allows this app ("
                                + r.outcome.key + ")";
                    }
                    return null;
                });
    }

    /** "blocked" when the active network reports the uid as blocked (firewall chain). */
    static boolean uidBlocked(Ctx c) {
        final ConnectivityManager cm = c.app.getSystemService(ConnectivityManager.class);
        @SuppressWarnings("deprecation")
        final NetworkInfo ni = cm.getActiveNetworkInfo();
        return ni != null && ni.getDetailedState() == NetworkInfo.DetailedState.BLOCKED;
    }

    /** Resolves {@code hosts}: how many resolved, how many to 0.0.0.0/::, how many failed. */
    static int[] resolve(String[] hosts) {
        int ok = 0;
        int sinkholed = 0;
        int failed = 0;
        for (String h : hosts) {
            try {
                final InetAddress[] a = InetAddress.getAllByName(h);
                boolean sink = a.length > 0;
                for (InetAddress x : a) {
                    sink &= x.isAnyLocalAddress();
                }
                if (sink) {
                    sinkholed++;
                } else {
                    ok++;
                }
            } catch (UnknownHostException e) {
                failed++;
            }
        }
        return new int[] {ok, sinkholed, failed};
    }

    /**
     * IchthysOS: resolves {@code hosts} and says whether a blocklist answered. Only 0.0.0.0 for
     * every host counts as blocked. A failed lookup does not: with Guard blocking the app
     * (run c) DnsResolver refuses every query, the hosts file included, and that used to pass
     * as "blocked" too.
     */
    static Result sinkholeResult(Ctx c, String[] hosts) {
        final int[] r = resolve(hosts);
        final Result res;
        if (r[1] == hosts.length) {
            res = Result.blockedIchthys("all sinkholed (0.0.0.0)");
        } else if (r[0] > 0) {
            res = Result.visible();
        } else if (r[1] == 0 && uidBlocked(c)) {
            res = Result.unavailable("DNS refused for this uid (network blocked), so no "
                    + "blocklist answer can be seen");
        } else {
            res = Result.empty().put("why", "lookups failed instead of 0.0.0.0");
        }
        return res.put("checked", hosts.length).put("resolved", r[0]).put("sinkholed", r[1])
                .put("failed", r[2]);
    }

    private static String kind(InetAddress a) {
        if (a instanceof Inet4Address) {
            return a.isSiteLocalAddress() ? "v4-private" : a.isLoopbackAddress() ? "v4-loop"
                    : a.isLinkLocalAddress() ? "v4-link" : "v4-public";
        }
        if (a instanceof Inet6Address) {
            final byte b0 = a.getAddress()[0];
            return a.isLinkLocalAddress() ? "v6-link" : (b0 & 0xfe) == 0xfc ? "v6-ula"
                    : "v6-global";
        }
        return "other";
    }

    public static void add(List<Probe> out) {
        out.add(new Probe(CAT, "net.active",
                "The active network: transport, metered, validated, VPN, blocked state.",
                Probe.NONE,
                c -> {
                    final ConnectivityManager cm =
                            c.app.getSystemService(ConnectivityManager.class);
                    final Network n = cm.getActiveNetwork();
                    @SuppressWarnings("deprecation")
                    final NetworkInfo ni = cm.getActiveNetworkInfo();
                    boolean vpn = false;
                    for (Network x : cm.getAllNetworks()) {
                        final NetworkCapabilities nc = cm.getNetworkCapabilities(x);
                        vpn |= nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
                    }
                    final Result r = n == null ? Result.empty() : Result.visible();
                    r.put("active", n != null);
                    r.put("state", ni == null ? "none" : String.valueOf(ni.getDetailedState()));
                    if (n != null) {
                        final NetworkCapabilities nc = cm.getNetworkCapabilities(n);
                        if (nc != null) {
                            r.put("wifi", nc.hasTransport(NetworkCapabilities.TRANSPORT_WIFI));
                            r.put("cellular",
                                    nc.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR));
                            r.put("validated", nc.hasCapability(
                                    NetworkCapabilities.NET_CAPABILITY_VALIDATED));
                            r.put("metered", !nc.hasCapability(
                                    NetworkCapabilities.NET_CAPABILITY_NOT_METERED));
                            r.put("down_kbps", Redact.bucket(nc.getLinkDownstreamBandwidthKbps()));
                        }
                    }
                    r.put("vpn_present", vpn);
                    r.put("restrict_background", cm.getRestrictBackgroundStatus());
                    return r;
                }));

        out.add(new Probe(CAT, "net.link",
                "Addresses (kinds only), DNS servers, Private DNS, proxy, MTU of the network.",
                Probe.NONE,
                c -> {
                    final ConnectivityManager cm =
                            c.app.getSystemService(ConnectivityManager.class);
                    final Network n = cm.getActiveNetwork();
                    final LinkProperties lp = n == null ? null : cm.getLinkProperties(n);
                    if (lp == null) {
                        return Result.empty().put("link", "none");
                    }
                    final StringBuilder kinds = new StringBuilder();
                    for (LinkAddress la : lp.getLinkAddresses()) {
                        kinds.append(kind(la.getAddress())).append(' ');
                    }
                    return Result.visible()
                            .put("interface", Redact.length(lp.getInterfaceName()))
                            .put("addresses", kinds.toString().trim())
                            .put("dns_servers", lp.getDnsServers().size())
                            .put("private_dns", lp.isPrivateDnsActive())
                            .put("private_dns_name", Redact.length(lp.getPrivateDnsServerName()))
                            .put("search_domains", Redact.length(lp.getDomains()))
                            .put("proxy", lp.getHttpProxy() != null)
                            .put("mtu", lp.getMtu());
                }));

        out.add(new Probe(CAT, "net.interfaces",
                "Network interfaces visible to Java (names count, MACs readable).",
                Probe.NONE,
                c -> {
                    int n = 0;
                    int macs = 0;
                    for (NetworkInterface ni : Collections.list(
                            NetworkInterface.getNetworkInterfaces())) {
                        n++;
                        try {
                            if (ni.getHardwareAddress() != null) {
                                macs++;
                            }
                        } catch (Exception e) {
                            // Refused: counts as unreadable.
                        }
                    }
                    return Result.count("interfaces", n).put("macs_readable", macs);
                }));

        out.add(new Probe(CAT, "net.https",
                "A plain HTTPS request to the internet (status and latency only).",
                perms(android.Manifest.permission.INTERNET),
                c -> {
                    final long t0 = SystemClock.elapsedRealtime();
                    try {
                        final HttpURLConnection h = (HttpURLConnection) new URL(
                                "https://connectivitycheck.gstatic.com/generate_204")
                                .openConnection();
                        h.setConnectTimeout(6000);
                        h.setReadTimeout(6000);
                        h.setInstanceFollowRedirects(false);
                        final int code = h.getResponseCode();
                        h.disconnect();
                        return Result.visible().put("status", code)
                                .put("ms", Redact.bucket(SystemClock.elapsedRealtime() - t0));
                    } catch (Exception e) {
                        final Result r = uidBlocked(c)
                                ? Result.blockedIchthys("network reports this uid BLOCKED")
                                : Result.of(Outcome.ERROR);
                        return r.put("error", Redact.exception(e));
                    }
                })
                .timeout(15_000)
                .expect(guardNet("HTTPS works when Guard allows the app, fails when it blocks")));

        out.add(new Probe(CAT, "net.dns_control",
                "DNS resolution of ordinary hosts (example.com, wikipedia.org, kernel.org).",
                perms(android.Manifest.permission.INTERNET),
                c -> {
                    final int[] r = resolve(CONTROL_HOSTS);
                    final Result res;
                    if (r[0] > 0) {
                        res = Result.visible();
                    } else if (uidBlocked(c)) {
                        res = Result.blockedIchthys("network reports this uid BLOCKED");
                    } else {
                        res = Result.empty();
                    }
                    return res.put("resolved", r[0]).put("sinkholed", r[1]).put("failed", r[2]);
                })
                .timeout(20_000)
                .expect(guardNet("DNS works when Guard allows the app, fails when it blocks")));

        out.add(new Probe(CAT, "net.dns_trackers_hosts",
                "DNS answers for trackers on the hosts blocklist (0.0.0.0 = blocked).",
                perms(android.Manifest.permission.INTERNET),
                c -> sinkholeResult(c, HOSTS_TRACKERS))
                .timeout(20_000)
                .expect(Expect.of("System-wide tracker blocklist (hosts file)", SRC_HOSTS,
                        "listed tracker hosts resolve to 0.0.0.0")
                        .outcomes(Outcome.BLOCKED_ICHTHYS)
                        .when(c -> "blocked".equals(c.option("expect_net"))
                                ? "Guard blocks this app's network; DNS can't answer at all"
                                : null)));

        out.add(new Probe(CAT, "net.dns_trackers_guard",
                "DNS answers for Guard's known trackers that the hosts file doesn't list.",
                perms(android.Manifest.permission.INTERNET),
                c -> sinkholeResult(c, GUARD_TRACKERS))
                .timeout(25_000)
                .expect(Expect.of("Guard tracker blocking", SRC_GUARD_TRACKERS,
                        "none: Guard shows trackers but doesn't block them (display only); "
                                + "only the hosts blocklist blocks")
                        .outcomes(Outcome.BLOCKED_ICHTHYS)
                        // Guard saves per-app tracker rules but doesn't apply them yet
                        // (HostRules.ENFORCED = false) and its UI says so; blocking this list
                        // for every app would break apps that need graph.facebook.com. So
                        // nothing is promised here: reported, never a failure.
                        .when(c -> "blocked".equals(c.option("expect_net"))
                                ? "whole app is blocked; says nothing about trackers"
                                : "Guard tracker rules not enforced yet (HostRules.ENFORCED = "
                                        + "false; its UI says so); only the hosts blocklist "
                                        + "is promised")));

        out.add(new Probe(CAT, "net.lan",
                "Whether the app reaches the LAN gateway (TCP 53/80) and holds "
                        + "ACCESS_LOCAL_NETWORK.",
                perms(ACCESS_LOCAL_NETWORK),
                c -> {
                    final ConnectivityManager cm =
                            c.app.getSystemService(ConnectivityManager.class);
                    final Network n = cm.getActiveNetwork();
                    final LinkProperties lp = n == null ? null : cm.getLinkProperties(n);
                    InetAddress gw = null;
                    if (lp != null) {
                        for (RouteInfo ri : lp.getRoutes()) {
                            if (ri.isDefaultRoute() && ri.getGateway() instanceof Inet4Address
                                    && ri.getGateway().isSiteLocalAddress()) {
                                gw = ri.getGateway();
                            }
                        }
                    }
                    if (gw == null) {
                        return Result.unavailable("no private IPv4 gateway (cellular or VPN)");
                    }
                    String how = null;
                    for (int port : new int[] {53, 80, 443}) {
                        try (Socket s = new Socket()) {
                            s.connect(new InetSocketAddress(gw, port), 1500);
                            how = "tcp/" + port + " connected";
                            break;
                        } catch (java.net.ConnectException e) {
                            final String m = String.valueOf(e.getMessage());
                            if (m.contains("ECONNREFUSED")) {
                                how = "tcp/" + port + " refused (host reached)";
                                break;
                            }
                            how = Redact.exception(e);
                        } catch (Exception e) {
                            how = Redact.exception(e);
                        }
                    }
                    final boolean reached = how != null && (how.contains("connected")
                            || how.contains("refused (host"));
                    final Result r = reached ? Result.visible()
                            : how != null && how.contains("EPERM")
                                    ? Result.blockedIchthys("EPERM (local network blocked)")
                                    : Result.empty();
                    return r.put("gateway", kind(gw)).put("result", String.valueOf(how))
                            .put("local_network_grant", c.granted(ACCESS_LOCAL_NETWORK));
                })
                .timeout(8000)
                .expect(Expect.of("Guard LAN block for new apps", SRC_LAN,
                        "a new app without the local-network grant can't reach LAN devices; "
                                + "an app Guard allows the local network reaches it")
                        // IchthysOS: UNAVAILABLE (no private gateway: cellular or VPN) is not
                        // a kept promise, it is "could not try" (judge makes it n/a).
                        .outcomes(Outcome.BLOCKED_ICHTHYS, Outcome.BLOCKED_PERMISSION,
                                Outcome.EMPTY, Outcome.VISIBLE)
                        // IchthysOS: in a Guard verification run Guard says what it holds for
                        // this uid (expect_lan); otherwise the grant decides what is promised.
                        // A whole-uid firewall block fails every connect (EPERM) and says
                        // nothing about the local-network rule.
                        .when(c -> "blocked".equals(c.option("expect_net"))
                                ? "whole app is blocked by Guard; says nothing about the local "
                                        + "network"
                                : c.option(GuardRun.EXTRA_EXPECT_LAN) == null
                                && c.granted(ACCESS_LOCAL_NETWORK)
                                ? "ACCESS_LOCAL_NETWORK granted (user or pm grant)" : null)
                        .check((c, r) -> {
                            final String expect = c.option(GuardRun.EXTRA_EXPECT_LAN);
                            if (r.outcome == Outcome.UNAVAILABLE) {
                                return null;
                            }
                            final boolean reached = r.outcome == Outcome.VISIBLE;
                            if (expect == null) {
                                return reached ? "LAN reached without the local-network grant"
                                        : null;
                            }
                            if ("blocked".equals(expect) && reached) {
                                return "LAN reached although Guard blocks this app's local "
                                        + "network";
                            }
                            if ("allowed".equals(expect) && !reached) {
                                return "LAN not reached although Guard allows this app's "
                                        + "local network (" + r.outcome.key + ")";
                            }
                            return null;
                        })));
    }
}
