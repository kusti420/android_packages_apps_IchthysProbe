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

import org.ichthys.probe.Expect;
import org.ichthys.probe.Outcome;
import org.ichthys.probe.Probe;
import org.ichthys.probe.Redact;
import org.ichthys.probe.Result;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * /proc, /sys, /data and other paths: whether each is readable or listable, with size, line or
 * entry counts and a salted hash of the content. Contents themselves never leave the app.
 */
public final class FsProbes {
    static final String CAT = "File system";

    private FsProbes() {}

    /** Reads up to 256 KB: lines, bytes, hash. EACCES/EPERM become blocked. */
    static Result readFile(String path) {
        final File f = new File(path);
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                new FileInputStream(f), StandardCharsets.UTF_8))) {
            final StringBuilder all = new StringBuilder();
            int lines = 0;
            String line;
            while ((line = r.readLine()) != null && all.length() < 256 * 1024) {
                all.append(line).append('\n');
                lines++;
            }
            if (all.length() == 0) {
                return Result.empty().put("readable", true).put("bytes", 0);
            }
            return Result.visible().put("lines", lines).put("bytes", all.length())
                    .put("content", Redact.hash(all.toString()));
        } catch (FileNotFoundException e) {
            final String m = String.valueOf(e.getMessage());
            if (m.contains("ENOENT")) {
                return Result.unavailable("does not exist");
            }
            return Result.blockedPermission(m.contains("EACCES") ? "EACCES"
                    : m.contains("EPERM") ? "EPERM" : Redact.exception(e));
        } catch (Exception e) {
            return Result.blockedPermission(Redact.exception(e));
        }
    }

    /** Lists a directory: entry count, or blocked when list() is refused. */
    static Result listDir(String path) {
        final File f = new File(path);
        final String[] names = f.list();
        if (names == null) {
            return f.exists() || f.getParentFile() == null || f.getParentFile().list() == null
                    ? Result.blockedPermission("list() refused")
                    : Result.unavailable("does not exist");
        }
        return Result.count("entries", names.length);
    }

    private static Probe file(String path, String reveals) {
        return new Probe(CAT, "fs.read:" + path, reveals, Probe.NONE, c -> readFile(path));
    }

    private static Probe dir(String path, String reveals) {
        return new Probe(CAT, "fs.list:" + path, reveals, Probe.NONE, c -> listDir(path));
    }

    public static void add(List<Probe> out) {
        out.add(new Probe(CAT, "fs.proc_pids",
                "How many other processes are visible in /proc (hidepid).",
                Probe.NONE,
                c -> {
                    final String[] names = new File("/proc").list();
                    if (names == null) {
                        return Result.blockedPermission("/proc not listable");
                    }
                    int pids = 0;
                    for (String n : names) {
                        if (!n.isEmpty() && Character.isDigit(n.charAt(0))) {
                            pids++;
                        }
                    }
                    return pids > 3 ? Result.visible().put("pids", pids)
                            : Result.blockedPermission("only own pids").put("pids", pids);
                }));

        out.add(file("/proc/version", "Kernel version and build host."));
        out.add(file("/proc/cpuinfo", "CPU model and features."));
        out.add(file("/proc/meminfo", "Memory totals."));
        out.add(file("/proc/stat", "System-wide CPU counters (side channel)."));
        out.add(file("/proc/uptime", "Uptime."));
        out.add(file("/proc/loadavg", "Load average."));
        out.add(file("/proc/self/mountinfo", "Mounted file systems (reveals partitions)."));
        out.add(file("/proc/1/cmdline", "init's command line (other process)."));
        out.add(file("/proc/net/tcp", "Open TCP sockets of all apps."));
        out.add(file("/proc/net/arp", "LAN neighbours' MAC addresses."));
        out.add(file("/proc/net/route", "Routing table."));
        out.add(file("/proc/net/dev", "Per-interface traffic counters."));
        out.add(file("/proc/net/unix", "Unix sockets of all apps."));
        out.add(file("/proc/bus/input/devices", "Input devices."));
        out.add(file("/proc/sys/kernel/random/boot_id",
                "Per-boot unique id (cross-app tracking)."));
        out.add(file("/sys/class/net/wlan0/address", "Wi-Fi MAC address."));
        out.add(file("/sys/devices/soc0/serial_number", "SoC serial number (hardware id)."));
        out.add(file("/sys/block/mmcblk0/device/cid", "Storage chip id (hardware id)."));
        out.add(file("/sys/class/power_supply/battery/capacity", "Battery percentage."));
        out.add(file("/sys/class/thermal/thermal_zone0/temp", "Thermal sensor."));
        out.add(file("/sys/fs/selinux/enforce", "SELinux mode."));
        out.add(file("/system/build.prop", "System build properties."));
        out.add(file("/vendor/build.prop", "Vendor build properties."));
        out.add(dir("/sys/class/net", "Network interface names."));
        out.add(dir("/dev/input", "Input device nodes."));
        out.add(dir("/data/local/tmp", "adb scratch directory."));
        out.add(dir("/data/data", "Other apps' private data directories."));
        out.add(dir("/data/app", "Installed APK directories."));
        out.add(dir("/data/data/com.android.settings", "Settings' private data."));
        out.add(dir("/data/misc", "System misc data."));
        out.add(dir("/storage", "Storage volumes (SD/USB names)."));
        out.add(dir("/apex", "Mainline modules."));

        out.add(new Probe(CAT, "fs.read:/data/system/packages.list",
                "Every installed package with its uid and data path.",
                Probe.NONE, c -> readFile("/data/system/packages.list")));

        out.add(new Probe(CAT, "fs.list:/data/system/ichthys",
                "ichthys.nix generations (the full device configuration history).",
                Probe.NONE, c -> listDir("/data/system/ichthys"))
                .expect(Expect.of("ichthys.nix config privacy",
                        "frameworks/base/services/core/java/com/android/server/ichthys/"
                                + "IchthysConfigService.java (generations in /data/system/ichthys,"
                                + " system-only)",
                        "apps can't read the configuration history")
                        .outcomes(Outcome.BLOCKED_PERMISSION, Outcome.UNAVAILABLE)));

        out.add(new Probe(CAT, "fs.hosts_blocklist",
                "/system/etc/hosts: size of the IchthysOS tracker blocklist (entry count).",
                Probe.NONE,
                c -> {
                    int entries = 0;
                    try (BufferedReader r = new BufferedReader(new InputStreamReader(
                            new FileInputStream("/system/etc/hosts"), StandardCharsets.UTF_8))) {
                        String line;
                        while ((line = r.readLine()) != null) {
                            if (line.startsWith("0.0.0.0 ")) {
                                entries++;
                            }
                        }
                    }
                    return Result.count("blocked_names", entries);
                })
                .expect(Expect.of("System-wide tracker blocklist (hosts file)",
                        "device/samsung/a52sxq/configs/hosts/hosts (HaGeZi Multi LIGHT, installed"
                                + " as /system/etc/hosts by ichthys_hosts)",
                        "the hosts blocklist is installed")
                        .check((c, r) -> {
                            final String n = r.detail.get("blocked_names");
                            return n != null && Integer.parseInt(n) > 10000 ? null
                                    : "hosts blocklist missing or small (" + n + ")";
                        })));
    }
}
