# IchthysProbe

A test app for IchthysOS. It measures what an **ordinary third-party app** can see on the
phone, permission by permission, and checks that each IchthysOS privacy feature does what it
promises. It is not shipped: it is in no `PRODUCT_PACKAGES` list, is signed with `testkey`
(not platform), is not privileged and has no allowlisted permissions. To the system it is
just another user-installed app.

Two modules live here:

| Module | Package | What it is |
|---|---|---|
| `IchthysProbe` | `org.ichthys.probe` | The probe app: one screen, headless autorun, JSON reports |
| `IchthysProbeHelper` | `org.ichthys.probe.helper` | "Another app" for the clipboard checks. It has no UI and no launcher icon, so Guard doesn't quarantine it. |

## Privacy rule

Reports never contain personal data. A probe records only presence, counts, lengths, types,
coarse ranges and **salted hashes**. For example:

- `contacts.rows: blocked-by-IchthysOS rows=0 truth_rows=213`
- `wifi.connection: ssid=visible, 9 chars, h:1a2b3c4d5e`
- `location.current_fix: fix, accuracy 12 m`
- `phone.imei: blocked-by-permission SecurityException`

The salt is random per install and stays in the app's private storage. So a hash can tell
you "this value changed between runs", but nobody can recover the value from it. Build and
boot-state values describe the device, not the owner, so they are recorded as they are.
Reports stay on the phone and the PC.

**Raw coarse region values (the `spoof.*` probes).** The "Spoofed values" probes record the
2-letter country ISO, the PLMN (MCC/MNC), the carrier/operator name and carrier id, the time
zone id and the locale tag **as they are**, not hashed. These describe a country or a carrier
with millions of subscribers, not the owner, and Guard's Verify has to compare them with the
profile it wrote (`ichthys_location_profile`): a hash of "us" against a hash of "US" would be
useless, and the app can't read the profile itself (SettingsProvider hides every
`ichthys_location_*` key from apps). Everything else in those probes keeps the rule above: IP
addresses, SSIDs, DNS servers and interface names appear only as presence, counts or lengths.
The public-IP check (`https://am.i.mullvad.net/json`) records only the country name and the
`mullvad_exit_ip` flag, never the address or the city. The same probes also read a few
`gsm.*` / `persist.sys.timezone` properties through the `getprop` binary (a child process, so
no in-process rewrite applies): those are the real values and are recorded raw for the same
reason, so a report of a spoofed app does name the real country.

The clipboard checks never need your clipboard. The "other app's clip" is a test token copied
by the helper. If a probe meets a clip that is neither the helper's nor its own, it records
only its length and hash.

## Build and install

```
m IchthysProbe IchthysProbeHelper
tools/sign_probe.sh out/target/product/a52sxq/system/app/IchthysProbe/IchthysProbe.apk /tmp/IchthysProbe-signed.apk
adb install /tmp/IchthysProbe-signed.apk
adb install out/target/product/a52sxq/system/app/IchthysProbeHelper/IchthysProbeHelper.apk
```

Guard trusts the tester only when it is signed with the dedicated IchthysOS probe key
(`~/.android-certs/ichthys_probe`; the public cert is `certs/ichthys_probe.x509.pem`, its
SHA-256 is pinned in Settings' `VerifyRunner.PROBE_CERT_SHA256`). The testkey build of
`m IchthysProbe` installs and runs on its own, but Guard won't verify with it, give it presets
or Full access. An already installed testkey build must be uninstalled first (other signer).
The "Check everything" button only asks: Guard's Verify page opens and the run starts when you
confirm there.

A freshly installed app is **quarantined by Ichthys Guard** (first-launch quarantine). It is
suspended until you review it. To release it, open IchthysProbe, tap **Review**, then tap
**Open as-is**. `pm unsuspend` cannot release it, because Guard's suspension belongs to
Settings. `tools/run_matrix.sh` detects this state, checks it, and either waits for you or
taps through the sheet (`--release-quarantine`).

## Running it

### On the phone

The screen answers "what is wrong and what do I do about it". **Check everything** asks Guard
(Settings) to run its verification: Guard puts this app into each stand-in state (Untrusted,
Messenger, Maps, and Full access when you gave the tester that preset), starts it headless for
each, and comes back here when the last state is done. The request is a broadcast to Settings'
`VerifyRequestReceiver` with this app's identity shared; Settings accepts it from
`org.ichthys.probe` only. **Run checks** runs this state only.

**Shield lists are hidden from apps since 2026-10-28** (SettingsProvider hides every `*_pkgs`,
`*_shield`, `ichthys_location_*` and lockdown key), so this app can't see its own shield state.
In a Guard run `expect_shields` is the authority (`Shields.useGuardView`); in a manual run shield
promises are *not judged* (they show under "Not tested · Only in a Guard verification") and no
test row is ever written on a guess. Headless and Guard launches are honoured only from the
system, shell or root uid (`GuardRun.trustedLaunch`); a busy probe answers a Guard launch with
an `error` extra at once instead of letting Guard wait.

Below the verdict and the cards:


- **Verdict line**: *Protected*, *Nothing verified yet* (no check could judge anything), or
  *N problems found*, coloured by the worst severity; then the run's time, build id (and the
  Guard stand-in), and "passed · not tested · checks". Leaks no IchthysOS feature covers are
  counted apart ("2 gaps IchthysOS doesn't cover yet") and don't make the line red.
- **Diff**: "New since last run: 1 problem · Fixed: 2" against the previous run of the same
  kind (manual/headless with each other, Guard runs per stand-in); tap for the titles. New cards
  carry a *New* chip. A problem only counts as fixed when this run could have found it again.
- **Problems**: one card per problem, worst first. A card is a broken promise (a FAIL) or a
  shield switched off (every app with the permission gets the real data). It shows a
  plain-language title, why it matters, the affected rule/shield and its settings keys, a
  **Fix** button that opens the place it is set (Guard is not exported, so a user app lands on
  App info › Guard or Settings › Guard and a toast names the rest of the path), **Share** (the
  redacted raw output as text) and **Details** (probe ids, outcome, why, promise, source
  file:line).
- **Not covered yet**: the same cards for gaps (stock leaks: Widevine id, boot id, readable
  shield lists, hardware serials, `/proc/net`). Fixing these needs a new shield.
- **Not tested**: checks that couldn't judge anything, grouped by reason with one action each:
  *Needs a permission* (Grant), *Needs usage access*, *Needs your tap* (the clipboard tap test),
  *IchthysProbe is allowed the real data* / *Shield not set for IchthysProbe* (Guard),
  *Only in a Guard verification*, *Needs IchthysProbeHelper*, *Checked by hand*. Tap a group for
  its probe ids and reasons.
- **Passed**: one line per category ("Contacts · 6 passed"); categories with nothing judged fold
  into *Observed only*. Tap for the checks, tap a check for its raw output.
- **Every protection, every state**: the matrix of the last Guard verification, one row per
  protection (contacts, calendar, call log, messages, phone number, location, scans, clipboard,
  sensors, usage, spoofed values, firewall, local network, radios), one column per stand-in:
  ✓ as promised, ✗ leak, ○ not judged in that state. Tap a row for the failed check ids.
- **Spoofed values**: real (getprop, a child process) / expected (the profile Guard wrote,
  kept in the report's `expect` block) / seen (what this app got) for country, carrier, carrier
  name, time zone, language, the public IP and country broadcasts.
- **History**: one dot per run (newest right, the shown run outlined; tap to open it), the
  system screens (App info, Usage access, Draw over apps, Notifications, Location, Permissions).

Severity is one table, `Triage.TABLE` (next to `Registry`): **High** when real data leaves
(contacts, calendar, call log, SMS, phone number, real location, the clipboard, identifiers,
the firewall), **Medium** for metadata (scans, Wi-Fi/cell, sensors, usage, installed apps, LAN,
Backstage, Guard state), **Low** for the environment (hosts blocklist, microG, prop spoofing,
keybox). A FAIL with no row counts as Medium.

At launch the screen shows the last run, read back from its report file. The buttons at the
top have content descriptions for adb/uiautomator: `probe_run_all`, `probe_tap_clipboard`
(the clipboard probe that needs a real tap), `probe_request_permissions`.

### From Guard (verification runs)

Settings › Guard › **Verify my protection** (and **Verify this app** on an app's page) runs this
app as a stand-in: Guard puts `org.ichthys.probe` on the lists and policy of a preset
(Untrusted, Messenger, Maps, or the app's own setup), starts it headless with what it should
find and the ground truth it can't see, and this app broadcasts its verdicts back
(`org.ichthys.probe.action.RESULT`, one-time token). Guard then shows pass/fail per rule
category next to the events its own stream saw, and puts this app's previous setup back. The
protocol is in `src/org/ichthys/probe/GuardRun.java`; the extras are:

| Extra | Meaning |
|---|---|
| `--ez guard_run true` | Run only Guard's categories (network, location, personal data, clipboard, sensors, radios) and reply when done |
| `--es reply_token T --es reply_component PKG/CLASS` | Where the reply goes; Guard accepts it only with its token |
| `--es stand_in NAME` | Shown in the header |
| `--es expect_location real\|fake\|none`, `--es expect_fake_latlon "lat,lon"` | The stand-in's Location control; `location.fake_place` checks the fix is near (fake) or far from (real) the fake place |
| `--es expect_scans real\|empty`, `--es expect_lan allowed\|blocked` | Scans and local network as Guard set them |
| `--es expect_shields id,id,...` | The shields Guard says protect this app; `guard.state_matches` compares with the settings lists |

A Guard run also includes the `spoof.*` probes. They carry no expectation of their own (the app
can't read the profile); the reply broadcast carries their full `detail` object (raw coarse
values, see the privacy rule), so Verify in Settings judges them against the profile without
reading the report file.

Every run (manual or from Guard) is recorded in `files/history.json` (date, label, build id,
every verdict, and now the stand-in, the report path and the problem cards); the reply carries
the probes whose verdict changed since the previous run, as before. The screen warns in red
when this app sits in `/system`.

### Headless

```
adb shell am start -n org.ichthys.probe/.MainActivity --ez autorun true --es label NAME \
    [--es expect_net allowed|blocked] [--es qap default|granted] [--ei truth_contacts N ...]
```

This runs every probe that needs no tap and logs one line per probe under the tag
`IchthysProbe`, for example:

```
I IchthysProbe: [NAME] contacts.rows outcome=blocked-by-IchthysOS verdict=pass granted=granted | ...
```

Then it writes the report and logs
`DONE label=NAME probes=.. pass=.. fail=.. info=.. skip=.. report=<path>`.

The report goes to `/sdcard/Android/data/org.ichthys.probe/files/reports/NAME.json`. Fetch it
with `adb pull`.

The last clipboard probe (`clip.background_self`) moves the app's task to the back. Bring the
app forward again with `am start -n org.ichthys.probe/.MainActivity` (no extras), then tap
the `probe_tap_clipboard` button:

```
adb shell uiautomator dump /sdcard/ui.xml && adb exec-out cat /sdcard/ui.xml   # find its bounds
adb shell input tap X Y
```

The tap result is merged into the same report. Logcat shows `TAP_DONE label=NAME ...`.

Optional extras:

| Extra | Meaning |
|---|---|
| `--es expect_net allowed\|blocked` | What Guard's network policy for this app is. The app can't read it, so without this the network probes stay informational. |
| `--es qap default\|granted` | Whether "see all apps" (`QUERY_ALL_PACKAGES`) was allowed. `checkSelfPermission` always says granted, so the app can't tell by itself. |
| `--ei truth_<table> N` | Row counts the host took as the shell uid, which every shield exempts. With these, the app can tell "shielded" (0 rows while the truth is 213) from "really empty". Keys: `contacts raw_contacts phones groups profile calendars events instances_30d calllog sms mms conversations packages`. |

### The matrix

`tools/run_matrix.sh` installs both APKs, runs the matrix below, pulls the reports, and runs
`compare.py`.

```
tools/run_matrix.sh -s SERIAL [--release-quarantine] [--guard-net root|connectivity|manual|none] [--with-pause]
```

The runs:

| Run | State |
|---|---|
| (install) | Fresh install. Host checks: quarantined on install, launch blocked while quarantined, `pm unsuspend` can't release it, the launcher-less helper is *not* quarantined, released after review. |
| `a` | Nothing granted: every runtime permission revoked, app-ops at their defaults, `QUERY_ALL_PACKAGES` withheld. |
| `b` | Every runtime permission granted with `pm grant` (including background location and Health). Usage access and overlay app-ops allowed. "See all apps" allowed. |
| `c` | `b` plus the protect lists: scans, No location, NFC. Also Guard's network block, chosen with `--guard-net` (see below). `--with-pause` (root mode only) also runs `c-paused`, a Guard pause of 2 min that should let traffic through, then `c-resumed`, after the pause, which should block again. |
| `d` | `b` plus the allow lists: contacts, calendar, call log, SMS, phone number, answer calls, clipboard, sensors, usage, BLE advertising. Every shield is lifted, so the app should see real data. The read allow lists also lift the write shields (an app allowed the real data may change it), so the write probes skip their test rows in run `d` and never write into your real address book. |

The `--guard-net` modes for run `c`:

- `root`: `adb root` plus `service call ichthys_guard 1 i32 <uid> i32 2`. This is Guard's own
  `setNetworkPolicy(uid, DENY)`. The binder needs the signature permission
  `MANAGE_ICHTHYS_GUARD`, and only root passes that check.
- `connectivity`: `cmd connectivity set-package-networking-enabled false`. This writes the same
  firewall chain as Guard (OEM_DENY_3), but it is not Guard.
- `manual` (the default): the script asks you to set **Settings › Guard › IchthysProbe ›
  Network: Block** and waits for Enter.
- `none`: no network block.

Guard has no shell command and no ichthys.nix option for per-app network policies, profiles,
Lockdown or pause. The shields, however, are plain settings keys (`settings put secure
ichthys_location_nofix_pkgs ...`). Shell can write them, and the script restores every key it
touched on exit. Before the first run it also takes IchthysProbe off every list a run uses, in
case an earlier run was killed before it could restore them; otherwise runs `a` and `b` would
start with shields lifted.

The script never taps or swipes while the keyguard shows. It waits for you to unlock.

### Reading the comparison

```
python3 tools/compare.py probe-reports/<stamp>             # table + failed expectations
python3 tools/compare.py probe-reports/<stamp> --all       # every probe, not only interesting rows
python3 tools/compare.py probe-reports/<stamp> --details contacts.rows
```

The output has three parts:

1. **Table**: one row per probe (grouped by category) and one column per run. Each cell is
   `outcome` plus `ok` (promise kept) or `FAIL` (promise broken). Outcomes:
   - `visible`: real data
   - `empty`: nothing
   - `blk-perm`: stock permission refusal
   - `blk-ichthys`: an IchthysOS feature refused or emptied it
   - `n/a`: not available on this device or in this state
   - `skip`: not run
   - `error`
2. **IchthysOS expectations that FAILED**: for each failure, the promise, what was observed,
   the redacted detail, and where in the source the promise comes from.
3. **Host-side checks** from run_matrix.sh (quarantine, firewall chain).

The exit status is 1 when anything failed.

## What each category covers

| Category | Probes |
|---|---|
| Device & system | `Build.*` fields; whether this app sees spoofed Build values; getprop (serial, verified boot state, debuggable, USB); languages and time zone (hashed or offset only); uptime and boot count; battery (5 % steps, cycles); RAM and cores; readable Global settings (dev options, adb, airplane) |
| Apps & usage | Installed package count (with and without "see all apps"); launchable apps; GmsCore's signing certificate as apps see it; other apps' processes and tasks; usage history and events; accounts; accessibility services; keyboards; overlays; this app's own suspended state and standby bucket |
| File system | `/proc` (pids, version, cpuinfo, stat, net/tcp, arp, route, unix, boot_id), `/sys` (Wi-Fi MAC, SoC serial, eMMC CID, battery, thermal, SELinux), `/data/local/tmp`, `/data/data`, `/data/app`, other apps' dirs, `/data/system/packages.list`, `/data/system/ichthys` (ichthys.nix generations), the hosts blocklist |
| Display & Backstage | Listed displays; display ids resolvable although unlisted; starting an activity on unlisted display ids; the Backstage app list |
| Network | Active network and VPN presence; link properties (address kinds, DNS, Private DNS); interfaces and MACs; HTTPS to the internet; DNS of ordinary hosts, of hosts-file trackers and of Guard's known trackers; reaching the LAN gateway; ACCESS_LOCAL_NETWORK |
| Phone & identifiers | SIM, operator and country; call state; subscriptions; the phone number (two APIs); IMEI, IMSI, ICCID, serial; cell towers; ending calls; ANDROID_ID; Widevine device id; device name |
| Contacts, Calendar, Call log, SMS & MMS | Row counts per table (contacts, raw, phones, groups, profile, calendars, events, instances, calls, SMS, MMS, threads, SIM messages). Write tests insert a test row, check the returned id, and delete it again if it was really saved. |
| Location | Grants; providers; last known fix; fresh fix; GPS updates; GNSS satellites; NMEA. Never coordinates: only accuracy, provider and age. |
| Spoofed values | What tells an app the country beside the GPS fix (Guard gear › Spoofed values): TelephonyManager country/PLMN/operator/carrier id; ServiceState registered PLMNs and cell MCC/MNC; Configuration mcc/mnc, locales and the gsm.*/debug.tracing properties (SystemProperties vs getprop); the time zone as java.util, ICU, java.time, `TZ` and persist.sys.timezone see it; emergency numbers (911/999/112/000/110/119); CountryDetector (hidden API); visible networks, DNS counts, DHCP info and the public IP's country (Mullvad); whether country/time-zone broadcasts arrive. Raw coarse values, see the privacy rule. |
| Sensors | The sensor list (generic or real identity, uncalibrated sensors); accelerometer, gyroscope and magnetometer delivered rate and value grid; light, proximity, pressure; step counter; heart rate |
| Bluetooth, Wi-Fi, UWB & NFC | Adapter, name and MAC; paired devices; BLE scan; classic discovery; BLE advertising; Wi-Fi state, connection (SSID/BSSID hidden or visible), scan results, control; NEARBY_WIFI_DEVICES; UWB; NFC |
| Camera & microphone | Camera list; opening the camera (no frames); 0.6 s of microphone level (nothing stored) |
| Media & storage, Notifications & media sessions, Health | Photo, video, audio and download counts (full vs "selected photos" grants); GPS in photo EXIF (count); `/sdcard` and other apps' Android/data; storage size; posting a notification; listener access; now playing (media sessions); audio state; Health Connect steps and heart-rate grant |
| IchthysOS settings & keys | Whether shield lists and other IchthysOS keys are readable; the keybox read gate; the key-attestation chain this app gets |
| Clipboard | Auto-clear; the clip-change listener; a no-tap read; the stripped description; presence; reading its own clip; a background read by another app; its own background read; paste after a real tap (once per tap) |

## IchthysOS expectations encoded

Each expectation is written as the feature **promises**, not as the code behaves today. A
known gap therefore shows red until it is fixed.

Expectations only apply in the state where the promise is made: the permission granted, the
shield on, and this app not on the shield's allow list. Elsewhere the probe is informational.

| Feature | Probes | Expected | Source of the promise |
|---|---|---|---|
| Clipboard lockdown | `clip.read_no_tap` | blocked: getPrimaryClip is null without a fresh tap | ClipboardService.java ichthysNeedsPasteProof / ichthysMayReadLocked (tracker#31) |
| Clipboard lockdown | `clip.description` | blocked: MIME types only, no label or extras | ClipboardService.java getPrimaryClipDescription |
| Clipboard lockdown | `clip.listener` | the callback can't read the new clip | same |
| Clipboard lockdown | `clip.tap_read` | visible right after a real tap; null for a second read 1 s later (one tap backs one paste) | ClipboardService.notePasteInput; services-fixes.md C2 |
| Clipboard lockdown | `clip.own_clip` | an app always reads its own clip | ichthysMayReadLocked |
| Clipboard lockdown | `clip.other_app_bg_read`, `clip.background_self` | blocked in the background | stock rule plus the lockdown; isUidFocusedOnTopFocusedDisplay (C5) |
| Clipboard auto-clear | `clip.autoclear` | the marker clip from the previous run is gone after `ichthys_clipboard_clear_minutes` (default 5), sleep included | services-fixes.md C3 |
| Contacts shield | `contacts.rows`, `raw_rows`, `phones`, `groups`, `profile` | 0 rows while protected; real rows once allowed (run d) | ContactsProvider IchthysShield and ContactsProvider2 (`AND 0`) |
| Contacts write shield | `contacts.write` | insert returns the fake id `/0`, nothing saved. Not tried when the contacts allow list lifts it (run d). | ContactsProvider2 rejectInsert; IchthysShield (read allow list covers writes) |
| Calendar shield, Calendar write shield | `calendar.*` | as for contacts | CalendarProvider2, calendar IchthysShield |
| Call log shield, Call log write shield | `calllog.rows`, `calllog.write` | as for contacts | CallLogProvider |
| SMS read shield | `sms.rows`, `mms_rows`, `conversations`, `sim_messages` | empty | TelephonyProvider IchthysSmsShield |
| Phone number shield | `phone.line1_number`, `phone.subscription_number` | null / "" | telephony IchthysShield, PhoneSubInfoController, SubscriptionManagerService |
| Answer/end calls shield | `phone.end_call` | SecurityException while holding ANSWER_PHONE_CALLS. Skipped while a call rings or is in progress, so a real call is never ended. | TelecomServiceImpl enforceAnswerCallPermission |
| Location shield (No location) | `location.last_known`, `current_fix`, `updates`, `nmea`, `phone.cell_info`, `wifi.connection` | no fix, no NMEA. Also no cells and no SSID/BSSID: "never get a location" (known gap M2). | IchthysLocationNoFix, LocationProviderManager; IchthysShields.LOCATION |
| Scan shield (+ No location) | `bt.le_scan`, `bt.discovery`, `wifi.scan_results` | scans find nothing | Wi-Fi IchthysRadioPolicy, Bluetooth RadioPolicy |
| BLE advertising shield | `bt.advertise` | ADVERTISE_FAILED_FEATURE_UNSUPPORTED on hardware that can advertise | Bluetooth RadioPolicy, AdvertiseManager |
| Sensor shield | `sensors.list` | vendor "Android", name "Accelerometer", version 1, minDelay at least 20 ms, no uncalibrated motion sensors | native SensorService hardenSensorForFingerprinting |
| Sensor shield | `sensors.accelerometer`, `gyroscope`, `magnetometer` | at most 50 Hz; values on a 0.02 / 0.002 / 0.25 grid | SensorService.h ICHTHYS_FP_SAMPLING_PERIOD_NS; quantisation |
| Sensor shield | `sensors.uncalibrated_register` | hidden or refused | same |
| Usage history shield | `apps.usage_stats`, `apps.usage_events` | empty with usage access | UsageStatsService |
| QUERY_ALL_PACKAGES user control | `apps.installed` (needs `truth_packages` + `qap`) | filtered until allowed, full after | AppIdPermissionPolicy (INSTALL_REVOKED), AppsFilterQueryAllPackages |
| Signature spoofing (microG) | `apps.gms_signature` | GmsCore reports Google's certificate | FakeSignatureUtils, PackageInfoUtils |
| Play Integrity prop spoofing scope | `build.spoof_scope` | this app sees the real Build values | PropImitationHooks (gms, vending, Photos only) |
| Keybox read gate | `settings.keybox` | the keybox reads as absent | SettingsProvider isKeyboxReadableByCaller (tracker#13) |
| Backstage hidden display | `display.list`, `display.id_scan`, `display.launch_scan` | not listed, not resolvable, launches refused | IchthysBackstageService (private virtual display, no PUBLIC flag) |
| Backstage privacy | `display.backstage_list` | blocked. Judged only with an app in Backstage (the list is cleared at every boot, and an empty list proves nothing). **Fails today** then: `ichthys_backstage_pkgs` is readable by every app (services.md B11-B13, not fixed) | audit |
| Guard per-app network block | `net.https`, `net.dns_control` (+ host check `guard.net_block_chain`) | works when allowed; blocked when Guard blocks | IchthysGuardService applyFirewall (OEM_DENY_3) |
| Guard pause | runs `c-paused` and `c-resumed` | allowed during the pause, blocked after it | IchthysGuardService pauseInternal (services-fixes.md G2) |
| Guard tracker blocking | `net.dns_trackers_guard` | nothing: information only. Guard shows trackers but doesn't block them; its tracker and host rules are display-only (`HostRules.ENFORCED = false`; services.md G5, apps.md G1). | Guard model/Rules.kt |
| System-wide tracker blocklist | `net.dns_trackers_hosts`, `fs.hosts_blocklist` | the hosts file is installed; listed trackers resolve to 0.0.0.0 (a failed lookup doesn't count; n/a while Guard blocks the app, because DNS then refuses every query) | device/samsung/a52sxq/configs/hosts |
| Guard LAN block for new apps | `net.lan` | no LAN without ACCESS_LOCAL_NETWORK | IchthysGuardService LAN default deny |
| First-launch quarantine | host checks `guard.*` | quarantined on install; launch intercepted; shell can't release it; launcher-less apps exempt; released after review | IchthysGuardService 1219-1317; FirstLaunchActivity |
| ichthys.nix config privacy | `fs.list:/data/system/ichthys` | not readable | IchthysConfigService |
| Stock identifier lockdown (not IchthysOS) | `phone.imei`, `subscriber_id`, `sim_serial`, `build_serial` | SecurityException | TelephonyPermissions |

The JSON report carries the full source reference (file and line) of every expectation.

### Spoofed values: fields Verify matches on

The `spoof.*` probes are informational in the app; Settings › Guard › Verify compares their
`detail` fields with the profile. The field names are the contract:

| Probe | Fields |
|---|---|
| `spoof.telephony_country` | `sim_state`, `sim_country`, `network_country`, `network_country_slotN`, `sim_operator`, `network_operator`, `sim_operator_name`, `network_operator_name`, `roaming`, `sim_carrier_id`, `sim_carrier_id_name` |
| `spoof.service_state` | `registered`, `delivered`, `source` (callback / getServiceState / none), `state`, `operator_numeric`, `operator_alpha_long`, `operator_alpha_short`, `roaming`, `nri_count`, `nriN` (one line per NetworkRegistrationInfo), `nri_plmns` (unique registered PLMNs, comma list or `none`), `cell_mccmnc` (unique cell MCC+MNC, or `none`) |
| `spoof.configuration` | `config_mcc`, `config_mnc`, `config_mnc_zero`, `config_locales`, `default_locales`, `locale_default`, `prop_<key>` for gsm.sim.operator.iso-country, gsm.operator.iso-country, gsm.sim.operator.numeric, gsm.operator.numeric, gsm.sim.operator.alpha, gsm.operator.alpha, gsm.operator.isroaming, debug.tracing.mcc, debug.tracing.mnc, persist.sys.locale, ro.boot.sales_code (SystemProperties.get; `blocked (...)` when refused); `getprop_<key>` for gsm.sim.operator.iso-country, gsm.operator.iso-country, gsm.sim.operator.numeric, gsm.operator.numeric, ro.boot.sales_code |
| `spoof.timezone` | `java_tz`, `icu_tz`, `zone_id`, `env_TZ` (`unset` when absent), `prop_persist.sys.timezone`, `getprop_persist.sys.timezone`, `raw_offset_min`, `dst`, `zone_name`, `consistent` |
| `spoof.emergency` | `emergency_911`, `emergency_999`, `emergency_112`, `emergency_000`, `emergency_110`, `emergency_119` (booleans), `emergency_numbers` (comma list or `none`) |
| `spoof.country_detector` | `country_iso` (iso, `null`, `blocked` or `unavailable`), `source` (0 network, 1 location, 2 sim, 3 locale), `source_name`; outcome `blocked-by-permission` when the hidden API refuses |
| `spoof.network_visibility` | `networks`, `vpn_networks`, `non_vpn_dns_servers`, `vpn_dns_servers`, `netN` (transports, dns/addrs/routes counts, iface length), `active_network`, `active_is_vpn`, `active_dns_servers`, `dhcp` (present/null), `dhcp_dns1_set`, `dhcp_dns2_set`, `dhcp_gateway_set`, `dhcp_ip_set`, `ip_check` (`ok` / `offline` / `error`), `ip_check_status`, `ip_country`, `mullvad_exit_ip`, `ip_check_error`, `uid_blocked`; outcome `empty` or `blocked-by-IchthysOS` when offline |
| `spoof.broadcasts` | `registered`, `waited_ms`, `country_broadcasts`, `timezone_broadcasts`, `country_extra`, `timezone_extra` |

Empty strings are recorded as `empty`. Country ISOs are lower case where the API returns them
lower case (TelephonyManager) and as-is elsewhere.

### Checked by hand (never automated)

These promises have no safe automatic observable. Their probes report `skip`:

| Probe | Shield | Manual check |
|---|---|---|
| `sms.send` | SMS send | A text sent by an app needs **Allow** in a system dialog. Deny gives `RESULT_ERROR_GENERIC_FAILURE`. |
| `phone.place_call` | Call | A call placed by an app opens IchthysCallConfirmActivity first. Cancel drops it. |
| `sms.mms_push` | MMS push | Needs a real incoming MMS. |
| `nfc.reader` | NFC | Needs a tag. A listed app's reader mode never fires. |
| `uwb.ranging` | UWB | Needs a peer. A shielded session fails to open with `REASON_SYSTEM_POLICY`. |

## Side effects

- **Clipboard**: the probes overwrite it. The last thing left on it is IchthysProbe's marker
  clip, which the next run's `clip.autoclear` checks.
- **Write tests** (`contacts.write`, `calendar.write`, `calllog.write`): they insert a test row
  only while the write shield should protect the app, so normally nothing is saved. If the
  shield is switched off or lifted (allow lists, run d) they skip. If a shield that should
  protect lets the row through anyway, the row is deleted again at once (`cleanup_deleted` in
  the detail).
- **Calls**: `phone.end_call` calls `endCall()` only while no call rings or is in progress.
- **Camera and microphone**: opened for a moment, so the privacy indicators flash.
- **BLE**: advertises for up to 3 s.
- **Notifications**: one silent notification, removed again.
- **Display scan**: an invisible activity may start and finish once per unlisted display id.

## Known limits

- Run `a` revokes every runtime permission first, so it is "fresh" even with
  `--skip-install`. It does not undo a Guard review or Guard's per-app choices.
- The Guard network policy, "see all apps" and the shell's ground-truth counts are known only
  to the host. Without the matching extras those checks are informational.
- `location.gnss_status` (satellites in view) is not covered by the No-location shield, so it
  is information only.
- A run on a locked or sleeping phone gives different answers: clipboard reads are refused
  while the phone is locked, and scans throttle. The report header records `keyguard_locked`
  and `interactive`.
