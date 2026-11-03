#!/usr/bin/env bash
# Copyright (C) 2026 IchthysOS
# SPDX-License-Identifier: Apache-2.0
#
# run_matrix.sh: install IchthysProbe (+ helper) on a phone, run it in several permission and
# privacy states, pull the JSON reports and print the comparison (tools/compare.py).
#
# Runs:
#   a  fresh install, no runtime permission granted (after Guard's first-launch quarantine)
#   b  every runtime permission granted with pm grant, usage access + overlay app-ops,
#      QUERY_ALL_PACKAGES allowed ("see all apps")
#   c  privacy profile: the app on the scans, No-location and NFC shield lists, and its
#      network blocked by Guard (see --guard-net); optional Guard pause check (--with-pause)
#   d  allowed profile: the app on the read/clipboard/sensor/usage allow lists (lifted shields)
#
# Every settings key the script changes is restored on exit (also on Ctrl-C).
# Nothing personal is read: ground-truth row counts are counted ON the phone (grep -c) as the
# exempt shell uid; only the numbers come back.
#
# The script taps the screen only when it must (the clipboard tap probe, and the Guard
# first-launch sheet with --release-quarantine), and refuses to tap while the keyguard shows.

set -u

PKG=org.ichthys.probe
HELPER=org.ichthys.probe.helper
TAG=IchthysProbe
HERE="$(cd "$(dirname "$0")" && pwd)"

SERIAL="${ANDROID_SERIAL:-}"
PRODUCT_OUT="${ANDROID_PRODUCT_OUT:-$HERE/../../../../out/target/product/a52sxq}"
APK=""
HELPER_APK=""
OUT=""
RUNS="a,b,c,d"
SKIP_INSTALL=0
RELEASE_QUARANTINE=0
WAIT_RELEASE=300
DO_TAPS=1
GUARD_NET="manual"   # root | connectivity | manual | none
WITH_PAUSE=0

usage() {
    cat <<EOF
usage: $0 [options]
  -s SERIAL            adb serial (default \$ANDROID_SERIAL; required with several devices)
  --apk PATH           IchthysProbe.apk (default \$ANDROID_PRODUCT_OUT/system/app/IchthysProbe/)
  --helper-apk PATH    IchthysProbeHelper.apk (default next to it)
  --out DIR            where reports go (default ./probe-reports/<timestamp>)
  --runs a,b,c,d       which runs (default all)
  --skip-install       keep the installed app (no fresh-install/quarantine checks)
  --release-quarantine tap through Guard's first-launch sheet ("Review" -> "Open as-is")
  --wait-release SEC   otherwise wait this long for you to release it by hand (default 300)
  --no-taps            skip the clipboard tap probe
  --guard-net MODE     run c network block: root (adb root + service call ichthys_guard),
                       connectivity (cmd connectivity; simulates Guard's chain, not Guard),
                       manual (you set "No network" in Guard and press Enter), none
  --with-pause         with --guard-net root: also check Guard's pause and resume (~3 min)
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -s) SERIAL="$2"; shift 2 ;;
        --apk) APK="$2"; shift 2 ;;
        --helper-apk) HELPER_APK="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --runs) RUNS="$2"; shift 2 ;;
        --skip-install) SKIP_INSTALL=1; shift ;;
        --release-quarantine) RELEASE_QUARANTINE=1; shift ;;
        --wait-release) WAIT_RELEASE="$2"; shift 2 ;;
        --no-taps) DO_TAPS=0; shift ;;
        --guard-net) GUARD_NET="$2"; shift 2 ;;
        --with-pause) WITH_PAUSE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage; exit 2 ;;
    esac
done

[ -n "$APK" ] || APK="$PRODUCT_OUT/system/app/IchthysProbe/IchthysProbe.apk"
[ -n "$HELPER_APK" ] || HELPER_APK="$PRODUCT_OUT/system/app/IchthysProbeHelper/IchthysProbeHelper.apk"
STAMP="$(date +%Y%m%d-%H%M%S)"
[ -n "$OUT" ] || OUT="$PWD/probe-reports/$STAMP"
mkdir -p "$OUT"
HOST_CHECKS="$OUT/host-checks.jsonl"
: > "$HOST_CHECKS"
RESTORE="$OUT/.restore"
: > "$RESTORE"

ADB=(adb)
[ -n "$SERIAL" ] && ADB=(adb -s "$SERIAL")

log() { echo "[matrix] $*"; }
die() { echo "[matrix] ERROR: $*" >&2; exit 1; }
# IchthysOS: </dev/null on every adb shell that runs inside a loop. adb shell forwards stdin, so
# inside `while read ...; done < file` the first call swallowed the rest of the file: only the
# first saved key was ever restored, and later runs started with the probe still on the
# allow/protect lists (seen in probe-reports/20261027-093717: run a had calendar, call log,
# SMS, clipboard, sensors, ... lifted and the No-location/NFC lists set).
sh_() { "${ADB[@]}" shell "$@" </dev/null 2>/dev/null | tr -d '\r'; }

# One host-side check: id feature expected actual source detail. Verdict computed here.
host_check() {
    local id="$1" feature="$2" expected="$3" actual="$4" source="$5" detail="${6:-}"
    local verdict=fail
    [ "$expected" = "$actual" ] && verdict=pass
    [ "$expected" = "-" ] && verdict=info
    python3 - "$HOST_CHECKS" "$id" "$feature" "$expected" "$actual" "$verdict" "$source" \
        "$detail" <<'PY'
import json, sys
path, *f = sys.argv[1:]
keys = ["id", "feature", "expected", "actual", "verdict", "source", "detail"]
with open(path, "a") as o:
    o.write(json.dumps(dict(zip(keys, f))) + "\n")
PY
    log "host check $id: expected=$expected actual=$actual -> $verdict"
}

# ---------------------------------------------------------------- device state / safety

check_device() {
    local n
    n=$(adb devices | awk 'NR>1 && $2=="device"' | wc -l)
    if [ -z "$SERIAL" ] && [ "$n" -gt 1 ]; then
        die "several devices attached: pass -s SERIAL"
    fi
    "${ADB[@]}" get-state >/dev/null 2>&1 || die "no device (try: adb kill-server; adb start-server)"
}

keyguard_showing() {
    sh_ dumpsys window | grep -Eq \
        'mKeyguardShowing=true|isKeyguardShowing=true|mShowingLockscreen=true|mDreamingLockscreen=true'
}

# Wake the screen and make sure the phone is unlocked. Never taps or swipes the lock screen.
require_unlocked() {
    if ! sh_ dumpsys power | grep -q 'mWakefulness=Awake'; then
        "${ADB[@]}" shell input keyevent KEYCODE_WAKEUP
        sleep 1
    fi
    local i
    for i in $(seq 1 30); do
        keyguard_showing || return 0
        [ "$i" = 1 ] && log "the phone is locked: unlock it (waiting up to 60 s, no taps sent)"
        sleep 2
    done
    die "the phone stayed locked; unlock it and run again"
}

# ---------------------------------------------------------------- UI helpers (uiautomator)

# Prints "x y" of the centre of the first node whose ATTR equals VALUE, or nothing.
ui_find() {
    local attr="$1" value="$2"
    "${ADB[@]}" shell uiautomator dump /sdcard/ichthysprobe-ui.xml >/dev/null 2>&1
    "${ADB[@]}" exec-out cat /sdcard/ichthysprobe-ui.xml 2>/dev/null | python3 -c '
import re, sys, xml.etree.ElementTree as ET
attr, value = sys.argv[1], sys.argv[2]
try:
    root = ET.fromstring(sys.stdin.read())
except ET.ParseError:
    sys.exit(0)
for n in root.iter("node"):
    if n.get(attr, "").strip().lower() == value.lower():
        m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", n.get("bounds", ""))
        if m:
            x1, y1, x2, y2 = map(int, m.groups())
            print((x1 + x2) // 2, (y1 + y2) // 2)
            break
' "$attr" "$value"
    "${ADB[@]}" shell rm -f /sdcard/ichthysprobe-ui.xml >/dev/null 2>&1
}

ui_tap() {
    local attr="$1" value="$2" xy
    require_unlocked
    xy=$(ui_find "$attr" "$value")
    [ -n "$xy" ] || return 1
    # shellcheck disable=SC2086
    "${ADB[@]}" shell input tap $xy
}

# ---------------------------------------------------------------- package state

app_uid() { sh_ pm list packages -U "$PKG" | sed -n "s/^package:$PKG uid:\([0-9,]*\).*/\1/p" | cut -d, -f1; }

is_quarantined() {
    local p="$1"
    sh_ pm list packages -q | grep -qx "package:$p" && return 0
    sh_ dumpsys package "$p" | grep -q 'quarantined=true'
}

is_suspended() { sh_ dumpsys package "$1" | grep -Eq 'suspended=true'; }

top_activity() {
    sh_ dumpsys activity activities | grep -E 'topResumedActivity|ResumedActivity:' | head -1
}

# ---------------------------------------------------------------- settings with restore

remember() {   # table key: save the current value once
    local table="$1" key="$2" cur
    grep -q "^$table $key " "$RESTORE" && return 0
    cur=$(sh_ settings get "$table" "$key")
    echo "$table $key $cur" >> "$RESTORE"
}

list_add() {   # table key: add PKG to a comma-separated package list
    local table="$1" key="$2" cur new
    remember "$table" "$key"
    cur=$(sh_ settings get "$table" "$key")
    if [ -z "$cur" ] || [ "$cur" = null ]; then
        new="$PKG"
    elif echo ",$cur," | grep -q ",$PKG,"; then
        return 0
    else
        new="$cur,$PKG"
    fi
    "${ADB[@]}" shell settings put "$table" "$key" "$new" </dev/null
}

restore_settings() {
    [ -s "$RESTORE" ] || return 0
    log "restoring changed settings"
    while read -r table key cur; do
        # IchthysOS: </dev/null, or adb eats the remaining lines of $RESTORE (see sh_).
        if [ -z "$cur" ] || [ "$cur" = null ]; then
            "${ADB[@]}" shell settings delete "$table" "$key" </dev/null >/dev/null 2>&1
        else
            "${ADB[@]}" shell settings put "$table" "$key" "$cur" </dev/null >/dev/null 2>&1
        fi
    done < "$RESTORE"
    : > "$RESTORE"
}

# IchthysOS: every per-app list a run puts the probe on (c: protect lists, d: allow lists).
PROTECT_LIST_KEYS="ichthys_scan_empty_pkgs ichthys_location_nofix_pkgs ichthys_nfc_blocked_pkgs"
ALLOW_LIST_KEYS="ichthys_contacts_allowed_pkgs ichthys_calendar_allowed_pkgs \
ichthys_call_log_allowed_pkgs ichthys_sms_read_allowed_pkgs ichthys_phone_number_allowed_pkgs \
ichthys_answer_calls_allowed_pkgs ichthys_clipboard_allowed_pkgs ichthys_sensor_exempt_pkgs \
ichthys_usage_full_pkgs ichthys_ble_advertise_pkgs"

# IchthysOS: takes the probe off every list a run may have left it on (an earlier run killed
# before its restore, or one hit by the old restore bug), so runs a and b really start with
# every shield on. Only the probe's own entry is removed; nothing is remembered, because the
# leftover entry is not the user's setting.
scrub_leftover_lists() {
    local key cur new
    for key in $PROTECT_LIST_KEYS $ALLOW_LIST_KEYS; do
        cur=$(sh_ settings get secure "$key")
        echo ",$cur," | grep -qF ",$PKG," || continue
        new=$(echo "$cur" | tr ',' '\n' | grep -vxF "$PKG" | paste -sd, -)
        log "removing a leftover $PKG entry from $key"
        if [ -z "$new" ]; then
            "${ADB[@]}" shell settings delete secure "$key" </dev/null >/dev/null 2>&1
        else
            "${ADB[@]}" shell settings put secure "$key" "$new" </dev/null >/dev/null 2>&1
        fi
    done
}

NET_BLOCKED_BY=""
restore_net() {
    case "$NET_BLOCKED_BY" in
        root) "${ADB[@]}" shell service call ichthys_guard 1 i32 "$(app_uid)" i32 0 >/dev/null
            ;;
        connectivity) "${ADB[@]}" shell cmd connectivity set-package-networking-enabled true \
            "$PKG" >/dev/null ;;
        manual) log "remember to set IchthysProbe back to Allow in Guard" ;;
    esac
    NET_BLOCKED_BY=""
}

ROOTED=0
cleanup() {
    restore_net
    restore_settings
    if [ "$ROOTED" = 1 ]; then
        "${ADB[@]}" unroot >/dev/null 2>&1
    fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# ---------------------------------------------------------------- ground truth

# Row count of a content URI as the shell uid (exempt from every IchthysOS shield). Only the
# count leaves the phone.
truth_count() {
    local n
    n=$(sh_ "content query --uri '$1' --projection _id 2>/dev/null | grep -c '^Row:'")
    echo "${n:-0}"
}

TRUTH_ARGS=()
collect_truth() {
    local now end
    now=$(( $(date +%s) * 1000 ))
    end=$(( now + 30 * 86400000 ))
    TRUTH_ARGS=(
        --ei truth_contacts "$(truth_count content://com.android.contacts/contacts)"
        --ei truth_raw_contacts "$(truth_count content://com.android.contacts/raw_contacts)"
        --ei truth_phones "$(truth_count content://com.android.contacts/data/phones)"
        --ei truth_groups "$(truth_count content://com.android.contacts/groups)"
        --ei truth_profile "$(truth_count content://com.android.contacts/profile)"
        --ei truth_calendars "$(truth_count content://com.android.calendar/calendars)"
        --ei truth_events "$(truth_count content://com.android.calendar/events)"
        --ei truth_instances_30d "$(truth_count "content://com.android.calendar/instances/when/$now/$end")"
        --ei truth_calllog "$(truth_count content://call_log/calls)"
        --ei truth_sms "$(truth_count content://sms)"
        --ei truth_mms "$(truth_count content://mms)"
        --ei truth_conversations "$(truth_count 'content://mms-sms/conversations?simple=true')"
        --ei truth_packages "$(sh_ pm list packages --user 0 | grep -c '^package:')"
    )
    log "ground truth (counts only): ${TRUTH_ARGS[*]}"
}

# ---------------------------------------------------------------- install + quarantine

install_apps() {
    [ -f "$APK" ] || die "no APK at $APK (build: m IchthysProbe IchthysProbeHelper)"
    log "fresh install of $PKG"
    "${ADB[@]}" uninstall "$PKG" >/dev/null 2>&1
    "${ADB[@]}" install "$APK" || die "install failed"
    if [ -f "$HELPER_APK" ]; then
        "${ADB[@]}" install -r "$HELPER_APK" >/dev/null || log "helper install failed"
    else
        log "no helper APK at $HELPER_APK: clipboard checks will be skipped"
    fi
    # Guard handles PACKAGE_ADDED on its own handler; give it a moment (services-fixes G6).
    sleep 3

    local q=no
    is_quarantined "$PKG" && q=yes
    host_check guard.quarantine_on_install "First-launch quarantine" yes "$q" \
        "IchthysGuardService.java:1219-1255,1301-1317 (new user apps suspended with\
 FLAG_SUSPEND_QUARANTINED, suspender com.android.settings)"
    if [ -f "$HELPER_APK" ]; then
        local hq=no
        is_quarantined "$HELPER" && hq=yes
        host_check guard.no_launcher_not_quarantined "First-launch quarantine" no "$hq" \
            "IchthysGuardService.java:1227 (apps without a launcher activity are not\
 quarantined; services-fixes G3)"
    fi
    if [ "$q" = yes ]; then
        check_quarantine_behaviour
        release_quarantine
    fi
}

check_quarantine_behaviour() {
    require_unlocked
    local before after top
    before=$(sh_ logcat -d -s "$TAG:I" | grep -c 'START label=')
    "${ADB[@]}" shell am start -n "$PKG/.MainActivity" --ez autorun true --es label q-probe \
        >/dev/null 2>&1
    sleep 4
    after=$(sh_ logcat -d -s "$TAG:I" | grep -c 'START label=q-probe')
    top=$(top_activity)
    local blocked=no
    [ "$after" = 0 ] && blocked=yes
    host_check guard.quarantine_blocks_launch "First-launch quarantine" yes "$blocked" \
        "wm/ActivityStartInterceptor.java:437-459 + Guard dialog (core/res ichthys_strings.xml)" \
        "top=$top probe_started=$after (before=$before)"
    local un
    un=$(sh_ pm unsuspend "$PKG")
    local still=no
    is_quarantined "$PKG" && still=yes
    host_check guard.quarantine_shell_cannot_release "First-launch quarantine" yes "$still" \
        "PackageManagerShellCommand unsuspend only drops the shell suspender; Guard's entry stays" \
        "pm unsuspend said: $un"
}

release_quarantine() {
    if [ "$RELEASE_QUARANTINE" = 1 ]; then
        log "releasing the quarantine through Guard's first-launch sheet"
        require_unlocked
        "${ADB[@]}" shell am start -n "$PKG/.MainActivity" >/dev/null 2>&1
        sleep 2
        ui_tap text "Review" || log "no \"Review\" button found on screen"
        sleep 3
        ui_tap text "Open as-is" || log "no \"Open as-is\" button found on screen"
        sleep 3
    else
        log "IchthysProbe is QUARANTINED by Ichthys Guard (expected for a new app)."
        log "Release it on the phone: open IchthysProbe -> Review -> \"Open as-is\""
        log "(or rerun with --release-quarantine). Waiting up to ${WAIT_RELEASE}s..."
    fi
    local waited=0
    while is_quarantined "$PKG"; do
        [ "$waited" -ge "$WAIT_RELEASE" ] && die "still quarantined after ${WAIT_RELEASE}s:" \
            "release it in Guard and rerun with --skip-install"
        sleep 5
        waited=$((waited + 5))
    done
    local s=no
    is_suspended "$PKG" && s=yes
    host_check guard.quarantine_released "First-launch quarantine" no "$s" \
        "FirstLaunchActivity.kt:137-207 (setPackagesSuspended(false) by Settings)"
    # Back to the launcher if Guard's flow opened anything.
    "${ADB[@]}" shell input keyevent KEYCODE_HOME
}

# ---------------------------------------------------------------- runs

wait_log() {   # pattern timeout_s
    local pat="$1" t="$2" i
    for i in $(seq 1 "$t"); do
        sh_ logcat -d -s "$TAG:I" | grep -q -- "$pat" && return 0
        sleep 1
    done
    return 1
}

pull_report() {
    local label="$1" remote="/sdcard/Android/data/$PKG/files/reports/$label.json"
    if ! "${ADB[@]}" pull "$remote" "$OUT/$label.json" >/dev/null 2>&1; then
        "${ADB[@]}" exec-out cat "$remote" > "$OUT/$label.json" 2>/dev/null
    fi
    [ -s "$OUT/$label.json" ] || log "could not pull $remote"
}

run_probe() {   # label extra-am-args...
    local run="$1"; shift
    local label="$run-$STAMP"
    if is_quarantined "$PKG"; then
        host_check "guard.$run.not_quarantined" "First-launch quarantine" no yes \
            "run $run" "app is quarantined; the run can't start"
        log "SKIP run $run: the app is quarantined"
        return 1
    fi
    require_unlocked
    log "run $run (label $label)"
    "${ADB[@]}" shell am start -n "$PKG/.MainActivity" --ez autorun true --es label "$label" \
        "$@" "${TRUTH_ARGS[@]}" >/dev/null
    if ! wait_log "DONE label=$label " 300; then
        log "run $run: no DONE line within 300 s (app crashed or blocked? see $label.log)"
    fi
    if [ "$DO_TAPS" = 1 ]; then
        tap_phase "$label"
    fi
    sh_ logcat -d -s "$TAG:I" "IchthysProbeHelper:I" | grep -- "$label\|IchthysProbeHelper" \
        > "$OUT/$label.log"
    pull_report "$label"
}

tap_phase() {
    local label="$1"
    "${ADB[@]}" shell am start -n "$PKG/.MainActivity" >/dev/null 2>&1
    sleep 2
    # Warm the helper so its copy lands well inside the 2 s the tap allows.
    "${ADB[@]}" shell am broadcast -n "$HELPER/.ClipReceiver" -a "$HELPER.COPY" \
        --es token warm -f 0x10000020 >/dev/null 2>&1
    if ui_tap content-desc probe_tap_clipboard; then
        wait_log "TAP_DONE label=$label " 25 || log "tap probe didn't report"
    else
        log "tap button (content-desc probe_tap_clipboard) not found on screen"
    fi
}

grant_all() {
    log "granting every runtime permission (pm grant) and the app-ops"
    local p
    for p in $(sh_ dumpsys package "$PKG" | sed -n '/requested permissions:/,/install permissions:/p' \
            | grep -oE 'android\.permission\.[A-Za-z0-9_.]+'); do
        "${ADB[@]}" shell pm grant "$PKG" "$p" >/dev/null 2>&1
    done
    "${ADB[@]}" shell pm grant "$PKG" android.permission.ACCESS_BACKGROUND_LOCATION >/dev/null 2>&1
    "${ADB[@]}" shell pm grant "$PKG" android.permission.QUERY_ALL_PACKAGES >/dev/null 2>&1
    "${ADB[@]}" shell appops set "$PKG" GET_USAGE_STATS allow
    "${ADB[@]}" shell appops set "$PKG" SYSTEM_ALERT_WINDOW allow
}

# Back to "nothing granted": runtime permissions, QUERY_ALL_PACKAGES and the app-ops. Revoking
# kills the app, which is fine between runs.
revoke_all() {
    local p
    for p in $(sh_ dumpsys package "$PKG" | sed -n '/requested permissions:/,/install permissions:/p' \
            | grep -oE 'android\.permission\.[A-Za-z0-9_.]+'); do
        "${ADB[@]}" shell pm revoke "$PKG" "$p" >/dev/null 2>&1
    done
    "${ADB[@]}" shell appops set "$PKG" GET_USAGE_STATS default
    "${ADB[@]}" shell appops set "$PKG" SYSTEM_ALERT_WINDOW default
}

block_net() {
    local uid
    uid=$(app_uid)
    case "$GUARD_NET" in
        root)
            "${ADB[@]}" root >/dev/null 2>&1 && ROOTED=1
            sleep 3
            "${ADB[@]}" wait-for-device
            "${ADB[@]}" shell service call ichthys_guard 1 i32 "$uid" i32 2 >/dev/null \
                && NET_BLOCKED_BY=root
            ;;
        connectivity)
            "${ADB[@]}" shell cmd connectivity set-package-networking-enabled false "$PKG" \
                && NET_BLOCKED_BY=connectivity
            ;;
        manual)
            if [ -t 0 ]; then
                log "On the phone: Settings > Guard > IchthysProbe > Network: Block (No network)."
                read -r -p "[matrix] press Enter when done (or type skip): " ans
                [ "$ans" = skip ] || NET_BLOCKED_BY=manual
            else
                log "no terminal: skipping the Guard network block (use --guard-net)"
            fi
            ;;
    esac
    [ -n "$NET_BLOCKED_BY" ] || return 1
    local state
    state=$(sh_ cmd connectivity get-package-networking-enabled "$PKG" | sed 's/.*://')
    host_check guard.net_block_chain "Guard per-app network block" deny "${state:-?}" \
        "IchthysGuardService.java:378-443 (DENY -> FIREWALL_CHAIN_OEM_DENY_3)" \
        "blocked via $NET_BLOCKED_BY"
    # Guard re-pushes its whole table from Settings at times, which would undo a root write.
    return 0
}

# ---------------------------------------------------------------- main

check_device
require_unlocked
log "device: $(sh_ getprop ro.product.model) $(sh_ getprop ro.build.display.id)"
log "reports: $OUT"
scrub_leftover_lists
[ "$SKIP_INSTALL" = 1 ] || install_apps
is_quarantined "$PKG" && release_quarantine
collect_truth

case ",$RUNS," in *,a,*)
    revoke_all
    run_probe a --es qap default --es expect_net allowed
esac

case ",$RUNS," in *,b,*)
    grant_all
    run_probe b --es qap granted --es expect_net allowed
esac

case ",$RUNS," in *,c,*)
    grant_all
    for key in $PROTECT_LIST_KEYS; do
        list_add secure "$key"
    done
    if [ "$GUARD_NET" != none ] && block_net; then
        run_probe c --es qap granted --es expect_net blocked
        if [ "$WITH_PAUSE" = 1 ] && [ "$NET_BLOCKED_BY" = root ]; then
            log "Guard pause for 2 min"
            "${ADB[@]}" shell service call ichthys_guard 9 i32 2 >/dev/null
            sleep 5
            run_probe c-paused --es qap granted --es expect_net allowed
            log "waiting for the pause to end"
            sleep 140
            run_probe c-resumed --es qap granted --es expect_net blocked
        fi
        restore_net
    else
        run_probe c --es qap granted
    fi
    restore_settings
esac

case ",$RUNS," in *,d,*)
    grant_all
    for key in $ALLOW_LIST_KEYS; do
        list_add secure "$key"
    done
    # IchthysOS: the write shields' own lists stay untouched, but the read allow lists lift
    # them too (IchthysShield: an app allowed the real data may change it). The write probes
    # see that and don't insert test rows in run d (PersonalProbes, Q.writeLifted).
    run_probe d --es qap granted --es expect_net allowed
    restore_settings
esac

python3 -c 'import json,sys
rows=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]
json.dump(rows, open(sys.argv[2], "w"), indent=1)' "$HOST_CHECKS" "$OUT/host-checks.json"

log "done; reports in $OUT"
python3 "$HERE/compare.py" "$OUT"
