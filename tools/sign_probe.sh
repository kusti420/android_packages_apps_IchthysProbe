#!/usr/bin/env bash
# IchthysOS: re-signs a built IchthysProbe.apk with the dedicated probe key. Guard (Settings)
# trusts the tester only when it is signed with this certificate (VerifyRunner.PROBE_CERT_SHA256,
# the SHA-256 of certs/ichthys_probe.x509.pem); the testkey build of `m IchthysProbe` is refused.
# The private key stays in ~/.android-certs (never in the tree, never copied).
#
#   tools/sign_probe.sh [in.apk] [out.apk]
#   adb install -r out.apk
set -euo pipefail
KEY="${PROBE_KEY:-$HOME/.android-certs/ichthys_probe}"
IN="${1:-${ANDROID_PRODUCT_OUT:?run lunch first}/system/app/IchthysProbe/IchthysProbe.apk}"
OUT="${2:-${IN%.apk}-signed.apk}"
[ -f "$KEY.pk8" ] && [ -f "$KEY.x509.pem" ] || { echo "no probe key at $KEY.{pk8,x509.pem}" >&2; exit 1; }
apksigner sign --key "$KEY.pk8" --cert "$KEY.x509.pem" --out "$OUT" "$IN"
apksigner verify --print-certs "$OUT" | grep -i 'SHA-256'
echo "signed: $OUT"
