#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Generate the complete Fortress OS release key set OFFLINE (run on the
# signing Mac, never in CI). Mirrors AOSP development/tools/make_key and the
# LineageOS "Signing Builds" guide, using only openssl.
#
#   signing/make_keys.sh [OUTDIR]        (default: ~/.fortress-keys)
#
# Put OUTDIR on an encrypted volume (docs/SIGNING.md). Keys are generated
# once; re-running refuses to touch an existing key directory because
# replacing keys breaks OTA updates for every installed device.
set -euo pipefail

out="${1:-$HOME/.fortress-keys}"
subject_base="${FORTRESS_KEY_SUBJECT:-/C=PL/O=Fortress OS/OU=Release}"
bits=4096

# APK/platform certificates (LineageOS 23.x list).
certs="bluetooth cyngn-app media networkstack nfc platform releasekey
       sdk_sandbox shared testcert verity"

# APEX container + payload keys (LineageOS 23.x list, signing_builds.md).
apexes="com.android.adbd com.android.adservices com.android.adservices.api
com.android.appsearch com.android.art com.android.bluetooth com.android.bt
com.android.btservices com.android.cellbroadcast com.android.compos
com.android.configinfrastructure com.android.connectivity.resources
com.android.conscrypt com.android.crashrecovery com.android.devicelock
com.android.extservices com.android.graphics.pdf
com.android.hardware.authsecret com.android.hardware.biometrics.face.virtual
com.android.hardware.biometrics.fingerprint.virtual com.android.hardware.boot
com.android.hardware.cas com.android.hardware.contexthub
com.android.hardware.drm.clearkey com.android.hardware.dumpstate
com.android.hardware.gatekeeper.nonsecure com.android.hardware.neuralnetworks
com.android.hardware.power com.android.hardware.rebootescrow
com.android.hardware.thermal com.android.hardware.threadnetwork
com.android.hardware.uwb com.android.hardware.vibrator
com.android.hardware.wifi com.android.healthfitness
com.android.hotspot2.osulogin com.android.i18n com.android.ipsec
com.android.media com.android.media.swcodec com.android.mediaprovider
com.android.nearby.halfsheet com.android.networkstack.tethering
com.android.neuralnetworks com.android.nfcservices com.android.npumanager
com.android.ondevicepersonalization com.android.os.statsd
com.android.permission com.android.profiling com.android.resolv
com.android.rkpd com.android.runtime com.android.safetycenter.resources
com.android.scheduling com.android.sdkext com.android.support.apexer
com.android.telephony com.android.telephonycore com.android.telephonymodules
com.android.tethering com.android.tzdata com.android.uprobestats
com.android.uwb com.android.uwb.resources com.android.virt
com.android.vndk.current com.android.vndk.current.on_vendor
com.android.webapp com.android.wifi com.android.wifi.dialog
com.android.wifi.resources com.google.pixel.camera.hal
com.google.pixel.vibrator.hal com.qorvo.uwb"

if [ -e "$out" ] && [ -n "$(ls -A "$out" 2>/dev/null)" ]; then
	echo "make_keys: $out already contains keys; refusing to overwrite" >&2
	exit 1
fi
repo="$(cd "$(dirname "$0")/.." && pwd -P)"
mkdir -p "$out"
out_abs="$(cd "$out" && pwd -P)"
case "$out_abs/" in
"$repo"/*)
	echo "make_keys: $out is inside the Fortress source tree; refusing" >&2
	rmdir "$out" 2>/dev/null || true
	exit 1 ;;
esac
if git -C "$out" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	echo "make_keys: $out is inside a git work tree; refusing" >&2
	rmdir "$out" 2>/dev/null || true
	exit 1
fi

umask 077
cd "$out"

# gen NAME CN [keep-pem]: NAME.pk8 (PKCS#8 DER) + NAME.x509.pem, and
# NAME.pem (PKCS#8 PEM) when keep-pem is given (APEX payload keys).
gen() {
	local name="$1" cn="$2" keep_pem="${3:-}"

	openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$bits" \
		-out "$name.key.tmp" 2>/dev/null
	openssl req -new -x509 -sha256 -days 10000 -key "$name.key.tmp" \
		-subj "$subject_base/CN=$cn" -out "$name.x509.pem"
	openssl pkcs8 -topk8 -nocrypt -outform DER -in "$name.key.tmp" \
		-out "$name.pk8"
	if [ -n "$keep_pem" ]; then
		openssl pkcs8 -topk8 -nocrypt -in "$name.key.tmp" -out "$name.pem"
	fi
	rm -f "$name.key.tmp"
}

n=0
for c in $certs; do
	gen "$c" "Fortress OS $c"
	n=$((n + 1))
done
ln -sf releasekey.pk8 testkey.pk8
ln -sf releasekey.x509.pem testkey.x509.pem

for a in $apexes; do
	gen "$a" "$a" keep-pem
	n=$((n + 1))
done

# Android Verified Boot signing key (vbmeta).
openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$bits" \
	-out avb.pem 2>/dev/null
n=$((n + 1))

# Public fingerprints, safe to publish (docs/SIGNING.md).
for c in $certs; do
	printf '%s ' "$c"
	openssl x509 -in "$c.x509.pem" -noout -fingerprint -sha256
done > CERT-FINGERPRINTS.txt

echo "make_keys: generated $n keys in $out"
echo "make_keys: back this directory up offline; losing it ends OTA updates."
