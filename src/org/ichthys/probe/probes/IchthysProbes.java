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

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import org.ichthys.probe.Ctx;
import org.ichthys.probe.Expect;
import org.ichthys.probe.Outcome;
import org.ichthys.probe.Probe;
import org.ichthys.probe.Redact;
import org.ichthys.probe.Result;
import org.ichthys.probe.Shields;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * IchthysOS's own settings and keys as an app sees them: which configuration keys leak, the
 * keybox read gate, and the key attestation chain this app gets.
 */
public final class IchthysProbes {
    static final String CAT = "IchthysOS settings & keys";

    private static final String SRC_KEYBOX =
            "frameworks/base/packages/SettingsProvider/src/com/android/providers/settings/"
                    + "SettingsProvider.java:2405-2438 (isKeyboxReadableByCaller; "
                    + "kusti420/ichthysos-tracker#13)";

    /** Undeclared IchthysOS keys a third-party app can probe, with their table. */
    private static final String[][] KEYS = {
        {"g", "ichthys_clipboard_lockdown"}, {"g", "ichthys_clipboard_clear_minutes"},
        {"g", "ichthys_sensor_fingerprint_protection"}, {"g", "ichthys_contacts_lockdown"},
        {"g", "ichthys_cast_enabled"}, {"g", "network_decoy_enabled"},
        {"g", "ichthys_privacy_level"}, {"s", "ichthys_privacy_level"},
        {"s", "ichthys_backstage_pkgs"}, {"s", "ichthys_bt_connect_devices"},
        {"s", "spoof_pif_config"}, {"s", "spoof_trickystore_target"},
        {"s", "spoof_trickystore_keybox"}, {"s", "spoof_pif_photos"},
        {"s", "ichthys_unrestricted_bg_pkgs"},
    };

    private IchthysProbes() {}

    /**
     * IchthysOS: whether this app is a line of spoof_trickystore_target (one package per line,
     * optional '!' or '?' suffix), the way SettingsProvider.isKeyboxReadableByCaller reads it.
     */
    static boolean listedAsTarget(Ctx c) {
        final Shields.Read target = c.shields.read("spoof_trickystore_target", false);
        if (!target.readable || target.value == null) {
            return false;
        }
        for (String line : target.value.split("\n")) {
            String pkg = line.trim();
            if (pkg.endsWith("!") || pkg.endsWith("?")) {
                pkg = pkg.substring(0, pkg.length() - 1).trim();
            }
            if (pkg.equals(c.app.getPackageName())) {
                return true;
            }
        }
        return false;
    }

    public static void add(List<Probe> out) {
        out.add(new Probe(CAT, "settings.shield_lists",
                "Whether this app can read every shield switch and per-app list (which apps the "
                        + "user trusts or shields): readable list count and entries, not names.",
                Probe.NONE,
                c -> {
                    int readableLists = 0;
                    int entries = 0;
                    int lists = 0;
                    for (Shields.Shield s : Shields.ALL) {
                        if (s.listKey == null) {
                            continue;
                        }
                        lists++;
                        final Shields.Read r = c.shields.read(s.listKey, false);
                        if (r.readable) {
                            readableLists++;
                            if (r.value != null) {
                                for (String e : r.value.split(",")) {
                                    if (!e.trim().isEmpty()) {
                                        entries++;
                                    }
                                }
                            }
                        }
                    }
                    final Result res = readableLists > 0 ? Result.visible()
                            : Result.blockedPermission("no list readable");
                    return res.put("lists_readable", readableLists + "/" + lists)
                            .put("entries_total", entries)
                            .put("note", "undeclared Secure keys are readable by every app");
                }));

        out.add(new Probe(CAT, "settings.ichthys_keys",
                "IchthysOS and spoofing keys readable by any app (presence and length only).",
                Probe.NONE,
                c -> {
                    final Result r = Result.visible();
                    int readable = 0;
                    for (String[] k : KEYS) {
                        final Shields.Read v = c.shields.read(k[1], "g".equals(k[0]));
                        if (v.readable) {
                            readable++;
                        }
                        r.put(k[0] + ":" + k[1], !v.readable ? "refused"
                                : v.value == null ? "unset" : Redact.length(v.value));
                    }
                    r.put("readable", readable + "/" + KEYS.length);
                    return r;
                }));

        out.add(new Probe(CAT, "settings.keybox",
                "Whether this app can read the attestation keybox (private keys) from settings.",
                Probe.NONE,
                c -> {
                    final boolean listed = listedAsTarget(c);
                    final Shields.Read kb = c.shields.read("spoof_trickystore_keybox", false);
                    final Result r;
                    if (!kb.readable) {
                        r = Result.blockedPermission(kb.error);
                    } else if (kb.value == null) {
                        // IchthysOS: the gate and "no keybox installed" look the same to an
                        // app, and shell can't read the key either; say so in the report.
                        r = Result.blockedIchthys("reads as absent").put("note",
                                "also absent when no keybox is installed; check with root");
                    } else {
                        r = Result.visible().put("keybox", Redact.length(kb.value));
                    }
                    return r.put("listed_as_target", listed);
                })
                .expect(Expect.of("Keybox read gate", SRC_KEYBOX,
                        "only system/root and listed attestation targets read the keybox; "
                                + "everyone else sees it as absent")
                        .outcomes(Outcome.BLOCKED_ICHTHYS, Outcome.BLOCKED_PERMISSION)
                        // IchthysOS: the same line match as the body and SettingsProvider; a
                        // substring test also hit e.g. "org.ichthys.probe.helper".
                        .when(c -> listedAsTarget(c)
                                ? "this app is listed as an attestation target" : null)));

        out.add(new Probe(CAT, "keystore.attestation",
                "The key attestation chain this app gets (length, root, leaf issuer: hashes).",
                Probe.NONE,
                c -> {
                    final String alias = "ichthysprobe-attest";
                    final KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
                    kpg.initialize(new KeyGenParameterSpec.Builder(alias,
                            KeyProperties.PURPOSE_SIGN)
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setAttestationChallenge("ichthysprobe".getBytes())
                            .build());
                    kpg.generateKeyPair();
                    final KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
                    ks.load(null);
                    try {
                        final Certificate[] chain = ks.getCertificateChain(alias);
                        if (chain == null || chain.length == 0) {
                            return Result.empty().put("chain", 0);
                        }
                        final X509Certificate leaf = (X509Certificate) chain[0];
                        final X509Certificate root = (X509Certificate) chain[chain.length - 1];
                        return Result.visible().put("chain", chain.length)
                                .put("root_subject", Redact.hash(
                                        root.getSubjectX500Principal().getName()))
                                .put("root_self_signed", root.getSubjectX500Principal()
                                        .equals(root.getIssuerX500Principal()))
                                .put("leaf_issuer", Redact.hash(
                                        leaf.getIssuerX500Principal().getName()));
                    } finally {
                        ks.deleteEntry(alias);
                    }
                })
                .timeout(15_000));
    }
}
