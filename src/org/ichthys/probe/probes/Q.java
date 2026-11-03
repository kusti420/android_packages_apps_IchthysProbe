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

import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;

import org.ichthys.probe.Ctx;
import org.ichthys.probe.Expect;
import org.ichthys.probe.Outcome;
import org.ichthys.probe.Result;
import org.ichthys.probe.Shields;

/** Small helpers shared by the probe groups. */
final class Q {
    private Q() {}

    /** Row count of a query, -1 when the provider returned a null cursor. */
    static int count(ContentResolver cr, Uri uri, String[] projection, String selection) {
        try (Cursor c = cr.query(uri, projection, selection, null, null)) {
            return c == null ? -1 : c.getCount();
        }
    }

    /** Column count of a query (shielded providers keep the real columns), -1 for null. */
    static int columns(ContentResolver cr, Uri uri, String[] projection) {
        try (Cursor c = cr.query(uri, projection, null, null, null)) {
            return c == null ? -1 : c.getColumnCount();
        }
    }

    /**
     * Classifies a row count from a provider behind an IchthysOS read shield. Zero rows while the
     * shield protects this app and the host's ground truth (counted as the exempt shell uid) is
     * above zero is proof of the shield: blocked-by-IchthysOS. Zero rows without that proof stay
     * "empty".
     */
    static Result shieldedRows(Ctx c, String key, int rows, Shields.Shield shield, String truth) {
        if (rows < 0) {
            return Result.empty().put(key, "null cursor");
        }
        final int t = c.truth(truth);
        final Result r;
        if (rows > 0) {
            r = Result.visible().put(key, rows);
        } else if (t > 0 && c.shields.protects(shield)) {
            r = Result.blockedIchthys("shield " + shield.name).put(key, 0);
        } else {
            r = Result.empty().put(key, 0);
        }
        r.put("truth_rows", t < 0 ? "unknown" : String.valueOf(t));
        r.put("shield_protects", c.shields.protects(shield));
        return r;
    }

    /**
     * Expectation for a read shield. While the shield protects this app (and it holds the
     * permission) it sees nothing; once the user allows it (listed, or the switch off) and the
     * host says the provider has rows, it sees them.
     */
    static Expect readShield(String feature, String source, String promise, String permission,
            Shields.Shield shield, String truth) {
        return Expect.of(feature, source, promise + "; an allowed app reads the real data")
                .when(c -> {
                    if (!c.granted(permission)) {
                        return "permission not granted (stock refusal)";
                    }
                    if (!c.shields.authoritative()) {
                        return c.shields.notProtecting(shield);
                    }
                    if (!c.shields.protects(shield) && c.truth(truth) <= 0) {
                        return c.shields.notProtecting(shield) + ", no ground truth to compare";
                    }
                    return null;
                })
                .check((c, r) -> {
                    if (c.shields.protects(shield)) {
                        return r.outcome == Outcome.EMPTY || r.outcome == Outcome.BLOCKED_ICHTHYS
                                ? null : "real data visible although the shield protects this app";
                    }
                    return r.outcome == Outcome.VISIBLE ? null
                            : "allowed app sees no rows although the provider has "
                                    + c.truth(truth);
                });
    }

    /**
     * IchthysOS: null while {@code write} protects this app, otherwise why not. Being on the
     * allow list of the matching read shield ({@code read}) lifts the write shield too
     * (IchthysShield.isRestricted in ContactsProvider and CalendarProvider: "an app the user
     * gave real access to the data may also change it").
     */
    static String writeLifted(Ctx c, Shields.Shield write, Shields.Shield read) {
        if (!c.shields.authoritative()) {
            // IchthysOS: the lists are hidden from apps; a test row is only ever written when
            // Guard says the write shield protects this app.
            return "shield lists are hidden from apps; write shields are judged only in a Guard "
                    + "verification (no test row is written otherwise)";
        }
        if (c.shields.listed(read)) {
            return "app is allowed the real data (" + read.listKey + "), which lifts the write "
                    + "shield";
        }
        return c.shields.notProtecting(write);
    }

    /** Expectation for a write shield: insert "succeeds" with a fake id 0 and nothing is saved. */
    static Expect writeShield(String feature, String source, String promise, String permission,
            Shields.Shield shield, Shields.Shield readShield) {
        return Expect.of(feature, source, promise)
                .outcomes(Outcome.BLOCKED_ICHTHYS)
                .when(c -> !c.granted(permission) ? "permission not granted (stock refusal)"
                        : writeLifted(c, shield, readShield));
    }

    /**
     * Classifies the Uri an insert returned. The IchthysOS write shields answer with
     * {@code <uri>/0} (ContentProvider.rejectInsert): reported as blocked-by-IchthysOS. A real id
     * means the row was saved; the caller deletes it again.
     */
    static Result insertResult(Uri inserted) {
        if (inserted == null) {
            return Result.empty().put("insert", "null");
        }
        final String last = inserted.getLastPathSegment();
        if ("0".equals(last)) {
            return Result.blockedIchthys("insert answered with fake id 0, nothing saved")
                    .put("insert", "fake id 0");
        }
        return Result.visible().put("insert", "saved (real id)");
    }

    static String yesNo(boolean b) {
        return b ? "yes" : "no";
    }
}
