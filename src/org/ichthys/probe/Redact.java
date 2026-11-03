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

import android.content.Context;
import android.content.SharedPreferences;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * The only ways a probe may describe a value it saw: presence, length, count, coarse range,
 * type, or a salted hash. The salt is random per install and never leaves the app's private
 * storage, so a hash tells two runs apart ("the value changed") without revealing the value.
 */
public final class Redact {
    private static final String PREFS = "probe";
    private static final String KEY_SALT = "salt";
    private static byte[] sSalt;

    private Redact() {}

    static synchronized void init(Context context) {
        if (sSalt != null) {
            return;
        }
        final SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String hex = prefs.getString(KEY_SALT, null);
        if (hex == null) {
            final byte[] b = new byte[16];
            new SecureRandom().nextBytes(b);
            hex = toHex(b, b.length);
            prefs.edit().putString(KEY_SALT, hex).apply();
        }
        sSalt = hex.getBytes(StandardCharsets.US_ASCII);
    }

    /** Salted SHA-256, first 10 hex chars: "h:1a2b3c4d5e". Null stays "null". */
    public static synchronized String hash(String value) {
        if (value == null) {
            return "null";
        }
        try {
            final MessageDigest md = MessageDigest.getInstance("SHA-256");
            if (sSalt != null) {
                md.update(sSalt);
            }
            final byte[] d = md.digest(value.getBytes(StandardCharsets.UTF_8));
            return "h:" + toHex(d, 5);
        } catch (Exception e) {
            return "h:?";
        }
    }

    /** "absent", "empty" or "N chars, h:..." for a string the app could read. */
    public static String text(CharSequence s) {
        if (s == null) {
            return "absent";
        }
        if (s.length() == 0) {
            return "empty";
        }
        return s.length() + " chars, " + hash(s.toString());
    }

    /** Length only, for values whose hash would also be too revealing to compare. */
    public static String length(CharSequence s) {
        if (s == null) {
            return "absent";
        }
        return s.length() == 0 ? "empty" : s.length() + " chars";
    }

    /** A coarse bucket for a non-negative count or size: 0, 1, 2-9, 10-99, 100-999, 1000+. */
    public static String bucket(long n) {
        if (n <= 0) {
            return "0";
        }
        if (n == 1) {
            return "1";
        }
        if (n < 10) {
            return "2-9";
        }
        if (n < 100) {
            return "10-99";
        }
        if (n < 1000) {
            return "100-999";
        }
        return "1000+";
    }

    /** Bytes rounded to whole GB (or MB under 1 GB). */
    public static String bytes(long b) {
        if (b < 0) {
            return "?";
        }
        if (b < (1L << 30)) {
            return (b >> 20) + " MB";
        }
        return Math.round(b / (double) (1L << 30)) + " GB";
    }

    /** Milliseconds as a coarse duration: "<1 min", "N min", "N h", "N d". */
    public static String age(long ms) {
        if (ms < 0) {
            return "future";
        }
        final long min = ms / 60000;
        if (min < 1) {
            return "<1 min";
        }
        if (min < 120) {
            return min + " min";
        }
        final long h = min / 60;
        return h < 48 ? h + " h" : (h / 24) + " d";
    }

    /** Exception class and a short message (platform messages name permissions, not data). */
    public static String exception(Throwable t) {
        if (t == null) {
            return "null";
        }
        String m = t.getMessage();
        if (m != null && m.length() > 160) {
            m = m.substring(0, 160) + "...";
        }
        return t.getClass().getSimpleName() + (m == null ? "" : ": " + m.replace('\n', ' '));
    }

    private static String toHex(byte[] b, int n) {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            sb.append(String.format("%02x", b[i] & 0xff));
        }
        return sb.toString();
    }
}
