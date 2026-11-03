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

/**
 * One thing an ordinary app can try to observe. A probe has a stable id ("contacts.rows"), a
 * category, the permissions it depends on (empty: needs none), a sentence on what it reveals,
 * and a body that returns a redacted {@link Result}. An optional {@link Expect} turns the result
 * into a pass/fail check of an IchthysOS promise.
 */
public final class Probe {

    /** The probe body. Runs on a worker thread; may block for a few seconds. */
    public interface Body {
        Result run(Ctx c) throws Exception;
    }

    public static final String[] NONE = new String[0];

    public final String category;
    public final String id;
    public final String reveals;
    public final String[] permissions;
    public final Body body;

    private Expect mExpect;
    private boolean mNeedsTap;
    private long mTimeoutMs = 10_000;

    public Probe(String category, String id, String reveals, String[] permissions, Body body) {
        this.category = category;
        this.id = id;
        this.reveals = reveals;
        this.permissions = permissions == null ? NONE : permissions;
        this.body = body;
    }

    public static String[] perms(String... p) {
        return p;
    }

    public Probe expect(Expect e) {
        mExpect = e;
        return this;
    }

    /** Only runs from a real tap on its button (the autorun skips it). */
    public Probe needsTap() {
        mNeedsTap = true;
        return this;
    }

    public Probe timeout(long ms) {
        mTimeoutMs = ms;
        return this;
    }

    public Expect expectation() {
        return mExpect;
    }

    public boolean isTapProbe() {
        return mNeedsTap;
    }

    public long timeoutMs() {
        return mTimeoutMs;
    }

    /** "n/a" (no permission needed), "granted", "denied" or "partial a/b". */
    public String grantedState(Ctx c) {
        if (permissions.length == 0) {
            return "n/a";
        }
        int granted = 0;
        for (String p : permissions) {
            if (c.granted(p)) {
                granted++;
            }
        }
        if (granted == permissions.length) {
            return "granted";
        }
        return granted == 0 ? "denied" : "partial " + granted + "/" + permissions.length;
    }
}
