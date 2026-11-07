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

import java.util.EnumSet;

/**
 * An IchthysOS promise a probe checks: the feature, where the promise comes from in the source,
 * when it applies, and which outcomes keep it. Expectations are written as the feature promises,
 * not as the current code behaves, so a known gap shows up red until it is fixed.
 */
public final class Expect {

    /** Returns null when the expectation applies, or a short reason why it doesn't. */
    public interface Condition {
        String notApplicable(Ctx c);
    }

    /** Extra check on the details: null when fine, or what broke the promise. */
    public interface Check {
        String failure(Ctx c, Result r);
    }

    /** Short feature name, e.g. "Clipboard lockdown". */
    public final String feature;
    /** Where the promise comes from: file and line or UI string. */
    public final String source;
    /** The promise in words, e.g. "a read without a tap returns nothing". */
    public final String promise;

    private EnumSet<Outcome> mAllowed;
    private Condition mWhen;
    private Check mCheck;

    private Expect(String feature, String source, String promise) {
        this.feature = feature;
        this.source = source;
        this.promise = promise;
    }

    public static Expect of(String feature, String source, String promise) {
        return new Expect(feature, source, promise);
    }

    /** The outcomes that keep the promise. */
    public Expect outcomes(Outcome first, Outcome... rest) {
        mAllowed = EnumSet.of(first, rest);
        return this;
    }

    public Expect when(Condition when) {
        mWhen = when;
        return this;
    }

    public Expect check(Check check) {
        mCheck = check;
        return this;
    }

    /** Text form of the allowed outcomes, for the report. */
    public String expectedText() {
        if (mAllowed == null) {
            return mCheck != null ? "check: " + promise : "";
        }
        final StringBuilder sb = new StringBuilder();
        for (Outcome o : mAllowed) {
            if (sb.length() > 0) {
                sb.append(" | ");
            }
            sb.append(o.key);
        }
        return sb.toString();
    }

    /** Judges {@code r} and writes the verdict and its reason into it. */
    public void judge(Ctx c, Result r) {
        if (r.outcome == Outcome.SKIPPED) {
            r.verdict = Verdict.SKIP;
            r.verdictWhy = "not run";
            return;
        }
        final String na;
        try {
            na = mWhen == null ? null : mWhen.notApplicable(c);
        } catch (RuntimeException e) {
            r.verdict = Verdict.INFO;
            r.verdictWhy = "condition failed: " + Redact.exception(e);
            return;
        }
        if (na != null) {
            r.verdict = Verdict.INFO;
            r.verdictWhy = "n/a: " + na;
            return;
        }
        if (r.outcome == Outcome.UNAVAILABLE
                && (mAllowed == null || !mAllowed.contains(Outcome.UNAVAILABLE))) {
            r.verdict = Verdict.INFO;
            r.verdictWhy = "n/a: not available on this device/state";
            return;
        }
        if (r.outcome == Outcome.ERROR
                && (mAllowed == null || !mAllowed.contains(Outcome.ERROR))) {
            // A fail (fail-closed: the promise wasn't checked), but kept distinguishable: Guard's
            // Verify counts a why starting with "probe error" as an error, not a broken promise.
            r.verdict = Verdict.FAIL;
            r.verdictWhy = "probe error: the promise couldn't be checked: " + r.detailLine();
            return;
        }
        if (mAllowed != null && !mAllowed.contains(r.outcome)) {
            r.verdict = Verdict.FAIL;
            r.verdictWhy = "expected " + expectedText() + ", got " + r.outcome.key;
            return;
        }
        if (mCheck != null) {
            final String failure = mCheck.failure(c, r);
            if (failure != null) {
                r.verdict = Verdict.FAIL;
                r.verdictWhy = failure;
                return;
            }
        }
        r.verdict = Verdict.PASS;
        r.verdictWhy = "as promised: " + promise;
    }
}
