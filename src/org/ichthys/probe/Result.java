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

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * What one probe run found. {@link #detail} holds only redacted facts: counts, lengths, types,
 * coarse ranges, booleans and salted hashes (see {@link Redact}). Never put raw personal data in
 * here; everything in it ends up in the JSON report and in logcat.
 */
public final class Result {
    public final Outcome outcome;
    /** Ordered key/value facts. Values are short strings. */
    public final Map<String, String> detail = new LinkedHashMap<>();

    /** Filled in by the runner. */
    public String granted = "n/a";
    public Verdict verdict = Verdict.INFO;
    /** Why the verdict is what it is (expectation text, or why it doesn't apply). */
    public String verdictWhy = "";
    public long millis;

    private Result(Outcome outcome) {
        this.outcome = outcome;
    }

    public static Result of(Outcome outcome) {
        return new Result(outcome);
    }

    public static Result visible() {
        return new Result(Outcome.VISIBLE);
    }

    public static Result empty() {
        return new Result(Outcome.EMPTY);
    }

    public static Result blockedPermission(String why) {
        return new Result(Outcome.BLOCKED_PERMISSION).put("why", why);
    }

    public static Result blockedIchthys(String why) {
        return new Result(Outcome.BLOCKED_ICHTHYS).put("why", why);
    }

    public static Result unavailable(String why) {
        return new Result(Outcome.UNAVAILABLE).put("why", why);
    }

    public static Result skipped(String why) {
        return new Result(Outcome.SKIPPED).put("why", why);
    }

    public static Result error(Throwable t) {
        return new Result(Outcome.ERROR).put("error", Redact.exception(t));
    }

    /** A SecurityException from the platform: stock permission refusal. */
    public static Result fromSecurity(SecurityException e) {
        return new Result(Outcome.BLOCKED_PERMISSION).put("error", Redact.exception(e));
    }

    /** Visible when {@code n > 0}, empty otherwise, with the count recorded under {@code key}. */
    public static Result count(String key, int n) {
        return new Result(n > 0 ? Outcome.VISIBLE : Outcome.EMPTY).put(key, String.valueOf(n));
    }

    public Result put(String key, String value) {
        detail.put(key, value == null ? "null" : value);
        return this;
    }

    public Result put(String key, long value) {
        detail.put(key, String.valueOf(value));
        return this;
    }

    public Result put(String key, boolean value) {
        detail.put(key, String.valueOf(value));
        return this;
    }

    /** One line for logcat and the UI. */
    public String detailLine() {
        final StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : detail.entrySet()) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(e.getKey()).append('=').append(e.getValue());
        }
        return sb.toString();
    }
}
