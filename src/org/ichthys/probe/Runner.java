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

import android.os.SystemClock;
import android.util.Log;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Runs one probe with a timeout and turns whatever happens into a judged {@link Result}. */
public final class Runner {
    public static final String TAG = "IchthysProbe";

    private static final ExecutorService POOL = Executors.newCachedThreadPool(r -> {
        final Thread t = new Thread(r, "probe");
        t.setDaemon(true);
        return t;
    });

    private Runner() {}

    /** Runs {@code p}. Call from a background thread; blocks up to the probe's timeout. */
    public static Result run(Probe p, Ctx c) {
        final long start = SystemClock.elapsedRealtime();
        Result r;
        final Future<Result> f = POOL.submit(() -> p.body.run(c));
        try {
            r = f.get(p.timeoutMs(), TimeUnit.MILLISECONDS);
            if (r == null) {
                r = Result.error(new IllegalStateException("probe returned null"));
            }
        } catch (TimeoutException e) {
            f.cancel(true);
            r = Result.of(Outcome.ERROR).put("error", "timeout after " + p.timeoutMs() + " ms");
        } catch (ExecutionException e) {
            final Throwable cause = e.getCause();
            if (cause instanceof SecurityException) {
                r = Result.fromSecurity((SecurityException) cause);
            } else {
                r = Result.error(cause);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            r = Result.error(e);
        } catch (RuntimeException e) {
            r = Result.error(e);
        }
        r.millis = SystemClock.elapsedRealtime() - start;
        try {
            r.granted = p.grantedState(c);
        } catch (RuntimeException e) {
            r.granted = "?";
        }
        final Expect e = p.expectation();
        if (e != null) {
            e.judge(c, r);
        } else if (r.outcome == Outcome.SKIPPED) {
            r.verdict = Verdict.SKIP;
            r.verdictWhy = "not run";
        } else {
            r.verdict = Verdict.INFO;
            r.verdictWhy = "";
        }
        Log.i(TAG, summary(c.label, p, r));
        return r;
    }

    /** The one logcat line per probe. */
    static String summary(String label, Probe p, Result r) {
        return "[" + label + "] " + p.id + " outcome=" + r.outcome.key + " verdict="
                + r.verdict.key + " granted=" + r.granted + " | " + r.detailLine()
                + (r.verdict == Verdict.FAIL ? " | FAIL: " + r.verdictWhy : "");
    }
}
