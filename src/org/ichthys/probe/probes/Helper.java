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

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;

import org.ichthys.probe.Ctx;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Talks to the companion app org.ichthys.probe.helper, which plays "another app" (its own uid)
 * for the clipboard checks: it copies a clip and tries to read the clipboard from the background.
 * Ordered broadcasts with FLAG_INCLUDE_STOPPED_PACKAGES, so the helper needs no activity start
 * (and no focus change).
 */
final class Helper {
    static final String PACKAGE = "org.ichthys.probe.helper";
    static final String RECEIVER = PACKAGE + ".ClipReceiver";
    static final String ACTION_COPY = PACKAGE + ".COPY";
    static final String ACTION_READ = PACKAGE + ".READ";
    static final String EXTRA_TOKEN = "token";
    static final String CLIP_PREFIX = "IchthysProbeHelper:";
    static final String CLIP_LABEL = "IchthysProbeHelper";

    private Helper() {}

    /** What the helper answered; null when it didn't answer (missing, quarantined, stopped). */
    static final class Reply {
        final int code;
        final String data;

        Reply(int code, String data) {
            this.code = code;
            this.data = data;
        }
    }

    static boolean installed(Ctx c) {
        try {
            c.app.getPackageManager().getPackageInfo(PACKAGE, 0);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    static Reply call(Ctx c, String action, String token, long timeoutMs) {
        final Intent i = new Intent(action)
                .setComponent(new ComponentName(PACKAGE, RECEIVER))
                .addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES | Intent.FLAG_RECEIVER_FOREGROUND)
                .putExtra(EXTRA_TOKEN, token);
        final AtomicReference<Reply> out = new AtomicReference<>();
        final CountDownLatch done = new CountDownLatch(1);
        c.app.sendOrderedBroadcast(i, null, new BroadcastReceiver() {
            @Override
            public void onReceive(Context ctx, Intent intent) {
                out.set(new Reply(getResultCode(), getResultData()));
                done.countDown();
            }
        }, c.worker, Activity.RESULT_CANCELED, null, null);
        try {
            done.await(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        final Reply r = out.get();
        // RESULT_OK means the helper's receiver really ran.
        return r != null && r.code == Activity.RESULT_OK ? r : null;
    }

    /** Asks the helper to copy {@code CLIP_PREFIX + token}; true when it did. */
    static boolean copy(Ctx c, String token) {
        return call(c, ACTION_COPY, token, 5000) != null;
    }

    /** Asks the helper to read the clipboard from the background: its redacted answer or null. */
    static String readInBackground(Ctx c, String token) {
        final Reply r = call(c, ACTION_READ, token, 5000);
        return r == null ? null : r.data;
    }
}
