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

package org.ichthys.probe.helper;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * COPY: puts "IchthysProbeHelper:&lt;token&gt;" on the clipboard (a write needs no focus).
 * READ: reads the clipboard from the background and answers "match" when the clip equals the
 * token, "null has=&lt;bool&gt;" when the read was refused, "other len=N" otherwise. Never the
 * content itself. Result code RESULT_OK tells the probe this receiver really ran.
 */
public class ClipReceiver extends BroadcastReceiver {
    private static final String TAG = "IchthysProbeHelper";
    static final String PREFIX = "IchthysProbeHelper:";
    static final String LABEL = "IchthysProbeHelper";

    @Override
    public void onReceive(Context context, Intent intent) {
        final ClipboardManager cm = context.getSystemService(ClipboardManager.class);
        final String token = intent.getStringExtra("token");
        final String action = String.valueOf(intent.getAction());
        String answer;
        try {
            if (action.endsWith(".COPY")) {
                cm.setPrimaryClip(ClipData.newPlainText(LABEL, PREFIX + token));
                answer = "copied";
            } else if (action.endsWith(".READ")) {
                final boolean has = cm.hasPrimaryClip();
                final ClipData clip = cm.getPrimaryClip();
                if (clip == null || clip.getItemCount() == 0) {
                    answer = "null has=" + has;
                } else {
                    final CharSequence t = clip.getItemAt(0).coerceToText(context);
                    final String s = t == null ? "" : t.toString();
                    answer = token != null && token.equals(s) ? "match" : "other len=" + s.length();
                }
            } else {
                answer = "unknown action";
            }
        } catch (RuntimeException e) {
            answer = "error " + e.getClass().getSimpleName();
        }
        Log.i(TAG, action + " -> " + answer);
        if (isOrderedBroadcast()) {
            setResult(Activity.RESULT_OK, answer, null);
        }
    }
}
