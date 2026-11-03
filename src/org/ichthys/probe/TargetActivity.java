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

import android.app.Activity;
import android.os.Bundle;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * An invisible activity display.launch_scan tries to start on unlisted display ids: it records
 * which display it actually landed on and finishes at once.
 */
public class TargetActivity extends Activity {
    private static volatile CountDownLatch sLanded = new CountDownLatch(1);
    private static volatile int sDisplayId = -1;

    public static void reset() {
        sDisplayId = -1;
        sLanded = new CountDownLatch(1);
    }

    /** The display id it landed on, or -1 when it didn't start within {@code ms}. */
    public static int awaitDisplay(long ms) throws InterruptedException {
        return sLanded.await(ms, TimeUnit.MILLISECONDS) ? sDisplayId : -1;
    }

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        sDisplayId = getDisplay() == null ? -1 : getDisplay().getDisplayId();
        sLanded.countDown();
        finishAndRemoveTask();
    }
}
