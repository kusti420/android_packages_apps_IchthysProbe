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
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.net.Uri;
import android.provider.Settings;

/**
 * IchthysOS: where a problem is fixed, as a button. Guard pages are tried first with Guard's own
 * extras (GuardActivity.EXTRA_OPEN_PAGE / Intent.EXTRA_PACKAGE_NAME); GuardActivity is not
 * exported, so from a user app that start is refused and the nearest public screen opens instead
 * (this app's App info, whose Guard row opens its Guard page; or Settings, whose Guard row opens
 * Guard), with a toast saying the last steps. {@link #GRANT} and {@link #TAP} are handled by
 * MainActivity; {@link #NONE} means only a code change fixes it (the card offers Share instead).
 */
public enum Fix {
    GUARD_APP("Open in Guard", "Guard › IchthysProbe"),
    SHIELDS("Open Master shields", "Guard › ⚙ › Master shields"),
    FAKE_PLACE("Open Fake place", "Guard › ⚙ › Fake place"),
    TRACKERS("Open Tracker rules", "Guard › ⚙ › Tracker rules"),
    VERIFY("Open Guard Verify", "Guard › Protection › Verify my protection"),
    USAGE_ACCESS("Open Usage access", "Settings › Apps › Special access › Usage access"),
    GRANT("Grant permissions", "the permission prompt"),
    TAP("Run tap test", "this app"),
    NONE("Share details", "the ROM source");

    private static final String SETTINGS = "com.android.settings";
    private static final String GUARD = "com.android.settings.ichthys.guard.ui.GuardActivity";
    /** GuardActivity.EXTRA_OPEN_PAGE and its values. */
    private static final String EXTRA_OPEN_PAGE =
            "com.android.settings.ichthys.guard.extra.OPEN_PAGE";

    public final String label;
    /** Where the control lives, for the card and the fallback toast. */
    public final String path;

    Fix(String label, String path) {
        this.label = label;
        this.path = path;
    }

    /** Whether {@link #open} handles this (not GRANT, TAP or NONE). */
    public boolean opensScreen() {
        return this != GRANT && this != TAP && this != NONE;
    }

    /** Opens the place; returns a hint to show, or null when it landed exactly there. */
    public String open(Activity a) {
        final Intent guard = new Intent().setClassName(SETTINGS, GUARD)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        Intent fallback = new Intent(Settings.ACTION_SETTINGS);
        String hint = "Opened Settings: " + path;
        switch (this) {
            case GUARD_APP:
                guard.putExtra(Intent.EXTRA_PACKAGE_NAME, a.getPackageName());
                fallback = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                        Uri.fromParts("package", a.getPackageName(), null));
                hint = "Opened App info: tap Guard";
                break;
            case SHIELDS:
            case FAKE_PLACE:
            case TRACKERS:
                guard.putExtra(EXTRA_OPEN_PAGE, "gear");
                break;
            case VERIFY:
                guard.putExtra(EXTRA_OPEN_PAGE, "verify");
                break;
            case USAGE_ACCESS:
                return start(a, new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS), null);
            default:
                return null;
        }
        try {
            a.startActivity(guard);
            // Gear sub-pages have no EXTRA_OPEN_PAGE value: Guard lands on the gear page.
            return this == SHIELDS || this == FAKE_PLACE || this == TRACKERS
                    ? "In Guard's gear page: " + path.substring(path.lastIndexOf('›') + 2) : null;
        } catch (SecurityException | ActivityNotFoundException e) {
            // GuardActivity isn't exported: expected from a user app.
            return start(a, fallback, hint);
        }
    }

    private static String start(Activity a, Intent i, String hint) {
        try {
            a.startActivity(i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            return hint;
        } catch (RuntimeException e) {
            return "Couldn't open it: " + Redact.exception(e);
        }
    }
}
