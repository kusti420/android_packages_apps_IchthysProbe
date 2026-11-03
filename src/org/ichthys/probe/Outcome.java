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

/** What a probe observed. The JSON report uses {@link #key}. */
public enum Outcome {
    /** Real data came back (redacted in the report). */
    VISIBLE("visible"),
    /** The call worked but returned nothing: no rows, no fix, null, an empty list. */
    EMPTY("empty"),
    /** Refused by the stock Android permission model (SecurityException, denied grant). */
    BLOCKED_PERMISSION("blocked-by-permission"),
    /** Refused or emptied by an IchthysOS feature (known signal: shield, quarantine, lockdown). */
    BLOCKED_ICHTHYS("blocked-by-IchthysOS"),
    /** The hardware, service or API isn't there on this device. */
    UNAVAILABLE("unavailable"),
    /** Not run: needs a user tap, a helper app, or a precondition that isn't met. */
    SKIPPED("skipped"),
    /** The probe itself failed (unexpected exception, timeout). */
    ERROR("error");

    public final String key;

    Outcome(String key) {
        this.key = key;
    }
}
