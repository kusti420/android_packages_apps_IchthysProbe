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

/** How a probe's outcome compares with its IchthysOS expectation. */
public enum Verdict {
    /** The outcome is one the expectation allows (green). */
    PASS("pass"),
    /** An expectation applied and the outcome broke it (red). */
    FAIL("fail"),
    /** No expectation, or it doesn't apply in this state (grey). */
    INFO("info"),
    /** The probe didn't run (needs a tap, helper missing, ...). */
    SKIP("skip");

    public final String key;

    Verdict(String key) {
        this.key = key;
    }
}
