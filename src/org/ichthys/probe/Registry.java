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

import org.ichthys.probe.probes.AppsProbes;
import org.ichthys.probe.probes.CameraMicProbes;
import org.ichthys.probe.probes.ClipProbes;
import org.ichthys.probe.probes.DisplayProbes;
import org.ichthys.probe.probes.FsProbes;
import org.ichthys.probe.probes.GuardProbes;
import org.ichthys.probe.probes.IchthysProbes;
import org.ichthys.probe.probes.LocationProbes;
import org.ichthys.probe.probes.MediaProbes;
import org.ichthys.probe.probes.NearbyProbes;
import org.ichthys.probe.probes.NetProbes;
import org.ichthys.probe.probes.PersonalProbes;
import org.ichthys.probe.probes.PhoneProbes;
import org.ichthys.probe.probes.SensorProbes;
import org.ichthys.probe.probes.SpoofProbes;
import org.ichthys.probe.probes.SystemProbes;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Every probe, in run order. The clipboard group runs last: its no-tap reads need the activity
 * focused and no recent input, and clip.background_self moves the task to the back.
 */
public final class Registry {
    private static List<Probe> sAll;

    private Registry() {}

    public static synchronized List<Probe> all() {
        if (sAll == null) {
            final List<Probe> l = new ArrayList<>();
            SystemProbes.add(l);
            AppsProbes.add(l);
            FsProbes.add(l);
            DisplayProbes.add(l);
            NetProbes.add(l);
            PhoneProbes.add(l);
            PersonalProbes.add(l);
            LocationProbes.add(l);
            SpoofProbes.add(l);
            SensorProbes.add(l);
            NearbyProbes.add(l);
            CameraMicProbes.add(l);
            MediaProbes.add(l);
            IchthysProbes.add(l);
            GuardProbes.add(l);
            ClipProbes.add(l);
            sAll = Collections.unmodifiableList(l);
        }
        return sAll;
    }

    public static Probe byId(String id) {
        for (Probe p : all()) {
            if (p.id.equals(id)) {
                return p;
            }
        }
        return null;
    }
}
