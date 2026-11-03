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

import static android.Manifest.permission.ACCESS_MEDIA_LOCATION;
import static android.Manifest.permission.POST_NOTIFICATIONS;
import static android.Manifest.permission.READ_MEDIA_AUDIO;
import static android.Manifest.permission.READ_MEDIA_IMAGES;
import static android.Manifest.permission.READ_MEDIA_VIDEO;
import static android.Manifest.permission.READ_MEDIA_VISUAL_USER_SELECTED;

import static org.ichthys.probe.Probe.perms;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.ComponentName;
import android.content.ContentUris;
import android.database.Cursor;
import android.health.connect.HealthConnectException;
import android.health.connect.HealthConnectManager;
import android.health.connect.ReadRecordsRequestUsingFilters;
import android.health.connect.ReadRecordsResponse;
import android.health.connect.TimeInstantRangeFilter;
import android.health.connect.datatypes.StepsRecord;
import android.media.AudioManager;
import android.media.ExifInterface;
import android.media.session.MediaController;
import android.media.session.MediaSessionManager;
import android.net.Uri;
import android.os.Environment;
import android.os.OutcomeReceiver;
import android.os.StatFs;
import android.os.storage.StorageManager;
import android.os.storage.StorageVolume;
import android.provider.MediaStore;
import android.service.notification.StatusBarNotification;

import org.ichthys.probe.Ctx;
import org.ichthys.probe.Probe;
import org.ichthys.probe.Redact;
import org.ichthys.probe.Result;

import java.io.File;
import java.io.InputStream;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Photos, videos and audio, shared storage, notifications, media sessions and Health. */
public final class MediaProbes {
    static final String CAT_MEDIA = "Media & storage";
    static final String CAT_NOTIF = "Notifications & media sessions";
    static final String CAT_HEALTH = "Health";

    static final String HEALTH_STEPS = "android.permission.health.READ_STEPS";
    static final String HEALTH_HEART = "android.permission.health.READ_HEART_RATE";

    private MediaProbes() {}

    private static Probe mediaCount(String id, String what, Uri uri, String... perms) {
        return new Probe(CAT_MEDIA, id, what + " in shared storage (count only).", perms,
                c -> {
                    final int n = Q.count(c.app.getContentResolver(), uri,
                            new String[] {MediaStore.MediaColumns._ID}, null);
                    final Result r = Result.count("items", Math.max(n, 0));
                    r.put("full_grant", c.granted(perms[0]));
                    if (perms.length > 1) {
                        r.put("user_selected_grant", c.granted(perms[1]));
                    }
                    return r;
                });
    }

    public static void add(List<Probe> out) {
        out.add(mediaCount("media.images", "Photos",
                MediaStore.Images.Media.EXTERNAL_CONTENT_URI, READ_MEDIA_IMAGES,
                READ_MEDIA_VISUAL_USER_SELECTED));
        out.add(mediaCount("media.video", "Videos",
                MediaStore.Video.Media.EXTERNAL_CONTENT_URI, READ_MEDIA_VIDEO,
                READ_MEDIA_VISUAL_USER_SELECTED));
        out.add(mediaCount("media.audio", "Audio files",
                MediaStore.Audio.Media.EXTERNAL_CONTENT_URI, READ_MEDIA_AUDIO));
        out.add(new Probe(CAT_MEDIA, "media.downloads",
                "Files in Downloads (an app sees only its own without broader access).",
                Probe.NONE,
                c -> Result.count("items", Math.max(0, Q.count(c.app.getContentResolver(),
                        MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                        new String[] {MediaStore.MediaColumns._ID}, null)))));

        out.add(new Probe(CAT_MEDIA, "media.photo_locations",
                "How many of the newest 20 photos carry GPS coordinates in EXIF (count only).",
                perms(READ_MEDIA_IMAGES, ACCESS_MEDIA_LOCATION),
                c -> {
                    int checked = 0;
                    int withGps = 0;
                    try (Cursor cur = c.app.getContentResolver().query(
                            MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
                            new String[] {MediaStore.Images.Media._ID}, null, null,
                            MediaStore.Images.Media.DATE_ADDED + " DESC")) {
                        while (cur != null && cur.moveToNext() && checked < 20) {
                            Uri u = ContentUris.withAppendedId(
                                    MediaStore.Images.Media.EXTERNAL_CONTENT_URI, cur.getLong(0));
                            if (c.granted(ACCESS_MEDIA_LOCATION)) {
                                u = MediaStore.setRequireOriginal(u);
                            }
                            try (InputStream in = c.app.getContentResolver().openInputStream(u)) {
                                if (in == null) {
                                    continue;
                                }
                                checked++;
                                final float[] ll = new float[2];
                                if (new ExifInterface(in).getLatLong(ll)) {
                                    withGps++;
                                }
                            } catch (Exception e) {
                                // Unreadable item: skip.
                            }
                        }
                    }
                    if (checked == 0) {
                        return Result.empty().put("checked", 0);
                    }
                    return Result.visible().put("checked", checked).put("with_gps", withGps)
                            .put("media_location_grant", c.granted(ACCESS_MEDIA_LOCATION));
                })
                .timeout(15_000));

        out.add(new Probe(CAT_MEDIA, "storage.shared_root",
                "Top-level entries of shared storage (/sdcard) the app can list.",
                Probe.NONE,
                c -> {
                    final File root = Environment.getExternalStorageDirectory();
                    final String[] names = root.list();
                    if (names == null) {
                        return Result.blockedPermission("list() returned null");
                    }
                    return Result.count("entries", names.length)
                            .put("manager", Environment.isExternalStorageManager());
                }));

        out.add(new Probe(CAT_MEDIA, "storage.other_app_dirs",
                "Other apps' folders under /sdcard/Android/data and /sdcard/Android/obb.",
                Probe.NONE,
                c -> {
                    final File base = new File(Environment.getExternalStorageDirectory(),
                            "Android");
                    final String[] data = new File(base, "data").list();
                    final String[] obb = new File(base, "obb").list();
                    final int dataOthers = data == null ? -1 : data.length
                            - (contains(data, c.app.getPackageName()) ? 1 : 0);
                    final int obbOthers = obb == null ? -1 : obb.length
                            - (contains(obb, c.app.getPackageName()) ? 1 : 0);
                    if (dataOthers <= 0 && obbOthers <= 0) {
                        return Result.blockedPermission("only own folders are visible")
                                .put("data_others", dataOthers).put("obb_others", obbOthers);
                    }
                    return Result.visible().put("data_others", dataOthers)
                            .put("obb_others", obbOthers);
                }));

        out.add(new Probe(CAT_MEDIA, "storage.stats",
                "Internal storage size and free space, storage volumes (coarse).",
                Probe.NONE,
                c -> {
                    final StatFs data = new StatFs(Environment.getDataDirectory().getPath());
                    final StorageManager sm = c.app.getSystemService(StorageManager.class);
                    final List<StorageVolume> vols = sm.getStorageVolumes();
                    int removable = 0;
                    for (StorageVolume v : vols) {
                        if (v.isRemovable()) {
                            removable++;
                        }
                    }
                    return Result.visible().put("data_total", Redact.bytes(data.getTotalBytes()))
                            .put("data_free", Redact.bytes(data.getAvailableBytes()))
                            .put("volumes", vols.size()).put("removable", removable);
                }));

        // ---- Notifications & media sessions ----
        out.add(new Probe(CAT_NOTIF, "notif.post",
                "Whether the app may post notifications (posts a silent one and removes it).",
                perms(POST_NOTIFICATIONS),
                c -> {
                    final NotificationManager nm =
                            c.app.getSystemService(NotificationManager.class);
                    if (!nm.areNotificationsEnabled()) {
                        return Result.blockedPermission("notifications disabled for the app");
                    }
                    nm.createNotificationChannel(new NotificationChannel("probe", "Probe",
                            NotificationManager.IMPORTANCE_MIN));
                    nm.notify(42, new Notification.Builder(c.app, "probe")
                            .setSmallIcon(android.R.drawable.stat_notify_more)
                            .setContentTitle("IchthysProbe").setTimeoutAfter(2000).build());
                    Ctx.sleep(300);
                    final StatusBarNotification[] own = nm.getActiveNotifications();
                    nm.cancel(42);
                    return Result.visible().put("posted", own.length > 0);
                }));

        out.add(new Probe(CAT_NOTIF, "notif.listener_access",
                "Whether the app can read other apps' notifications (listener access).",
                Probe.NONE,
                c -> {
                    final NotificationManager nm =
                            c.app.getSystemService(NotificationManager.class);
                    final boolean granted = nm.isNotificationListenerAccessGranted(
                            new ComponentName(c.app, "org.ichthys.probe.NoSuchListener"));
                    return granted ? Result.visible().put("listener_access", true)
                            : Result.blockedPermission("no notification listener access");
                }));

        out.add(new Probe(CAT_NOTIF, "media.sessions",
                "Now playing in other apps (active media sessions).",
                Probe.NONE,
                c -> {
                    final MediaSessionManager msm =
                            c.app.getSystemService(MediaSessionManager.class);
                    final List<MediaController> s = msm.getActiveSessions(null);
                    return Result.count("sessions", s.size());
                }));

        out.add(new Probe(CAT_NOTIF, "media.audio_state",
                "Whether music is playing, ringer mode and volume levels (no permission).",
                Probe.NONE,
                c -> {
                    final AudioManager am = c.app.getSystemService(AudioManager.class);
                    return Result.visible().put("music_active", am.isMusicActive())
                            .put("ringer_mode", am.getRingerMode())
                            .put("mode", am.getMode())
                            .put("media_volume", am.getStreamVolume(AudioManager.STREAM_MUSIC)
                                    + "/" + am.getStreamMaxVolume(AudioManager.STREAM_MUSIC))
                            .put("outputs", am.getDevices(AudioManager.GET_DEVICES_OUTPUTS).length);
                }));

        // ---- Health ----
        out.add(new Probe(CAT_HEALTH, "health.steps_7d",
                "Step records in Health Connect for the last 7 days (record count only).",
                perms(HEALTH_STEPS),
                c -> {
                    final HealthConnectManager hcm =
                            c.app.getSystemService(HealthConnectManager.class);
                    if (hcm == null) {
                        return Result.unavailable("no Health Connect");
                    }
                    final Instant now = Instant.now();
                    final ReadRecordsRequestUsingFilters<StepsRecord> req =
                            new ReadRecordsRequestUsingFilters.Builder<>(StepsRecord.class)
                                    .setTimeRangeFilter(new TimeInstantRangeFilter.Builder()
                                            .setStartTime(now.minus(7, ChronoUnit.DAYS))
                                            .setEndTime(now).build())
                                    .build();
                    final AtomicReference<Object> res = new AtomicReference<>();
                    final CountDownLatch done = new CountDownLatch(1);
                    hcm.readRecords(req, c.app.getMainExecutor(),
                            new OutcomeReceiver<ReadRecordsResponse<StepsRecord>,
                                    HealthConnectException>() {
                                @Override
                                public void onResult(ReadRecordsResponse<StepsRecord> r) {
                                    res.set(r.getRecords().size());
                                    done.countDown();
                                }

                                @Override
                                public void onError(HealthConnectException e) {
                                    res.set(e);
                                    done.countDown();
                                }
                            });
                    if (!done.await(8, TimeUnit.SECONDS)) {
                        return Result.of(org.ichthys.probe.Outcome.ERROR).put("error", "timeout");
                    }
                    final Object o = res.get();
                    if (o instanceof HealthConnectException) {
                        final HealthConnectException e = (HealthConnectException) o;
                        return e.getErrorCode() == HealthConnectException.ERROR_SECURITY
                                ? Result.blockedPermission(Redact.exception(e))
                                : Result.error(e);
                    }
                    return Result.count("records", (Integer) o);
                })
                .timeout(12_000));

        out.add(new Probe(CAT_HEALTH, "health.heart_rate_grant",
                "Whether the app holds the Health Connect heart-rate read grant.",
                perms(HEALTH_HEART),
                c -> c.granted(HEALTH_HEART) ? Result.visible().put("granted", true)
                        : Result.blockedPermission("not granted")));
    }

    private static boolean contains(String[] a, String s) {
        for (String x : a) {
            if (x.equals(s)) {
                return true;
            }
        }
        return false;
    }
}
