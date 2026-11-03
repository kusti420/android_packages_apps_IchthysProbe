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

import static android.Manifest.permission.CAMERA;
import static android.Manifest.permission.RECORD_AUDIO;

import static org.ichthys.probe.Probe.perms;

import android.annotation.SuppressLint;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.media.AudioFormat;
import android.media.AudioRecord;
import android.media.MediaRecorder;

import org.ichthys.probe.Outcome;
import org.ichthys.probe.Probe;
import org.ichthys.probe.Redact;
import org.ichthys.probe.Result;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Camera and microphone. Nothing is stored: frames are never requested, audio is measured. */
@SuppressLint("MissingPermission")
public final class CameraMicProbes {
    static final String CAT = "Camera & microphone";

    private CameraMicProbes() {}

    public static void add(List<Probe> out) {
        out.add(new Probe(CAT, "camera.list",
                "Camera count, facing and hardware level (no permission needed).",
                Probe.NONE,
                c -> {
                    final CameraManager cm = c.app.getSystemService(CameraManager.class);
                    final String[] ids = cm.getCameraIdList();
                    int front = 0;
                    int back = 0;
                    int ext = 0;
                    for (String id : ids) {
                        final Integer f = cm.getCameraCharacteristics(id)
                                .get(CameraCharacteristics.LENS_FACING);
                        if (f == null) {
                            continue;
                        }
                        if (f == CameraCharacteristics.LENS_FACING_FRONT) {
                            front++;
                        } else if (f == CameraCharacteristics.LENS_FACING_BACK) {
                            back++;
                        } else {
                            ext++;
                        }
                    }
                    return Result.count("cameras", ids.length).put("front", front)
                            .put("back", back).put("external", ext);
                }));

        out.add(new Probe(CAT, "camera.open",
                "Whether the app can open the camera (opened and closed at once, no frames).",
                perms(CAMERA),
                c -> {
                    final CameraManager cm = c.app.getSystemService(CameraManager.class);
                    final String[] ids = cm.getCameraIdList();
                    if (ids.length == 0) {
                        return Result.unavailable("no camera");
                    }
                    final AtomicReference<String> state = new AtomicReference<>("timeout");
                    final CountDownLatch done = new CountDownLatch(1);
                    try {
                        cm.openCamera(ids[0], new CameraDevice.StateCallback() {
                            @Override
                            public void onOpened(CameraDevice d) {
                                state.set("opened");
                                d.close();
                                done.countDown();
                            }

                            @Override
                            public void onDisconnected(CameraDevice d) {
                                state.set("disconnected");
                                d.close();
                                done.countDown();
                            }

                            @Override
                            public void onError(CameraDevice d, int error) {
                                state.set("error " + error);
                                d.close();
                                done.countDown();
                            }
                        }, c.worker);
                    } catch (CameraAccessException e) {
                        return e.getReason() == CameraAccessException.CAMERA_DISABLED
                                ? Result.blockedPermission("camera disabled (policy/privacy "
                                        + "toggle)")
                                : Result.error(e);
                    }
                    done.await(5, TimeUnit.SECONDS);
                    final String s = state.get();
                    if ("opened".equals(s)) {
                        return Result.visible().put("camera", "opened");
                    }
                    return Result.of(s.startsWith("error") ? Outcome.BLOCKED_PERMISSION
                            : Outcome.ERROR).put("camera", s);
                })
                .timeout(8000));

        out.add(new Probe(CAT, "mic.record",
                "Whether the microphone delivers real sound in 0.6 s (level only, nothing kept).",
                perms(RECORD_AUDIO),
                c -> {
                    final int rate = 16000;
                    final int min = AudioRecord.getMinBufferSize(rate,
                            AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT);
                    final AudioRecord ar = new AudioRecord(MediaRecorder.AudioSource.MIC, rate,
                            AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT,
                            Math.max(min, rate));
                    try {
                        if (ar.getState() != AudioRecord.STATE_INITIALIZED) {
                            return Result.blockedPermission("AudioRecord not initialized");
                        }
                        ar.startRecording();
                        final short[] buf = new short[rate * 6 / 10];
                        int read = 0;
                        while (read < buf.length) {
                            final int n = ar.read(buf, read, buf.length - read);
                            if (n <= 0) {
                                break;
                            }
                            read += n;
                        }
                        ar.stop();
                        int peak = 0;
                        for (int i = 0; i < read; i++) {
                            peak = Math.max(peak, Math.abs((int) buf[i]));
                        }
                        if (read == 0 || peak == 0) {
                            return Result.empty().put("samples", read)
                                    .put("note", "all-zero audio: mic privacy toggle or silenced");
                        }
                        return Result.visible().put("samples", read)
                                .put("peak_level", Redact.bucket(peak));
                    } finally {
                        ar.release();
                    }
                })
                .timeout(6000));
    }
}
