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

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * IchthysOS: the few view pieces the screen is built from, in the IchthysOS dark palette (the
 * system_*_dark colours IchthysOS themes: ink ground, cream text, the accent for actions; see
 * frameworks/base core/res values/ichthys_tokens.xml). Plain framework views, no libraries.
 */
final class Ui {
    final Context c;
    final int ink;
    final int card;
    final int raised;
    final int hairline;
    final int text;
    final int muted;
    final int accent;
    final int onAccent;
    final int danger;
    final int amber = 0xFFF0B35A;
    final int low = 0xFF9DB4CC;
    final int ok = 0xFF7DCB9A;

    final Typeface medium = Typeface.create("sans-serif-medium", Typeface.NORMAL);

    Ui(Context c) {
        this.c = c;
        ink = color(android.R.color.system_background_dark, 0xFF111318);
        card = color(android.R.color.system_surface_container_low_dark, 0xFF1A1C21);
        raised = color(android.R.color.system_surface_container_high_dark, 0xFF282A2F);
        hairline = color(android.R.color.system_outline_variant_dark, 0xFF44474E);
        text = color(android.R.color.system_on_surface_dark, 0xFFE9E2D5);
        muted = color(android.R.color.system_on_surface_variant_dark, 0xFFC4C6CF);
        accent = color(android.R.color.system_primary_dark, 0xFFA8C8FF);
        onAccent = color(android.R.color.system_on_primary_dark, 0xFF07305F);
        danger = color(android.R.color.system_error_dark, 0xFFFFB4AB);
    }

    private int color(int id, int fallback) {
        try {
            return c.getColor(id);
        } catch (RuntimeException e) {
            return fallback;
        }
    }

    int dp(float v) {
        return Math.round(TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v,
                c.getResources().getDisplayMetrics()));
    }

    static int alpha(int color, int a) {
        return Color.argb(a, Color.red(color), Color.green(color), Color.blue(color));
    }

    int severity(Triage.Severity s) {
        if (s == null) {
            return ok;
        }
        switch (s) {
            case HIGH:
                return danger;
            case MEDIUM:
                return amber;
            default:
                return low;
        }
    }

    int verdict(Verdict v) {
        switch (v) {
            case PASS:
                return ok;
            case FAIL:
                return danger;
            case SKIP:
                return hairline;
            default:
                return muted;
        }
    }

    TextView text(CharSequence s, float sp, int color) {
        final TextView t = new TextView(c);
        t.setText(s);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setTextColor(color);
        t.setLineSpacing(0, 1.15f);
        return t;
    }

    TextView title(CharSequence s, float sp, int color) {
        final TextView t = text(s, sp, color);
        t.setTypeface(medium);
        return t;
    }

    TextView mono(CharSequence s) {
        final TextView t = text(s, 12, muted);
        t.setTypeface(Typeface.MONOSPACE);
        t.setTextIsSelectable(true);
        return t;
    }

    LinearLayout vbox() {
        final LinearLayout l = new LinearLayout(c);
        l.setOrientation(LinearLayout.VERTICAL);
        return l;
    }

    LinearLayout hbox() {
        final LinearLayout l = new LinearLayout(c);
        l.setOrientation(LinearLayout.HORIZONTAL);
        l.setGravity(Gravity.CENTER_VERTICAL);
        return l;
    }

    GradientDrawable shape(int fill, int stroke, float radiusDp) {
        final GradientDrawable g = new GradientDrawable();
        g.setColor(fill);
        g.setCornerRadius(dp(radiusDp));
        if (stroke != 0) {
            g.setStroke(dp(1), stroke);
        }
        return g;
    }

    /** A card: filled, hairline-outlined, rounded. */
    LinearLayout card() {
        final LinearLayout l = vbox();
        l.setBackground(shape(card, hairline, 20));
        l.setPadding(dp(16), dp(14), dp(16), dp(14));
        return l;
    }

    Drawable ripple(Drawable content, float radiusDp) {
        return new RippleDrawable(ColorStateList.valueOf(alpha(text, 0x30)), content,
                content == null ? shape(Color.WHITE, 0, radiusDp) : null);
    }

    /** Makes {@code v} tappable with a ripple over its background. */
    void tappable(View v, View.OnClickListener l) {
        final Drawable bg = v.getBackground();
        v.setBackground(ripple(bg, 20));
        v.setClickable(true);
        v.setFocusable(true);
        v.setOnClickListener(l);
    }

    TextView chip(String s, int color) {
        final TextView t = title(s, 11, color);
        t.setAllCaps(true);
        t.setLetterSpacing(0.06f);
        t.setBackground(shape(alpha(color, 0x2E), 0, 10));
        t.setPadding(dp(8), dp(3), dp(8), dp(3));
        return t;
    }

    /** A button: accent-filled (primary) or outlined. */
    TextView button(String s, String desc, boolean primary, View.OnClickListener l) {
        final TextView b = title(s, 14, primary ? onAccent : accent);
        b.setGravity(Gravity.CENTER);
        b.setSingleLine(true);
        b.setEllipsize(TextUtils.TruncateAt.END);
        b.setMinHeight(dp(44));
        b.setPadding(dp(16), dp(8), dp(16), dp(8));
        b.setBackground(ripple(primary ? shape(accent, 0, 22) : shape(Color.TRANSPARENT,
                alpha(accent, 0x80), 22), 22));
        b.setClickable(true);
        b.setFocusable(true);
        if (desc != null) {
            b.setContentDescription(desc);
        }
        b.setOnClickListener(l);
        return b;
    }

    TextView section(String s) {
        final TextView t = title(s, 13, muted);
        t.setAllCaps(true);
        t.setLetterSpacing(0.08f);
        t.setPadding(dp(4), dp(24), 0, dp(8));
        return t;
    }

    View dot(int color) {
        final View v = new View(c);
        final GradientDrawable g = new GradientDrawable();
        g.setShape(GradientDrawable.OVAL);
        g.setColor(color);
        v.setBackground(g);
        final LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(dp(8), dp(8));
        lp.rightMargin = dp(12);
        v.setLayoutParams(lp);
        return v;
    }

    LinearLayout.LayoutParams wide(int topDp) {
        final LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(topDp);
        return lp;
    }

    LinearLayout.LayoutParams weight(int leftDp) {
        final LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        lp.leftMargin = dp(leftDp);
        return lp;
    }

    LinearLayout.LayoutParams wrap(int leftDp) {
        final LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.leftMargin = dp(leftDp);
        return lp;
    }
}
