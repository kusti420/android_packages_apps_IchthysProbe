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

import static android.Manifest.permission.READ_CALENDAR;
import static android.Manifest.permission.READ_CALL_LOG;
import static android.Manifest.permission.READ_CONTACTS;
import static android.Manifest.permission.READ_SMS;
import static android.Manifest.permission.RECEIVE_MMS;
import static android.Manifest.permission.RECEIVE_WAP_PUSH;
import static android.Manifest.permission.SEND_SMS;
import static android.Manifest.permission.WRITE_CALENDAR;
import static android.Manifest.permission.WRITE_CALL_LOG;
import static android.Manifest.permission.WRITE_CONTACTS;

import static org.ichthys.probe.Probe.perms;

import android.content.ContentResolver;
import android.content.ContentUris;
import android.content.ContentValues;
import android.net.Uri;
import android.provider.CalendarContract;
import android.provider.CallLog;
import android.provider.ContactsContract;
import android.provider.Telephony;

import org.ichthys.probe.Ctx;
import org.ichthys.probe.Expect;
import org.ichthys.probe.Outcome;
import org.ichthys.probe.Probe;
import org.ichthys.probe.Result;
import org.ichthys.probe.Shields;

import java.util.List;
import java.util.TimeZone;

/** Contacts, calendar, call log and SMS: the provider-backed personal data. */
public final class PersonalProbes {
    static final String CONTACTS = "Contacts";
    static final String CALENDAR = "Calendar";
    static final String CALLLOG = "Call log";
    static final String SMS = "SMS & MMS";

    private static final String SRC_CONTACTS =
            "packages/providers/ContactsProvider/src/com/android/providers/contacts/"
                    + "ContactsProvider2.java:6289-6313,6516-6523 (AND 0 / empty MatrixCursor); "
                    + "IchthysShields.CONTACTS";
    private static final String SRC_CONTACTS_WRITE =
            "ContactsProvider2.java:2559-2562 (rejectInsert -> <uri>/0); "
                    + "IchthysShields.CONTACTS_WRITE";
    private static final String SRC_CALENDAR =
            "packages/providers/CalendarProvider/src/com/android/providers/calendar/"
                    + "CalendarProvider2.java:890-925 (AND 0 on every table); "
                    + "IchthysShields.CALENDAR";
    private static final String SRC_CALENDAR_WRITE =
            "CalendarProvider2.java:2348-2420 (rejectInsert); IchthysShields.CALENDAR_WRITE";
    private static final String SRC_CALLLOG =
            "packages/providers/ContactsProvider/src/com/android/providers/contacts/"
                    + "CallLogProvider.java:563-575; IchthysShields.CALL_LOG";
    private static final String SRC_CALLLOG_WRITE =
            "CallLogProvider.java:757-760 (insert -> calls/0); IchthysShields.CALL_LOG_WRITE";
    private static final String SRC_SMS =
            "packages/providers/TelephonyProvider/src/com/android/providers/telephony/"
                    + "IchthysSmsShield.java, SmsProvider.java:249-251,560-565, "
                    + "MmsProvider.java:214-217, MmsSmsProvider.java:414-452; "
                    + "IchthysShields.SMS_READ";

    private PersonalProbes() {}

    /**
     * IchthysOS: a write test only proves something while the write shield protects this app.
     * When it doesn't (run d: the read allow lists lift the write shields too), the test row
     * would really land in the user's contacts, calendar or call log, so it isn't inserted at
     * all. Without the permission the insert still runs, to record the stock refusal.
     */
    private static Result skipIfLifted(Ctx c, String permission,
            Shields.Shield write, Shields.Shield read) {
        if (!c.granted(permission)) {
            return null;
        }
        final String why = Q.writeLifted(c, write, read);
        return why == null ? null
                : Result.skipped("not writing a test row into real data: " + why);
    }

    public static void add(List<Probe> out) {
        // ---- Contacts ----
        out.add(new Probe(CONTACTS, "contacts.rows",
                "How many contacts the address book holds (aggregated contacts).",
                perms(READ_CONTACTS),
                c -> Q.shieldedRows(c, "rows", Q.count(c.app.getContentResolver(),
                        ContactsContract.Contacts.CONTENT_URI,
                        new String[] {ContactsContract.Contacts._ID}, null),
                        Shields.CONTACTS, "contacts"))
                .expect(Q.readShield("Contacts shield",
                        SRC_CONTACTS, "apps holding READ_CONTACTS read an empty address book",
                        READ_CONTACTS, Shields.CONTACTS, "contacts")));

        out.add(new Probe(CONTACTS, "contacts.raw_rows",
                "Raw contacts, one per account, including hidden and deleted-pending rows.",
                perms(READ_CONTACTS),
                c -> Q.shieldedRows(c, "rows", Q.count(c.app.getContentResolver(),
                        ContactsContract.RawContacts.CONTENT_URI,
                        new String[] {ContactsContract.RawContacts._ID}, null),
                        Shields.CONTACTS, "raw_contacts"))
                .expect(Q.readShield("Contacts shield",
                        SRC_CONTACTS, "raw contacts are empty too", READ_CONTACTS,
                        Shields.CONTACTS, "raw_contacts")));

        out.add(new Probe(CONTACTS, "contacts.phones",
                "Phone numbers stored in contacts (count only).",
                perms(READ_CONTACTS),
                c -> Q.shieldedRows(c, "rows", Q.count(c.app.getContentResolver(),
                        ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
                        new String[] {ContactsContract.CommonDataKinds.Phone._ID}, null),
                        Shields.CONTACTS, "phones"))
                .expect(Q.readShield("Contacts shield",
                        SRC_CONTACTS, "contact phone numbers are empty", READ_CONTACTS,
                        Shields.CONTACTS, "phones")));

        out.add(new Probe(CONTACTS, "contacts.groups",
                "Contact groups / labels.",
                perms(READ_CONTACTS),
                c -> Q.shieldedRows(c, "rows", Q.count(c.app.getContentResolver(),
                        ContactsContract.Groups.CONTENT_URI,
                        new String[] {ContactsContract.Groups._ID}, null),
                        Shields.CONTACTS, "groups"))
                .expect(Q.readShield("Contacts shield",
                        SRC_CONTACTS, "groups are empty", READ_CONTACTS, Shields.CONTACTS,
                        "groups")));

        out.add(new Probe(CONTACTS, "contacts.profile",
                "The owner's own profile card (\"Me\"): name, number, photo.",
                perms(READ_CONTACTS),
                c -> Q.shieldedRows(c, "rows", Q.count(c.app.getContentResolver(),
                        ContactsContract.Profile.CONTENT_URI,
                        new String[] {ContactsContract.Profile._ID}, null),
                        Shields.CONTACTS, "profile"))
                .expect(Q.readShield("Contacts shield",
                        SRC_CONTACTS, "the owner profile is empty", READ_CONTACTS,
                        Shields.CONTACTS, "profile")));

        out.add(new Probe(CONTACTS, "contacts.default_account",
                "The default account for new contacts (often the owner's Google e-mail), asked "
                        + "through ContactsContract.Settings rather than read as rows.",
                perms(READ_CONTACTS),
                c -> {
                    final android.accounts.Account a =
                            ContactsContract.Settings.getDefaultAccount(c.app.getContentResolver());
                    return Q.shieldedRows(c, "accounts", a == null ? 0 : 1,
                            Shields.CONTACTS, "default_account");
                })
                .expect(Q.readShield("Contacts shield",
                        SRC_CONTACTS, "no default account is named", READ_CONTACTS,
                        Shields.CONTACTS, "default_account")));

        out.add(new Probe(CONTACTS, "contacts.sim_phonebook",
                "The SIM card's own phonebook (content://icc/adn), a second way to the contacts.",
                perms(READ_CONTACTS),
                c -> Q.shieldedRows(c, "rows", Q.count(c.app.getContentResolver(),
                        Uri.parse("content://icc/adn"), null, null),
                        Shields.CONTACTS, "sim_phonebook"))
                .expect(Q.readShield("Contacts shield",
                        SRC_CONTACTS, "the SIM phonebook is empty", READ_CONTACTS,
                        Shields.CONTACTS, "sim_phonebook")));

        out.add(new Probe(CONTACTS, "contacts.write",
                "Whether a contact the app saves is really stored (test row, deleted again; only "
                        + "while the write shield protects the app).",
                perms(WRITE_CONTACTS),
                c -> {
                    final Result lifted = skipIfLifted(c, WRITE_CONTACTS,
                            Shields.CONTACTS_WRITE, Shields.CONTACTS);
                    if (lifted != null) {
                        return lifted;
                    }
                    final ContentResolver cr = c.app.getContentResolver();
                    final ContentValues v = new ContentValues();
                    v.putNull(ContactsContract.RawContacts.ACCOUNT_NAME);
                    v.putNull(ContactsContract.RawContacts.ACCOUNT_TYPE);
                    final Uri u = cr.insert(ContactsContract.RawContacts.CONTENT_URI, v);
                    final Result r = Q.insertResult(u);
                    if (r.outcome == Outcome.VISIBLE) {
                        final Uri del = u.buildUpon().appendQueryParameter(
                                ContactsContract.CALLER_IS_SYNCADAPTER, "true").build();
                        r.put("cleanup_deleted", cr.delete(del, null, null));
                    }
                    return r;
                })
                .expect(Expect.of("Contacts write shield", SRC_CONTACTS_WRITE,
                        "saving a contact reports success but nothing is saved")
                        .outcomes(Outcome.BLOCKED_ICHTHYS)
                        .when(c -> !c.granted(WRITE_CONTACTS) ? "permission not granted"
                                : Q.writeLifted(c, Shields.CONTACTS_WRITE, Shields.CONTACTS))));

        // ---- Calendar ----
        out.add(new Probe(CALENDAR, "calendar.calendars",
                "Calendar accounts on the phone (count only).",
                perms(READ_CALENDAR),
                c -> Q.shieldedRows(c, "rows", Q.count(c.app.getContentResolver(),
                        CalendarContract.Calendars.CONTENT_URI,
                        new String[] {CalendarContract.Calendars._ID}, null),
                        Shields.CALENDAR, "calendars"))
                .expect(Q.readShield("Calendar shield", SRC_CALENDAR,
                        "apps holding READ_CALENDAR see no calendars", READ_CALENDAR,
                        Shields.CALENDAR, "calendars")));

        out.add(new Probe(CALENDAR, "calendar.events",
                "Calendar events (count only).",
                perms(READ_CALENDAR),
                c -> Q.shieldedRows(c, "rows", Q.count(c.app.getContentResolver(),
                        CalendarContract.Events.CONTENT_URI,
                        new String[] {CalendarContract.Events._ID}, null),
                        Shields.CALENDAR, "events"))
                .expect(Q.readShield("Calendar shield", SRC_CALENDAR,
                        "apps read an empty calendar", READ_CALENDAR, Shields.CALENDAR, "events")));

        out.add(new Probe(CALENDAR, "calendar.instances_30d",
                "Event occurrences in the next 30 days (count only).",
                perms(READ_CALENDAR),
                c -> {
                    final long now = System.currentTimeMillis();
                    final Uri.Builder b = CalendarContract.Instances.CONTENT_URI.buildUpon();
                    android.content.ContentUris.appendId(b, now);
                    android.content.ContentUris.appendId(b, now + 30L * 86_400_000L);
                    return Q.shieldedRows(c, "rows", Q.count(c.app.getContentResolver(),
                            b.build(), new String[] {CalendarContract.Instances._ID}, null),
                            Shields.CALENDAR, "instances_30d");
                })
                .expect(Q.readShield("Calendar shield", SRC_CALENDAR,
                        "upcoming instances are empty", READ_CALENDAR, Shields.CALENDAR,
                        "instances_30d")));

        out.add(new Probe(CALENDAR, "calendar.write",
                "Whether an event the app saves is really stored (test event, deleted again; only "
                        + "while the write shield protects the app).",
                perms(WRITE_CALENDAR),
                c -> {
                    final Result lifted = skipIfLifted(c, WRITE_CALENDAR,
                            Shields.CALENDAR_WRITE, Shields.CALENDAR);
                    if (lifted != null) {
                        return lifted;
                    }
                    final ContentResolver cr = c.app.getContentResolver();
                    final ContentValues v = new ContentValues();
                    final long now = System.currentTimeMillis();
                    v.put(CalendarContract.Events.CALENDAR_ID, 1);
                    v.put(CalendarContract.Events.TITLE, "IchthysProbe test");
                    v.put(CalendarContract.Events.DTSTART, now);
                    v.put(CalendarContract.Events.DTEND, now + 60_000);
                    v.put(CalendarContract.Events.EVENT_TIMEZONE, TimeZone.getDefault().getID());
                    final Uri u;
                    try {
                        u = cr.insert(CalendarContract.Events.CONTENT_URI, v);
                    } catch (IllegalArgumentException e) {
                        return Result.empty().put("insert", "refused: no calendar 1 ("
                                + e.getClass().getSimpleName() + ")");
                    }
                    final Result r = Q.insertResult(u);
                    if (r.outcome == Outcome.VISIBLE) {
                        r.put("cleanup_deleted", cr.delete(u, null, null));
                    }
                    return r;
                })
                .expect(Expect.of("Calendar write shield", SRC_CALENDAR_WRITE,
                        "saving an event reports success but nothing is saved")
                        .outcomes(Outcome.BLOCKED_ICHTHYS)
                        .when(c -> !c.granted(WRITE_CALENDAR) ? "permission not granted"
                                : Q.writeLifted(c, Shields.CALENDAR_WRITE, Shields.CALENDAR))));

        // ---- Call log ----
        out.add(new Probe(CALLLOG, "calllog.rows",
                "Calls made and received (count only).",
                perms(READ_CALL_LOG),
                c -> Q.shieldedRows(c, "rows", Q.count(c.app.getContentResolver(),
                        CallLog.Calls.CONTENT_URI, new String[] {CallLog.Calls._ID}, null),
                        Shields.CALL_LOG, "calllog"))
                .expect(Q.readShield("Call log shield", SRC_CALLLOG,
                        "apps holding READ_CALL_LOG read an empty call log", READ_CALL_LOG,
                        Shields.CALL_LOG, "calllog")));

        out.add(new Probe(CALLLOG, "calllog.write",
                "Whether a call-log entry the app adds is really stored (test row, deleted again; "
                        + "only while the write shield protects the app).",
                perms(WRITE_CALL_LOG),
                c -> {
                    final Result lifted = skipIfLifted(c, WRITE_CALL_LOG,
                            Shields.CALL_LOG_WRITE, Shields.CALL_LOG);
                    if (lifted != null) {
                        return lifted;
                    }
                    final ContentResolver cr = c.app.getContentResolver();
                    final ContentValues v = new ContentValues();
                    v.put(CallLog.Calls.NUMBER, "0000000");
                    v.put(CallLog.Calls.TYPE, CallLog.Calls.INCOMING_TYPE);
                    v.put(CallLog.Calls.DATE, System.currentTimeMillis());
                    v.put(CallLog.Calls.DURATION, 0);
                    v.put(CallLog.Calls.NEW, 0);
                    final Uri u = cr.insert(CallLog.Calls.CONTENT_URI, v);
                    final Result r = Q.insertResult(u);
                    if (r.outcome == Outcome.VISIBLE) {
                        // CallLogProvider refuses deletes on an item URI (calls/<id>), so the
                        // test row goes through a selection on the table instead.
                        r.put("cleanup_deleted", cr.delete(CallLog.Calls.CONTENT_URI,
                                CallLog.Calls._ID + "=?",
                                new String[] {String.valueOf(ContentUris.parseId(u))}));
                    }
                    return r;
                })
                .expect(Q.writeShield("Call log write shield", SRC_CALLLOG_WRITE,
                        "changes to the call log report success but are not saved",
                        WRITE_CALL_LOG, Shields.CALL_LOG_WRITE, Shields.CALL_LOG)));

        // ---- SMS / MMS ----
        out.add(new Probe(SMS, "sms.rows",
                "Text messages in all boxes (count only).",
                perms(READ_SMS),
                c -> Q.shieldedRows(c, "rows", Q.count(c.app.getContentResolver(),
                        Telephony.Sms.CONTENT_URI, new String[] {Telephony.Sms._ID}, null),
                        Shields.SMS_READ, "sms"))
                .expect(Q.readShield("SMS read shield", SRC_SMS,
                        "apps holding READ_SMS read an empty inbox", READ_SMS,
                        Shields.SMS_READ, "sms")));

        out.add(new Probe(SMS, "sms.mms_rows",
                "MMS messages (count only).",
                perms(READ_SMS),
                c -> Q.shieldedRows(c, "rows", Q.count(c.app.getContentResolver(),
                        Telephony.Mms.CONTENT_URI, new String[] {Telephony.Mms._ID}, null),
                        Shields.SMS_READ, "mms"))
                .expect(Q.readShield("SMS read shield", SRC_SMS, "MMS are empty too",
                        READ_SMS, Shields.SMS_READ, "mms")));

        out.add(new Probe(SMS, "sms.conversations",
                "Message threads (count only).",
                perms(READ_SMS),
                c -> Q.shieldedRows(c, "rows", Q.count(c.app.getContentResolver(),
                        Uri.parse("content://mms-sms/conversations?simple=true"),
                        new String[] {"_id"}, null),
                        Shields.SMS_READ, "conversations"))
                .expect(Q.readShield("SMS read shield", SRC_SMS, "threads are empty",
                        READ_SMS, Shields.SMS_READ, "conversations")));

        out.add(new Probe(SMS, "sms.sim_messages",
                "Messages stored on the SIM card (count only).",
                perms(READ_SMS),
                c -> Q.shieldedRows(c, "rows", Q.count(c.app.getContentResolver(),
                        Uri.parse("content://sms/icc"), null, null),
                        Shields.SMS_READ, "sms_icc"))
                .expect(Q.readShield("SMS read shield", SRC_SMS,
                        "SIM messages return an empty cursor", READ_SMS, Shields.SMS_READ,
                        "sms_icc")));

        out.add(new Probe(SMS, "sms.send",
                "Whether the app can send a text without the user confirming it.",
                perms(SEND_SMS),
                c -> Result.skipped("manual: sending a real SMS is never automated; see README"))
                .expect(Expect.of("SMS send shield",
                        "frameworks/opt/telephony/.../SMSDispatcher.java:2270-2274,2609-2676",
                        "every text an app sends needs the user's Allow in a system dialog")
                        .outcomes(Outcome.BLOCKED_ICHTHYS)));

        out.add(new Probe(SMS, "sms.mms_push",
                "Whether the app receives MMS / WAP push broadcasts meant for the SMS app.",
                perms(RECEIVE_MMS, RECEIVE_WAP_PUSH),
                c -> Result.skipped("manual: needs a real incoming MMS; see README"))
                .expect(Expect.of("MMS push shield",
                        "frameworks/opt/telephony/.../InboundSmsHandler.java:1460-1572",
                        "only the SMS app receives MMS and WAP push")
                        .outcomes(Outcome.BLOCKED_ICHTHYS)));
    }
}
