#!/usr/bin/env python3
"""Codegen: build ``src/dexllm/data/android_api_map.json`` — the L3 capability catalog.

Issue #30. The catalog was 50 hand-written entries against ``perm_api.json``'s
5,150, and the obvious repair — project every ``@RequiresPermission`` member into
it — was MEASURED and rejected:

=====================================  =======  =======  =========  ==================
candidate                              entries  file     lookup     tvleanback matches
=====================================  =======  =======  =========  ==================
the 0.3 hand seed                           50   12 KB    0.22 ms                   10
every ``@RequiresPermission`` member     3,533  655 KB    9.00 ms                   32
=====================================  =======  =======  =========  ==================

Cost is linear in the entry count (~2.5 µs each, median of 20 warm calls) and did
not decide it: even the full projection costs 9 ms against a ~150 ms APK load, and
its 655 KB is smaller than the ``perm_api.json`` already shipped. SIGNAL is: the
APIs the full projection adds are, in corpus-frequency order,
``Context.startActivity`` (16 of the 32 loadable sources), ``ContentResolver.query``
(16), ``startActivityForResult`` (16), ``bindService`` (10), ``sendBroadcast`` (7) —
present in essentially every app, so a report whose top rows are ``startActivity``
is *worse* than 50 curated entries. Nor is the protection
level the missing filter: ``dangerous``-only drops ``TelephonyManager.getImei`` and
``PackageManager.setComponentEnabledSetting`` (both ``signature``), and
``normal``+``dangerous`` empties ``PackageManager`` / ``AlarmManager`` /
``ClipboardManager`` / ``UsageStatsManager`` entirely. No mechanical rule selects
"capability-relevant" — that judgement IS the file's content, and the permission
surface is already answered by ``dangerous_permission_apis`` over all 5,150.

So the split is: **the selection is curated, everything mechanical is derived.**
``CURATED`` below names a Java class and a MEMBER NAME — never a Dalvik descriptor —
and this script

1. **resolves** each name against the AOSP member catalog and EXPANDS it to every
   overload, so ``Runtime#exec`` yields all six forms. Forgetting an overload is the
   hole that let the 0.3 catalog carry ``getDeviceId()`` and ``getDeviceId(int)``
   while never seeing ``getImei``;
2. **verifies** it exists at all. A hand-typed descriptor that names nothing matches
   nothing and raises nothing — the exact defect dexllm#36 found (three field keys
   shipped dead for three months). An unresolvable name is a hard error here, so
   that class of bug cannot reach the catalog;
3. **fills the permissions** from the bundled ``perm_api.json``, i.e. the same AOSP
   data ``dangerous_permission_apis`` joins against, so the two APIs cannot disagree
   about what a permission-carrying API is. A permission is never hand-typed.

**A curated class is the class the APP NAMES, not the one AOSP declares.** A dex
``method_id`` records the STATIC RECEIVER type, so a real APK carries
``Ljava/lang/reflect/Method;->setAccessible(Z)V`` — measured across the corpus,
alongside the ``Field`` and ``Constructor`` forms, and never
``AccessibleObject``, which is where AOSP declares it. Resolution therefore walks
``extends``/``implements`` and emits the descriptor under the CURATED class. Curating
the declaring class instead would produce an entry no APK can match.

**The same rule puts a whole class of API out of reach of this catalog, and that
is why ACCESSIBILITY is absent.** When the app SUBCLASSES a framework class, its
own ``this.m()`` is compiled against the SUBCLASS: a2dp.Vol's
``NotificationCatcher extends NotificationListenerService`` records
``La2dp/Vol/NotificationCatcher;->registerReceiver(…)``, never the framework
spelling. So ``AccessibilityService#getRootInActiveWindow`` /
``performGlobalAction`` / ``dispatchGesture`` and
``NotificationListenerService#getActiveNotifications`` — the accessibility-abuse
and notification-reading surfaces — cannot be expressed as ``find_call_sites_to``
keys at all; they are a question about a class's SUPERCLASS, which
``find_classes_by_super`` answers and this catalog does not. A first cut shipped
them anyway: real AOSP members, resolvable, and dead in every possible APK. What
was left of ACCESSIBILITY was ``AccessibilityNodeInfo`` / ``AccessibilityManager``,
whose callers are **100% support-library internals** on the corpus (measured over
32 sources, 72/72 touches) — a detector for bundling androidx, so the category
went with them rather than shipping as a false positive.

Requires a checkout of https://github.com/mobile-threat-hunter/aosp_data_set
(``aosp_members.csv`` + ``aosp_classes.csv``). Regenerate after editing ``CURATED``:

    python scripts/gen_capability_catalog.py /path/to/aosp_data_set
    python scripts/gen_capability_catalog.py          # or set $DEXLLM_AOSP_DATASET

The output is committed, so neither the build nor CI needs the dataset;
``tests/test_capability_catalog.py`` re-runs this script when the dataset IS present
and asserts the committed file is byte-identical, which is what keeps the two from
drifting.
"""

from __future__ import annotations

import collections
import csv
import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "src" / "dexllm" / "data" / "android_api_map.json"
PERM_API = ROOT / "src" / "dexllm" / "data" / "perm_api.json"
PERM_LEVELS = ROOT / "src" / "dexllm" / "data" / "perm_levels.json"

# Protection levels a third-party app can actually be granted.
APP_HOLDABLE = {"normal", "dangerous"}

VERSION = "0.4"
SOURCE = (
    "curated selection (2026-05-25, taxonomy normalised 2026-08-12, field keys "
    "2026-08-16, behaviour surfaces 2026-08-16); descriptors, overloads and "
    "permissions derived from aosp_data_set by scripts/gen_capability_catalog.py"
)

# The closed vocabularies. `categories` is ONE axis: no tag may be implied by
# another, so a call site is never counted twice under two names for the same
# concern. `flags` is the orthogonal axis for what a domain tag cannot express.
CATEGORY_VOCABULARY = [
    # domains
    "ACCOUNTS",
    "BLUETOOTH",
    "CALENDAR",
    "CALL_LOG",
    "CAMERA",
    "CONTACTS",
    "LOCATION",
    "MICROPHONE",
    "NETWORK_IO",
    "PACKAGE_INFO",
    "SETTINGS",
    "SMS",
    "STORAGE",
    "TELEPHONY",
    "WEBVIEW",
    "WIFI",
    # behaviours
    "BIOMETRIC",
    "CLIPBOARD",
    "CRYPTO",
    "DEVICE_ADMIN",
    "DYNAMIC_LOAD",
    "KEYSTORE",
    "NATIVE_CODE",
    "NOTIFICATIONS",
    "PACKAGE_INSTALL",
    "PROCESS_EXEC",
    "REFLECTION",
    "SCHEDULING",
    "SCREEN_CAPTURE",
    "USAGE_STATS",
]
FLAG_VOCABULARY = ["IDENTIFIER"]

# (java class the APP names, member name, categories, flags).
#
# Every entry is a judgement that a call site is worth telling an analyst about.
# The standing exclusion is UBIQUITY: an API essentially every app calls carries no
# information, so `Context.startActivity`, `sendBroadcast`, `bindService`,
# `ContentResolver.query`, `PackageManager.getPackageInfo`, `NotificationManager.notify`
# and `Field.get`/`set` are deliberately absent even though several of them carry a
# permission. `tests/test_capability_catalog.py` pins that decision.
CURATED: list[tuple[str, str, list[str], list[str]]] = [
    # --- ACCOUNTS ---------------------------------------------------------
    ("android.accounts.AccountManager", "getAccounts", ["ACCOUNTS"], []),
    ("android.accounts.AccountManager", "getAccountsByType", ["ACCOUNTS"], []),
    # --- BLUETOOTH --------------------------------------------------------
    # getAddress is the device's own MAC; the flag is the fact the domain tag
    # cannot express, and the key already states WHICH identifier.
    ("android.bluetooth.BluetoothAdapter", "getAddress", ["BLUETOOTH"], ["IDENTIFIER"]),
    ("android.bluetooth.BluetoothAdapter", "getDefaultAdapter", ["BLUETOOTH"], []),
    ("android.bluetooth.BluetoothAdapter", "getBondedDevices", ["BLUETOOTH"], []),
    ("android.bluetooth.BluetoothAdapter", "getName", ["BLUETOOTH"], []),
    ("android.bluetooth.BluetoothAdapter", "startDiscovery", ["BLUETOOTH"], []),
    ("android.bluetooth.BluetoothDevice", "getAddress", ["BLUETOOTH"], ["IDENTIFIER"]),
    ("android.bluetooth.BluetoothDevice", "getName", ["BLUETOOTH"], []),
    (
        "android.bluetooth.BluetoothDevice",
        "createRfcommSocketToServiceRecord",
        ["BLUETOOTH", "NETWORK_IO"],
        [],
    ),
    # --- CAMERA / MICROPHONE ---------------------------------------------
    ("android.hardware.Camera", "open", ["CAMERA"], []),
    ("android.hardware.camera2.CameraManager", "openCamera", ["CAMERA"], []),
    ("android.media.AudioRecord", "<init>", ["MICROPHONE"], []),
    ("android.media.AudioRecord", "startRecording", ["MICROPHONE"], []),
    ("android.media.MediaRecorder", "setAudioSource", ["MICROPHONE"], []),
    # --- LOCATION ---------------------------------------------------------
    ("android.location.LocationManager", "getLastKnownLocation", ["LOCATION"], []),
    ("android.location.LocationManager", "getProviders", ["LOCATION"], []),
    ("android.location.LocationManager", "requestLocationUpdates", ["LOCATION"], []),
    ("android.location.LocationManager", "requestSingleUpdate", ["LOCATION"], []),
    (
        "android.location.LocationManager",
        "registerGnssStatusCallback",
        ["LOCATION"],
        [],
    ),
    # --- WIFI -------------------------------------------------------------
    ("android.net.wifi.WifiManager", "getConnectionInfo", ["WIFI"], []),
    # The scan result set is a location oracle in its own right, which is why it
    # carries ACCESS_FINE_LOCATION — two genuine domains, counted once in each.
    ("android.net.wifi.WifiManager", "getScanResults", ["WIFI", "LOCATION"], []),
    ("android.net.wifi.WifiManager", "getConfiguredNetworks", ["WIFI"], []),
    ("android.net.wifi.WifiManager", "startScan", ["WIFI"], []),
    ("android.net.wifi.WifiInfo", "getMacAddress", ["WIFI"], ["IDENTIFIER"]),
    ("android.net.wifi.WifiInfo", "getBSSID", ["WIFI"], []),
    ("android.net.wifi.WifiInfo", "getSSID", ["WIFI"], []),
    # --- TELEPHONY --------------------------------------------------------
    (
        "android.telephony.TelephonyManager",
        "getDeviceId",
        ["TELEPHONY"],
        ["IDENTIFIER"],
    ),
    ("android.telephony.TelephonyManager", "getImei", ["TELEPHONY"], ["IDENTIFIER"]),
    ("android.telephony.TelephonyManager", "getMeid", ["TELEPHONY"], ["IDENTIFIER"]),
    (
        "android.telephony.TelephonyManager",
        "getSimSerialNumber",
        ["TELEPHONY"],
        ["IDENTIFIER"],
    ),
    (
        "android.telephony.TelephonyManager",
        "getSubscriberId",
        ["TELEPHONY"],
        ["IDENTIFIER"],
    ),
    (
        "android.telephony.TelephonyManager",
        "getLine1Number",
        ["TELEPHONY"],
        ["IDENTIFIER"],
    ),
    ("android.telephony.TelephonyManager", "getNetworkOperator", ["TELEPHONY"], []),
    ("android.telephony.TelephonyManager", "getNetworkOperatorName", ["TELEPHONY"], []),
    ("android.telephony.TelephonyManager", "getSimOperator", ["TELEPHONY"], []),
    ("android.telephony.TelephonyManager", "getSimCountryIso", ["TELEPHONY"], []),
    # Cell identity is a location oracle, like the Wi-Fi scan above.
    (
        "android.telephony.TelephonyManager",
        "getCellLocation",
        ["TELEPHONY", "LOCATION"],
        [],
    ),
    (
        "android.telephony.TelephonyManager",
        "getAllCellInfo",
        ["TELEPHONY", "LOCATION"],
        [],
    ),
    ("android.telephony.TelephonyManager", "listen", ["TELEPHONY"], []),
    (
        "android.telephony.TelephonyManager",
        "registerTelephonyCallback",
        ["TELEPHONY"],
        [],
    ),
    # --- SMS --------------------------------------------------------------
    ("android.telephony.SmsManager", "getDefault", ["SMS"], []),
    ("android.telephony.SmsManager", "getSmsManagerForSubscriptionId", ["SMS"], []),
    ("android.telephony.SmsManager", "sendTextMessage", ["SMS"], []),
    ("android.telephony.SmsManager", "sendMultipartTextMessage", ["SMS"], []),
    ("android.telephony.SmsManager", "sendDataMessage", ["SMS"], []),
    # A provider is reached by READING a CONTENT_URI constant, so these are field
    # keys — no method call expresses them (dexllm#36).
    ("android.provider.Telephony.Sms", "CONTENT_URI", ["SMS"], []),
    ("android.provider.Telephony.Sms.Inbox", "CONTENT_URI", ["SMS"], []),
    ("android.provider.Telephony.Mms", "CONTENT_URI", ["SMS"], []),
    # --- CONTACTS / CALL_LOG / CALENDAR ----------------------------------
    ("android.provider.ContactsContract.Contacts", "CONTENT_URI", ["CONTACTS"], []),
    ("android.provider.ContactsContract.RawContacts", "CONTENT_URI", ["CONTACTS"], []),
    ("android.provider.ContactsContract.Data", "CONTENT_URI", ["CONTACTS"], []),
    (
        "android.provider.ContactsContract.PhoneLookup",
        "CONTENT_FILTER_URI",
        ["CONTACTS"],
        [],
    ),
    (
        "android.provider.ContactsContract.CommonDataKinds.Phone",
        "CONTENT_URI",
        ["CONTACTS"],
        [],
    ),
    (
        "android.provider.ContactsContract.CommonDataKinds.Email",
        "CONTENT_URI",
        ["CONTACTS"],
        [],
    ),
    ("android.provider.CallLog.Calls", "CONTENT_URI", ["CALL_LOG"], []),
    ("android.provider.CallLog.Calls", "CONTENT_URI_WITH_VOICEMAIL", ["CALL_LOG"], []),
    ("android.provider.CalendarContract.Events", "CONTENT_URI", ["CALENDAR"], []),
    # --- SETTINGS ---------------------------------------------------------
    # The ANDROID_ID read is `Settings$Secure.getString(cr, "android_id")`. WHICH
    # setting is an argument, which `resolve_call_args` answers properly, so the
    # entry is the read and there is no IDENTIFIER flag to assert here.
    ("android.provider.Settings.Secure", "getString", ["SETTINGS"], []),
    ("android.provider.Settings.Global", "getString", ["SETTINGS"], []),
    ("android.provider.Settings.System", "getString", ["SETTINGS"], []),
    # --- PACKAGE_INFO / PACKAGE_INSTALL ----------------------------------
    ("android.content.pm.PackageManager", "getInstalledPackages", ["PACKAGE_INFO"], []),
    (
        "android.content.pm.PackageManager",
        "getInstalledApplications",
        ["PACKAGE_INFO"],
        [],
    ),
    ("android.content.pm.PackageManager", "getPackagesForUid", ["PACKAGE_INFO"], []),
    ("android.content.pm.PackageInstaller", "createSession", ["PACKAGE_INSTALL"], []),
    ("android.content.pm.PackageInstaller", "openSession", ["PACKAGE_INSTALL"], []),
    ("android.content.pm.PackageInstaller", "uninstall", ["PACKAGE_INSTALL"], []),
    ("android.content.pm.PackageInstaller.Session", "commit", ["PACKAGE_INSTALL"], []),
    (
        "android.content.pm.PackageInstaller.Session",
        "openWrite",
        ["PACKAGE_INSTALL"],
        [],
    ),
    # --- STORAGE ----------------------------------------------------------
    ("android.content.Context", "getExternalFilesDir", ["STORAGE"], []),
    ("android.content.Context", "getExternalCacheDir", ["STORAGE"], []),
    ("android.os.Environment", "getExternalStorageDirectory", ["STORAGE"], []),
    ("android.os.Environment", "getExternalStoragePublicDirectory", ["STORAGE"], []),
    # --- CLIPBOARD --------------------------------------------------------
    # Both receiver spellings: `android.content.ClipboardManager` extends the
    # deprecated `android.text.ClipboardManager`, and an app writes either.
    ("android.content.ClipboardManager", "getPrimaryClip", ["CLIPBOARD"], []),
    (
        "android.content.ClipboardManager",
        "getPrimaryClipDescription",
        ["CLIPBOARD"],
        [],
    ),
    ("android.content.ClipboardManager", "hasPrimaryClip", ["CLIPBOARD"], []),
    ("android.content.ClipboardManager", "setPrimaryClip", ["CLIPBOARD"], []),
    (
        "android.content.ClipboardManager",
        "addPrimaryClipChangedListener",
        ["CLIPBOARD"],
        [],
    ),
    ("android.content.ClipboardManager", "getText", ["CLIPBOARD"], []),
    ("android.text.ClipboardManager", "getText", ["CLIPBOARD"], []),
    ("android.text.ClipboardManager", "setText", ["CLIPBOARD"], []),
    # --- ACCESSIBILITY: deliberately ABSENT, see the note below ------------
    # --- NOTIFICATIONS ----------------------------------------------------
    # Posting a notification is what every app does; READING everyone else's is
    # the capability. `NotificationManager` is obtained from `getSystemService`,
    # so a call to it is recorded under `NotificationManager` — unlike
    # `NotificationListenerService`, which an app SUBCLASSES (see the note below).
    (
        "android.app.NotificationManager",
        "getActiveNotifications",
        ["NOTIFICATIONS"],
        [],
    ),
    (
        "android.app.NotificationManager",
        "isNotificationListenerAccessGranted",
        ["NOTIFICATIONS"],
        [],
    ),
    # --- SCHEDULING -------------------------------------------------------
    # Persistence across reboot / doze is what makes a background payload durable.
    # androidx.work.WorkManager is a library, not framework: it is absent from the
    # AOSP catalog (so unverifiable here) and reaches JobScheduler anyway.
    ("android.app.AlarmManager", "set", ["SCHEDULING"], []),
    ("android.app.AlarmManager", "setExact", ["SCHEDULING"], []),
    ("android.app.AlarmManager", "setExactAndAllowWhileIdle", ["SCHEDULING"], []),
    ("android.app.AlarmManager", "setAndAllowWhileIdle", ["SCHEDULING"], []),
    ("android.app.AlarmManager", "setRepeating", ["SCHEDULING"], []),
    ("android.app.AlarmManager", "setInexactRepeating", ["SCHEDULING"], []),
    ("android.app.AlarmManager", "setAlarmClock", ["SCHEDULING"], []),
    ("android.app.job.JobScheduler", "schedule", ["SCHEDULING"], []),
    ("android.app.job.JobScheduler", "enqueue", ["SCHEDULING"], []),
    ("android.app.job.JobInfo.Builder", "setPersisted", ["SCHEDULING"], []),
    # --- USAGE_STATS ------------------------------------------------------
    # Observing what OTHER apps are doing: the foreground-app oracle overlays and
    # phishing payloads use to decide when to strike.
    ("android.app.usage.UsageStatsManager", "queryUsageStats", ["USAGE_STATS"], []),
    ("android.app.usage.UsageStatsManager", "queryEvents", ["USAGE_STATS"], []),
    (
        "android.app.usage.UsageStatsManager",
        "queryAndAggregateUsageStats",
        ["USAGE_STATS"],
        [],
    ),
    ("android.app.ActivityManager", "getRunningAppProcesses", ["USAGE_STATS"], []),
    ("android.app.ActivityManager", "getRunningTasks", ["USAGE_STATS"], []),
    ("android.app.ActivityManager", "getRecentTasks", ["USAGE_STATS"], []),
    # --- DEVICE_ADMIN -----------------------------------------------------
    ("android.app.admin.DevicePolicyManager", "isAdminActive", ["DEVICE_ADMIN"], []),
    ("android.app.admin.DevicePolicyManager", "isDeviceOwnerApp", ["DEVICE_ADMIN"], []),
    ("android.app.admin.DevicePolicyManager", "lockNow", ["DEVICE_ADMIN"], []),
    ("android.app.admin.DevicePolicyManager", "resetPassword", ["DEVICE_ADMIN"], []),
    ("android.app.admin.DevicePolicyManager", "wipeData", ["DEVICE_ADMIN"], []),
    (
        "android.app.admin.DevicePolicyManager",
        "setCameraDisabled",
        ["DEVICE_ADMIN"],
        [],
    ),
    (
        "android.app.admin.DevicePolicyManager",
        "addUserRestriction",
        ["DEVICE_ADMIN"],
        [],
    ),
    (
        "android.app.admin.DevicePolicyManager",
        "setKeyguardDisabled",
        ["DEVICE_ADMIN"],
        [],
    ),
    # --- SCREEN_CAPTURE ---------------------------------------------------
    (
        "android.media.projection.MediaProjectionManager",
        "createScreenCaptureIntent",
        ["SCREEN_CAPTURE"],
        [],
    ),
    (
        "android.media.projection.MediaProjectionManager",
        "getMediaProjection",
        ["SCREEN_CAPTURE"],
        [],
    ),
    (
        "android.media.projection.MediaProjection",
        "createVirtualDisplay",
        ["SCREEN_CAPTURE"],
        [],
    ),
    (
        "android.hardware.display.DisplayManager",
        "createVirtualDisplay",
        ["SCREEN_CAPTURE"],
        [],
    ),
    # --- BIOMETRIC --------------------------------------------------------
    ("android.hardware.biometrics.BiometricPrompt", "authenticate", ["BIOMETRIC"], []),
    (
        "android.hardware.biometrics.BiometricManager",
        "canAuthenticate",
        ["BIOMETRIC"],
        [],
    ),
    (
        "android.hardware.fingerprint.FingerprintManager",
        "authenticate",
        ["BIOMETRIC"],
        [],
    ),
    (
        "android.hardware.fingerprint.FingerprintManager",
        "hasEnrolledFingerprints",
        ["BIOMETRIC"],
        [],
    ),
    (
        "android.hardware.fingerprint.FingerprintManager",
        "isHardwareDetected",
        ["BIOMETRIC"],
        [],
    ),
    # --- KEYSTORE ---------------------------------------------------------
    # Distinct from CRYPTO: these reach hardware-backed key material rather than
    # transform bytes.
    ("java.security.KeyStore", "getInstance", ["KEYSTORE"], []),
    ("java.security.KeyStore", "getKey", ["KEYSTORE"], []),
    ("java.security.KeyStore", "getEntry", ["KEYSTORE"], []),
    ("java.security.KeyStore", "setKeyEntry", ["KEYSTORE"], []),
    (
        "android.security.keystore.KeyGenParameterSpec.Builder",
        "<init>",
        ["KEYSTORE"],
        [],
    ),
    ("android.security.KeyChain", "getPrivateKey", ["KEYSTORE"], []),
    ("android.security.KeyChain", "getCertificateChain", ["KEYSTORE"], []),
    ("android.security.KeyChain", "createInstallIntent", ["KEYSTORE"], []),
    # --- CRYPTO -----------------------------------------------------------
    ("javax.crypto.Cipher", "getInstance", ["CRYPTO"], []),
    ("javax.crypto.Mac", "getInstance", ["CRYPTO"], []),
    ("javax.crypto.spec.SecretKeySpec", "<init>", ["CRYPTO"], []),
    ("java.security.MessageDigest", "getInstance", ["CRYPTO"], []),
    # --- REFLECTION -------------------------------------------------------
    # Only the steps that express INTENT — resolve a name, dispatch dynamically,
    # defeat access control. The lookups and instantiations that carry them out
    # (`getDeclaredMethod`, `getMethod`, `getDeclaredField`, `getField`,
    # `getDeclaredConstructor`, `newInstance`, `Field.get`/`set`) are deliberately
    # absent: every JSON/ORM/DI library performs them, they always accompany an
    # entry that IS listed, and including them measured library weight instead —
    # adding the six `Class` ones takes tvleanback's REFLECTION from 120 to 194
    # touches (+62%) while identifying no app the kept entries do not already.
    # The kept four are not immune to that either — 84% of the corpus's REFLECTION
    # touches come from bundled library callers — but that is the report-wide
    # limitation noted in `capability.py`, not a reason to add more of them.
    # `setAccessible` is curated under the three RECEIVER types a dex records.
    ("java.lang.Class", "forName", ["REFLECTION"], []),
    ("java.lang.reflect.Method", "invoke", ["REFLECTION"], []),
    ("java.lang.reflect.Method", "setAccessible", ["REFLECTION"], []),
    ("java.lang.reflect.Field", "setAccessible", ["REFLECTION"], []),
    ("java.lang.reflect.Constructor", "setAccessible", ["REFLECTION"], []),
    ("java.lang.ClassLoader", "loadClass", ["REFLECTION"], []),
    # --- DYNAMIC_LOAD -----------------------------------------------------
    ("dalvik.system.DexClassLoader", "<init>", ["DYNAMIC_LOAD"], []),
    ("dalvik.system.PathClassLoader", "<init>", ["DYNAMIC_LOAD"], []),
    ("dalvik.system.InMemoryDexClassLoader", "<init>", ["DYNAMIC_LOAD"], []),
    ("dalvik.system.BaseDexClassLoader", "<init>", ["DYNAMIC_LOAD"], []),
    ("dalvik.system.DexFile", "<init>", ["DYNAMIC_LOAD"], []),
    ("dalvik.system.DexFile", "loadDex", ["DYNAMIC_LOAD"], []),
    ("dalvik.system.DexFile", "loadClass", ["DYNAMIC_LOAD"], []),
    # --- NATIVE_CODE ------------------------------------------------------
    ("java.lang.System", "load", ["NATIVE_CODE"], []),
    ("java.lang.System", "loadLibrary", ["NATIVE_CODE"], []),
    ("java.lang.Runtime", "load", ["NATIVE_CODE"], []),
    ("java.lang.Runtime", "loadLibrary", ["NATIVE_CODE"], []),
    # --- PROCESS_EXEC -----------------------------------------------------
    # WHAT is executed (`su`, `mount`, a dropped binary) is an argument, which
    # `resolve_call_args` answers; the entry is the exec itself.
    ("java.lang.Runtime", "exec", ["PROCESS_EXEC"], []),
    ("java.lang.ProcessBuilder", "<init>", ["PROCESS_EXEC"], []),
    ("java.lang.ProcessBuilder", "start", ["PROCESS_EXEC"], []),
    ("java.lang.ProcessBuilder", "command", ["PROCESS_EXEC"], []),
    # --- NETWORK_IO -------------------------------------------------------
    ("java.net.URL", "openConnection", ["NETWORK_IO"], []),
    ("java.net.URL", "openStream", ["NETWORK_IO"], []),
    ("java.net.Socket", "<init>", ["NETWORK_IO"], []),
    ("java.net.DatagramSocket", "<init>", ["NETWORK_IO"], []),
    ("javax.net.ssl.SSLSocketFactory", "createSocket", ["NETWORK_IO"], []),
    # Replacing the default verifier or socket factory is how TLS validation is
    # disabled process-wide.
    (
        "javax.net.ssl.HttpsURLConnection",
        "setDefaultHostnameVerifier",
        ["NETWORK_IO"],
        [],
    ),
    (
        "javax.net.ssl.HttpsURLConnection",
        "setDefaultSSLSocketFactory",
        ["NETWORK_IO"],
        [],
    ),
    ("javax.net.ssl.HttpsURLConnection", "setSSLSocketFactory", ["NETWORK_IO"], []),
    # --- WEBVIEW ----------------------------------------------------------
    ("android.webkit.WebView", "addJavascriptInterface", ["WEBVIEW"], []),
    ("android.webkit.WebView", "loadUrl", ["WEBVIEW", "NETWORK_IO"], []),
    ("android.webkit.WebView", "loadData", ["WEBVIEW"], []),
    ("android.webkit.WebView", "loadDataWithBaseURL", ["WEBVIEW"], []),
    ("android.webkit.WebView", "evaluateJavascript", ["WEBVIEW"], []),
    ("android.webkit.WebSettings", "setJavaScriptEnabled", ["WEBVIEW"], []),
    ("android.webkit.WebSettings", "setAllowFileAccess", ["WEBVIEW"], []),
    (
        "android.webkit.WebSettings",
        "setAllowUniversalAccessFromFileURLs",
        ["WEBVIEW"],
        [],
    ),
]

# (class, member) -> (permissions, why the AOSP annotation cannot supply them).
#
# The rule is that a permission is DERIVED, never typed — but `@RequiresPermission`
# only covers what the framework enforces with an annotation, and three real
# enforcement mechanisms carry none. Every supplement below names which one, is
# UNIONED with whatever the dataset does say, and is checked against the dataset:
# a supplement the annotation already provides is a hard error, so this list cannot
# quietly outlive the gap it exists for.
CURATED_PERMISSIONS: dict[tuple[str, str], tuple[list[str], str]] = {
    # Kernel DAC, not an annotation: INTERNET is a GID (`inet`), so no framework
    # method is annotated with it.
    ("java.net.Socket", "<init>"): (["android.permission.INTERNET"], "kernel GID"),
    ("java.net.DatagramSocket", "<init>"): (
        ["android.permission.INTERNET"],
        "kernel GID",
    ),
    ("java.net.URL", "openConnection"): (["android.permission.INTERNET"], "kernel GID"),
    ("java.net.URL", "openStream"): (["android.permission.INTERNET"], "kernel GID"),
    ("javax.net.ssl.SSLSocketFactory", "createSocket"): (
        ["android.permission.INTERNET"],
        "kernel GID",
    ),
    # Enforced by the ContentProvider, so the annotation is on the provider, not on
    # the constant an app reads.
    ("android.provider.Telephony.Sms", "CONTENT_URI"): (
        ["android.permission.READ_SMS"],
        "provider-enforced",
    ),
    ("android.provider.Telephony.Sms.Inbox", "CONTENT_URI"): (
        ["android.permission.READ_SMS"],
        "provider-enforced",
    ),
    ("android.provider.Telephony.Mms", "CONTENT_URI"): (
        ["android.permission.READ_SMS"],
        "provider-enforced",
    ),
    ("android.provider.ContactsContract.Contacts", "CONTENT_URI"): (
        ["android.permission.READ_CONTACTS"],
        "provider-enforced",
    ),
    ("android.provider.ContactsContract.RawContacts", "CONTENT_URI"): (
        ["android.permission.READ_CONTACTS"],
        "provider-enforced",
    ),
    ("android.provider.ContactsContract.Data", "CONTENT_URI"): (
        ["android.permission.READ_CONTACTS"],
        "provider-enforced",
    ),
    ("android.provider.ContactsContract.PhoneLookup", "CONTENT_FILTER_URI"): (
        ["android.permission.READ_CONTACTS"],
        "provider-enforced",
    ),
    ("android.provider.ContactsContract.CommonDataKinds.Phone", "CONTENT_URI"): (
        ["android.permission.READ_CONTACTS"],
        "provider-enforced",
    ),
    ("android.provider.ContactsContract.CommonDataKinds.Email", "CONTENT_URI"): (
        ["android.permission.READ_CONTACTS"],
        "provider-enforced",
    ),
    ("android.provider.CallLog.Calls", "CONTENT_URI"): (
        ["android.permission.READ_CALL_LOG"],
        "provider-enforced",
    ),
    ("android.provider.CallLog.Calls", "CONTENT_URI_WITH_VOICEMAIL"): (
        ["android.permission.READ_CALL_LOG"],
        "provider-enforced",
    ),
    ("android.provider.CalendarContract.Events", "CONTENT_URI"): (
        ["android.permission.READ_CALENDAR"],
        "provider-enforced",
    ),
    # Package VISIBILITY filtering, enforced by the package manager against the
    # manifest declaration rather than at the call.
    ("android.content.pm.PackageManager", "getInstalledPackages"): (
        ["android.permission.QUERY_ALL_PACKAGES"],
        "package-visibility filtering",
    ),
    ("android.content.pm.PackageManager", "getInstalledApplications"): (
        ["android.permission.QUERY_ALL_PACKAGES"],
        "package-visibility filtering",
    ),
    # Legacy APIs that predate the annotation and never got one, though the
    # permission is still required.
    ("android.hardware.Camera", "open"): (
        ["android.permission.CAMERA"],
        "un-annotated legacy",
    ),
    ("android.media.MediaRecorder", "setAudioSource"): (
        ["android.permission.RECORD_AUDIO"],
        "un-annotated legacy",
    ),
    # targetSdk-gated: AOSP annotates the privileged permission, and its own javadoc
    # documents that an app targeting API <= 28 reaches the same value with
    # READ_PHONE_STATE — which is what the samples in the wild declare. Both are
    # reported because both are true, of different apps.
    ("android.telephony.TelephonyManager", "getDeviceId"): (
        ["android.permission.READ_PHONE_STATE"],
        "targetSdk<=28 path documented in the AOSP javadoc",
    ),
    ("android.telephony.TelephonyManager", "getSubscriberId"): (
        ["android.permission.READ_PHONE_STATE"],
        "targetSdk<=28 path documented in the AOSP javadoc",
    ),
    ("android.telephony.TelephonyManager", "getSimSerialNumber"): (
        ["android.permission.READ_PHONE_STATE"],
        "targetSdk<=28 path documented in the AOSP javadoc",
    ),
}

# (class, member, erased signature) -> why this overload can never be recorded
# under that receiver. Overload closure is otherwise blind: it cannot see modifiers
# (the AOSP member catalog drops them for methods), and a STATIC member is compiled
# against its DECLARING class, so emitting it under a subclass receiver produces a
# real AOSP member that no dex ever spells that way. Kept small and checked — an
# entry matching no overload is a hard error, like CURATED_PERMISSIONS'.
EXCLUDED_OVERLOADS: dict[tuple[str, str, str], str] = {
    (
        cls,
        "setAccessible",
        "setAccessible(java.lang.reflect.AccessibleObject[], boolean)",
    ): (
        "static on AccessibleObject; javac emits it against that class, never "
        "against a subclass receiver"
    )
    for cls in (
        "java.lang.reflect.Method",
        "java.lang.reflect.Field",
        "java.lang.reflect.Constructor",
    )
}

NOTES = (
    "Android framework API -> permission/capability metadata for "
    "summarize_capabilities. GENERATED by scripts/gen_capability_catalog.py from a "
    "curated (class, member) selection plus the AOSP member catalog -- edit that "
    "script, not this file. TWO AXES, kept separate so the aggregate Counter stays "
    "meaningful: `categories` is ONE axis (domain / behaviour) and no tag may be "
    "implied by another, so one call site is never counted twice under two names for "
    "the SAME concern -- a second tag is only correct when the API genuinely spans two "
    "domains (e.g. WifiManager.getScanResults -> WIFI + LOCATION), and then it does "
    "count once in each. `flags` carries the orthogonal, cross-domain concerns a domain "
    "tag cannot express (today only IDENTIFIER: the API provably returns a device/user "
    "identifier). Facts already stated by the key (IMSI for getSubscriberId, "
    "MAC_ADDRESS for getAddress, ...), severity judgements (RISKY) and "
    "argument-dependent guesses (which setting Settings$Secure.getString reads, what "
    "Runtime.exec runs -- resolve_call_args answers those properly) are deliberately "
    "NOT tags. A key is a METHOD descriptor (Lcls;->name(proto)ret) or a FIELD "
    "descriptor (Lcls;->NAME:Ltype;) -- the two are unambiguous by shape, so no schema "
    "key says which. A method key counts INVOKE INSTRUCTIONS into call_site_count; a "
    "field key counts READ INSTRUCTIONS into the separate field_access_count, because "
    "reading a framework CONTENT_URI constant is how an app reaches "
    "contacts/call log/calendar and no method call expresses it (dexllm#36). The two "
    "are the same unit and the counters are kept apart only so call_site_count's "
    "released meaning is untouched. A key names the class the APP writes (the dex "
    "method_id records the static receiver type), which is why Method/Field/Constructor "
    "each carry setAccessible although AOSP declares it once on AccessibleObject. The "
    "selection is a judgement about what is worth reporting and excludes ubiquitous "
    "APIs (startActivity, sendBroadcast, ContentResolver.query, ...) even when they "
    "carry a permission; the exhaustive permission surface is dangerous_permission_apis. "
    "The two vocabularies below are the CLOSED sets summarize_capabilities validates "
    "`only_categories` against, so a tag that is not here is a loud error instead of a "
    "silently empty report; a replacement catalog must declare its own."
)

PRIMITIVES = {
    "void": "V",
    "int": "I",
    "boolean": "Z",
    "byte": "B",
    "short": "S",
    "char": "C",
    "long": "J",
    "float": "F",
    "double": "D",
}


def _erase(java_type: str) -> str:
    """Drop generic arguments and normalise varargs — dex records erased types."""
    out, depth = [], 0
    for ch in java_type:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        elif depth == 0:
            out.append(ch)
    return "".join(out).replace("...", "[]").strip()


def _type_desc(java_type: str, packages: dict) -> str:
    """Render a metalava type name as a Dalvik type descriptor.

    metalava writes ``java.lang`` types with their simple name and everything else
    fully qualified, and a nested class with a ``.`` where dex uses ``$`` — which is
    why the package map is needed to know where the package ends. A type the AOSP
    catalog does not know (a ``java.util`` class, say) is assumed to have no nested
    part, which is true of every type reachable from a public signature.

    A dotless name that is not a primitive and not a real ``java.lang`` type is a
    TYPE VARIABLE, and this dataset carries no type-parameter BOUNDS — so its
    erasure is ``Object`` when unbounded and the bound when not, and the two are
    indistinguishable here. Guessing ``Object`` would silently emit
    ``onError(Ljava/lang/Object;)V`` where a dex records
    ``onError(Ljava/lang/Throwable;)V``: a real member spelled wrong, which matches
    nothing forever and raises nothing. So it is a hard error, and a curated name
    that hits one has to wait for a source of bounds.
    """
    t = _erase(java_type)
    arr = 0
    while t.endswith("[]"):
        arr, t = arr + 1, t[:-2].strip()
    if t in PRIMITIVES:
        return "[" * arr + PRIMITIVES[t]
    if any(c in t for c in "?@ "):
        raise ValueError(f"unsupported type syntax: {java_type!r}")
    if "." not in t:
        if f"java.lang.{t}" not in packages:
            raise ValueError(
                f"{java_type!r} is neither a primitive nor a java.lang type — if it "
                "is a type variable, its erasure is not derivable from this dataset"
            )
        t = f"java.lang.{t}"
    package = packages.get(t)
    if package is None:
        # A type the AOSP catalog does not know. Its nesting is then unknown too,
        # and guessing "no nested part" would render `java.util.Map.Entry` as the
        # invalid `Ljava/util/Map/Entry;` — a key that matches nothing, silently.
        raise ValueError(f"{java_type!r} is not in the AOSP class catalog")
    nested = t[len(package) + 1 :] if package else t
    prefix = package.replace(".", "/") + "/" if package else ""
    return "[" * arr + "L" + prefix + nested.replace(".", "$") + ";"


def _split_params(params: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in params:
        depth += ch in "<("
        depth -= ch in ">)"
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return [p.strip() for p in out]


def _load_dataset(root: pathlib.Path):
    """Return (members by (class, member name), supertypes, packages)."""
    packages, supers = {}, {}
    with open(root / "aosp_classes.csv") as fh:
        for row in csv.DictReader(fh):
            packages[row["fqn"]] = row["package"]
            parents = [row["extends"]] if row["extends"] else []
            parents += [i.strip() for i in row["implements"].split(",") if i.strip()]
            supers[row["fqn"]] = parents
    members = collections.defaultdict(list)
    with open(root / "aosp_members.csv") as fh:
        for row in csv.DictReader(fh):
            name = "<init>" if row["kind"] == "ctor" else row["name"]
            members[(row["class"], name)].append(row)
    return members, supers, packages


def _resolve(cls: str, member: str, members, supers) -> list[tuple[str, dict]]:
    """Return every (declaring class, row) for ``member`` visible on ``cls``.

    The WHOLE hierarchy, not the nearest declaring class: Java does not hide a
    supertype's overload when a subclass declares one of the same name, so
    stopping at the first hit loses the rest. ``SSLSocketFactory`` declares one
    ``createSocket`` and inherits five from ``SocketFactory`` — including
    ``createSocket(String, int)``, the common one — and taking only the nearest
    class reproduced exactly the missing-overload hole this script exists to
    close. Breadth-first with a per-SIGNATURE dedup so an override still resolves
    to the nearest declaration, which is where the permission annotation is.

    A constructor is never inherited.
    """
    if member == "<init>":
        return [(cls, row) for row in members.get((cls, member), [])]
    out: list[tuple[str, dict]] = []
    by_signature: dict[str, str] = {}
    seen, queue = {cls}, collections.deque([cls])
    while queue:
        cur = queue.popleft()
        for row in members.get((cur, member), ()):
            signature = _erase(row["signature"])
            if signature in by_signature:
                continue  # a nearer class already declared this exact overload
            by_signature[signature] = cur
            out.append((cur, row))
        for parent in supers.get(cur, ()):
            if parent not in seen:
                seen.add(parent)
                queue.append(parent)
    return out


def build(root: pathlib.Path) -> dict:
    """Return the whole catalog object, ready to serialise.

    Separate from :func:`main` so the guard in ``tests/test_capability_catalog.py``
    can compare it against the committed file without writing anything.
    """
    members, supers, packages = _load_dataset(root)
    perm_api = json.loads(PERM_API.read_text())
    levels = json.loads(PERM_LEVELS.read_text())
    perms_of = collections.defaultdict(set)
    for perm, apis in perm_api.items():
        for api in apis:
            perms_of[api].add(perm)

    curated_permissions = CURATED_PERMISSIONS
    used_supplements: set[tuple[str, str]] = set()
    used_exclusions: set[tuple[str, str, str]] = set()
    entries: dict[str, dict] = {}
    for cls, member, categories, flags in CURATED:
        if cls not in packages:
            raise SystemExit(f"{cls} is not in the AOSP class catalog")
        resolved = _resolve(cls, member, members, supers)
        if not resolved:
            raise SystemExit(f"{cls}#{member} names no AOSP member")
        owner = _type_desc(cls, packages)  # the class the APP writes, not `declaring`
        for declaring, row in resolved:
            signature = row["signature"]
            if (cls, member, _erase(signature)) in EXCLUDED_OVERLOADS:
                used_exclusions.add((cls, member, _erase(signature)))
                continue
            if row["kind"] == "field":
                key = (
                    f"{owner}->{row['name']}:{_type_desc(row['return_type'], packages)}"
                )
            else:
                params = signature[signature.index("(") + 1 : signature.rindex(")")]
                proto = "".join(_type_desc(p, packages) for p in _split_params(params))
                ret = _type_desc(row["return_type"] or "void", packages)
                name = "<init>" if row["kind"] == "ctor" else row["name"]
                key = f"{owner}->{name}({proto})" + (
                    "V" if row["kind"] == "ctor" else ret
                )
            # The permission is keyed on the DECLARING class, which is where the
            # annotation lives; the catalog key stays the receiver spelling. The
            # `(Nargs)` alternative is the runtime-enforcement bridge, whose entries
            # carry an arity instead of parameter types — how `SmsManager` reaches
            # SEND_SMS, which no annotation states. Missing it is what made the first
            # cut of this script silently drop SEND_SMS off `sendTextMessage`.
            found = set(perms_of.get(f"{declaring}#{signature}", ()))
            if row["kind"] != "field":
                arity = len(
                    _split_params(
                        signature[signature.index("(") + 1 : signature.rindex(")")]
                    )
                )
                bridged = perms_of.get(f"{declaring}#{row['name']}({arity}args)", set())
                # The bridge reports EVERY permission gate on the call chain down to
                # the service impl, including internal ones no app can hold, so only
                # here is the protection level a filter: without it `getProviders`
                # collects LOCATION_BYPASS / LOCATION_HARDWARE / UPDATE_APP_OPS_STATS
                # / UPDATE_DEVICE_STATS beside the two location permissions that are
                # actually its answer. The ANNOTATION join above is NOT filtered —
                # `getDeviceId`'s READ_PRIVILEGED_PHONE_STATE is signature-level and
                # is exactly what AOSP says the API requires.
                # A permission absent from perm_levels.json has no level and is
                # dropped with the rest — deliberate: an unknown level cannot be
                # shown to be app-holdable, and this arm exists to be conservative.
                found |= {p for p in bridged if levels.get(p) in APP_HOLDABLE}
            supplement, reason = curated_permissions.get((cls, member), ([], ""))
            already = sorted(set(supplement) & found)
            if already:
                raise SystemExit(
                    f"{cls}#{member}: curated permission(s) {already} are ALREADY in "
                    f"the dataset — drop them (the {reason!r} gap has closed)"
                )
            used_supplements.add((cls, member))
            meta: dict = {}
            if found or supplement:
                meta["permissions"] = sorted(found | set(supplement))
            meta["categories"] = list(categories)
            if flags:
                meta["flags"] = list(flags)
            if key in entries and entries[key] != meta:
                raise SystemExit(f"conflicting metadata for {key}")
            entries[key] = meta

    # A supplement for a name no longer curated would sit here forever, unread and
    # unfalsifiable — the same dead-weight the 0.3 catalog's `since_api` leftovers
    # were. Same reason the "already in the dataset" check above is an error.
    orphans = sorted(set(curated_permissions) - used_supplements)
    if orphans:
        raise SystemExit(
            "CURATED_PERMISSIONS entries match no curated name: " + str(orphans)
        )
    unused = sorted(set(EXCLUDED_OVERLOADS) - used_exclusions)
    if unused:
        raise SystemExit("EXCLUDED_OVERLOADS entries match no overload: " + str(unused))

    return {
        "version": VERSION,
        "source": SOURCE,
        "notes": NOTES,
        "category_vocabulary": sorted(CATEGORY_VOCABULARY),
        "flag_vocabulary": sorted(FLAG_VOCABULARY),
        "entries": {k: entries[k] for k in sorted(entries)},
    }


def main() -> None:
    """Regenerate the committed catalog from CURATED plus the AOSP dataset."""
    argv = [a for a in sys.argv[1:] if a != "--allow-drop"]
    allow_drop = "--allow-drop" in sys.argv
    unknown = [a for a in argv if a.startswith("-")]
    if unknown:
        raise SystemExit(f"unknown option(s) {unknown}; the only flag is --allow-drop")
    root = argv[0] if argv else os.environ.get("DEXLLM_AOSP_DATASET")
    if not root:
        root = str(pathlib.Path.home() / "Project" / "aosp_data_set")
    root = pathlib.Path(root)
    if not (root / "aosp_members.csv").is_file():
        raise SystemExit(
            f"no aosp_members.csv under {root} — pass an aosp_data_set checkout "
            "or set $DEXLLM_AOSP_DATASET"
        )

    catalog = build(root)
    previous = json.loads(OUT.read_text())["entries"] if OUT.is_file() else {}
    # Dropping an entry is a real curation decision (an API judged to be noise) but
    # it is also what a mistyped rename looks like, and the two are indistinguishable
    # from the diff alone — a name that no longer resolves is already a hard error,
    # so what is left here is exactly the ambiguous case. Say it out loud and make
    # the curator opt in.
    lost = sorted(set(previous) - set(catalog["entries"]))
    if lost and not allow_drop:
        raise SystemExit(
            f"regeneration would DROP {len(lost)} "
            f"{'entry' if len(lost) == 1 else 'entries'} the committed catalog "
            "carries; re-run with --allow-drop if that is the intent:\n  "
            + "\n  ".join(lost)
        )

    OUT.write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n")
    print(
        f"wrote {OUT} — {len(catalog['entries'])} entries "
        f"({len(CURATED)} curated names, {len(previous)} before), "
        f"{len(catalog['category_vocabulary'])} categories"
    )


if __name__ == "__main__":
    main()
