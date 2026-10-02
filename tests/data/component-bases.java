// Fixture source for tests/data/component-bases.dex (find_component_subclasses).
//
// Authored rather than copied: the bundled corpus has no depth-2 chain through
// an app-side abstract class, no ZygotePreload implementor, no class whose
// parent is in neither the dex nor the SDK, and no class extending Service
// without a public no-arg constructor — and a fixture where two predicates
// AGREE proves nothing. One class per branch of the decision:
//
//   PlainActivity     extends Activity                 — depth 1, resolved
//   BaseActivity      abstract, extends Activity       — a chain NODE (is_abstract)
//   LeafActivity      extends BaseActivity             — chain through an APP intermediate
//   MyTile            extends TileService              — chain through a FRAMEWORK
//                                                       intermediate the dex does not
//                                                       declare (the table's whole point)
//   Widget            extends AppWidgetProvider        — receiver, depth 2 via the table
//   CtorService       extends Service, ctor (int)      — no public no-arg constructor
//   PkgService        extends Service, package ctor    — no PUBLIC no-arg constructor
//   PkgClass          package-private class, public    — NOT instantiable: ART's
//                     no-arg ctor                        Class.newInstance refuses a class
//                                                       the caller (android.app) cannot
//                                                       access, whatever its constructor
//   NewedService      extends Service                  — constructed by Factory.make
//   SuperOnly         extends Service                  — constructed ONLY through a
//   SubOfSuperOnly    extends SuperOnly                  subclass's super(): constructed_in
//                                                       must be EMPTY for SuperOnly
//   Registrar$1       anonymous BroadcastReceiver      — handed to registerReceiver: the
//                                                       dynamic-registration shape
//   Rcv / Holder      Holder's CONSTRUCTOR registers    — a `<init>` caller that is NOT a
//                     new Rcv()                           subclass: must be KEPT (an
//                                                       adversarial review's mutant)
//   PrivCtor          public class, PRIVATE no-arg ctor — the constructor half of
//                                                       is_instantiable, alone
//   TwiceSvc / Twice  two `new TwiceSvc()` in ONE method — constructed_in is deduplicated
//   Preload           implements ZygotePreload         — the INTERFACE root
//   PreloadActivity   extends Activity implements      — BOTH roots hold; the row is
//                     ZygotePreload                      `activity` (class root first)
//   Delegating        extends Service, this(1) ctor    — a constructor delegating to
//                                                       another is NOT a construction
//   MyPreload         interface extends ZygotePreload  — a TYPE, never a row
//   ViaIface          implements MyPreload             — chain through an app interface
//   MyApp / MyBackup / MyFactory / MyInstr             — the four remaining class roots
//   ViewSub           extends android.view.View        — a KNOWN SDK class that is not a
//                                                       base: resolved NOT a candidate
//   ThreadSub         extends java.lang.Thread         — same, java.*
//   Orphan            extends com.example.missing.Vanished
//                     (compiled, then EXCLUDED from the dex) — a parent in no dex and
//                     not in the SDK: UNRESOLVED
//
// `is_instantiable` is ART's Class.newInstance predicate — a PUBLIC class with a
// PUBLIC zero-argument constructor, neither abstract nor an interface — so the
// fixture's classes are PUBLIC STATIC members of one public outer class (javac
// allows one top-level public class per file, and a public static nested class
// gets ACC_PUBLIC in its own class_def). A public nested class's default
// constructor is public; the two that must NOT be instantiable spell their
// constructor out, and PkgClass drops `public` on the class instead.
//
// Build (see tests/data/README.md): `cp component-bases.java ComponentBases.java`,
// javac against android.jar, then d8 over every class file EXCEPT Vanished.class.

package com.example.cb;

import android.app.Activity;
import android.app.AppComponentFactory;
import android.app.Application;
import android.app.Instrumentation;
import android.app.Service;
import android.app.ZygotePreload;
import android.app.backup.BackupAgent;
import android.app.backup.BackupDataInput;
import android.app.backup.BackupDataOutput;
import android.appwidget.AppWidgetProvider;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.service.quicksettings.TileService;
import android.view.View;

public class ComponentBases {
    public static class PlainActivity extends Activity {
    }

    public static abstract class BaseActivity extends Activity {
    }

    public static class LeafActivity extends BaseActivity {
    }

    public static class MyTile extends TileService {
    }

    public static class Widget extends AppWidgetProvider {
    }

    public static class CtorService extends Service {
        public CtorService(int unused) {
        }

        public IBinder onBind(Intent intent) {
            return null;
        }
    }

    static class PkgClass extends Service {
        public PkgClass() {
        }

        public IBinder onBind(Intent intent) {
            return null;
        }
    }

    static class PkgService extends Service {
        PkgService() {
        }

        public IBinder onBind(Intent intent) {
            return null;
        }
    }

    public static class NewedService extends Service {
        public IBinder onBind(Intent intent) {
            return null;
        }
    }

    public static class SuperOnly extends Service {
        public IBinder onBind(Intent intent) {
            return null;
        }
    }

    public static class SubOfSuperOnly extends SuperOnly {
    }

    public static class Factory {
        Service make() {
            return new NewedService();
        }
    }

    public static class Registrar {
        void go(Context c) {
            c.registerReceiver(new BroadcastReceiver() {
                public void onReceive(Context x, Intent i) {
                }
            }, new IntentFilter("com.example.cb.PING"));
        }
    }

    public static class PreloadActivity extends Activity implements ZygotePreload {
        public void doPreload(ApplicationInfo info) {
        }
    }

    public static class Delegating extends Service {
        public Delegating() {
            this(1);
        }

        public Delegating(int unused) {
        }

        public IBinder onBind(Intent intent) {
            return null;
        }
    }

    public static class Rcv extends BroadcastReceiver {
        public void onReceive(Context c, Intent i) {
        }
    }

    public static class Holder {
        public Holder(Context c) {
            c.registerReceiver(new Rcv(), new IntentFilter("com.example.cb.PONG"));
        }
    }

    public static class PrivCtor extends Service {
        private PrivCtor() {
        }

        public IBinder onBind(Intent intent) {
            return null;
        }
    }

    public static class TwiceSvc extends Service {
        public IBinder onBind(Intent intent) {
            return null;
        }
    }

    public static class Twice {
        Service make(boolean b) {
            return b ? new TwiceSvc() : new TwiceSvc();
        }
    }

    public static class Preload implements ZygotePreload {
        public void doPreload(ApplicationInfo info) {
        }
    }

    public static interface MyPreload extends ZygotePreload {
    }

    public static class ViaIface implements MyPreload {
        public void doPreload(ApplicationInfo info) {
        }
    }

    public static class MyApp extends Application {
    }

    public static class MyBackup extends BackupAgent {
        public void onBackup(ParcelFileDescriptor oldState, BackupDataOutput data,
                ParcelFileDescriptor newState) {
        }

        public void onRestore(BackupDataInput data, int appVersionCode,
                ParcelFileDescriptor newState) {
        }
    }

    public static class MyFactory extends AppComponentFactory {
    }

    public static class MyInstr extends Instrumentation {
    }

    public static class ViewSub extends View {
        ViewSub(Context c) {
            super(c);
        }
    }

    public static class ThreadSub extends Thread {
    }

    public static class Orphan extends com.example.missing.Vanished {
    }
}
