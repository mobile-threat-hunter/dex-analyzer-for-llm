// dexllm#127 fixture: one class per member-class spelling rule.
// Rebuild: see tests/data/README.md.
package mc;

import java.util.Map;

public class Outer {
    // a static member, and a member of a member
    public static class Nested {
        public static class Deep {
            public static int X;
        }

        // an anonymous class inside a member: Outer$Nested$1
        public static Runnable anon() {
            return new Runnable() {
                public void run() {}
            };
        }
    }

    // an inner (non-static) member
    public class Inner {
        public int f;
    }

    // an anonymous class directly in Outer: Outer$1
    public static Runnable anonTop() {
        return new Runnable() {
            public void run() {}
        };
    }

    // a local class: Outer$1Loc, which carries EnclosingMethod, not EnclosingClass
    public static Object local() {
        class Loc {}
        return new Loc();
    }

    // every reference below is a TYPE position the Java view spells
    public static int use(Nested n, Nested.Deep d, Inner i,
                          Map.Entry<String, String> e, Thread.State s,
                          Weird$Name w) {
        Nested.Deep.X = 1;
        return Nested.Deep.X + (e == null ? 0 : 1) + s.ordinal() + Weird$Name.y
                + (n == null ? 0 : 1) + (d == null ? 0 : 1) + (i == null ? 0 : i.f)
                + (w == null ? 0 : 1);
    }

    // a FIELD type: declared through the class's own field list, not a body
    public static Nested.Deep KEEP;

    // reads the class `member-classes-sdkname.java` declares
    public static int sdkNamed() {
        return android.view.View$OnClickListener.z;
    }

    public static int topLevelPrefix() {
        return Outer$Nested$Top.t;
    }

    public Inner makeInner() {
        return new Inner();
    }
}

// a class HEADER naming a member superclass and a framework member interface
class Sub extends Outer.Nested implements Thread.UncaughtExceptionHandler {
    public void uncaughtException(Thread t, Throwable e) {}
}

// a class whose descriptor is as long as `Lmc/Outer;`: a crafted EnclosingClass
// pointing here differs from the true outer only in its CONTENT, which is what
// isolates the prefix check from the length check
class Other {}

// a TOP-LEVEL class whose name extends a MEMBER's (`Outer$Nested` is one): it
// is not nested, so its `$` stay, and so does every `$` before them —
// `mc.Outer.Nested$Top` would name a member of Nested that does not exist.
// D8's `$$ExternalSyntheticLambda0` classes have exactly this shape.
class Outer$Nested$Top {
    static int t;
}

// a TOP-LEVEL class whose name merely contains `$`: no InnerClass annotation,
// so nothing proves a nesting and the `$` must stay.
class Weird$Name {
    static int y;
}
