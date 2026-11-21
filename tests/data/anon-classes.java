// dexllm#129 fixture: anonymous classes inlined at their construction site.
package ac;

import java.util.Comparator;

public class Anon {
    int count = 3;

    static abstract class Base {
        final String tag;
        Base(String tag, int n) { this.tag = tag + n; }
        abstract int get();
    }

    // Captures the outer instance and a parameter.
    public Runnable capture(final int limit) {
        return new Runnable() {
            public void run() {
                if (count > limit) count = limit;
            }
        };
    }

    // Static: captures a local only, no outer instance.
    public static Comparator<String> byLength(final boolean reverse) {
        return new Comparator<String>() {
            public int compare(String a, String b) {
                int d = a.length() - b.length();
                return reverse ? -d : d;
            }
        };
    }

    // Superclass constructor arguments, plus a captured value.
    public Base withSuper(final int extra) {
        return new Base("t", 7) {
            int get() { return tag.length() + extra; }
        };
    }

    // Thread(String): a framework superclass with an argument.
    public static Thread thread(String name) {
        return new Thread(name) {
            public void run() { setPriority(1); }
        };
    }

    // No capture at all, in a static method.
    static Runnable make() {
        return new Runnable() { public void run() {} };
    }

    // A static method's own parameter, captured by a body that declares no
    // name of the same spelling.
    public static Runnable print(final String msg) {
        return new Runnable() {
            public void run() { System.out.println(msg); }
        };
    }

    // A wide (long) captured value: two registers, one parameter.
    public Runnable wide(final long t, final int n) {
        return new Runnable() {
            public void run() { count = (int) (t + n); }
        };
    }

    // A field initializer: the constructor does more than store parameters.
    public static Object withInit() {
        return new Object() {
            int[] cache = new int[4];
            public String toString() { return "" + cache.length; }
        };
    }

    // An anonymous class inside an anonymous class.
    public Runnable nested(final String s) {
        return new Runnable() {
            public void run() {
                Runnable inner = new Runnable() {
                    public void run() { System.out.println(s); }
                };
                inner.run();
            }
        };
    }

    // A statement, not an expression: the result is discarded.
    public void discard(final int v) {
        new Thread() {
            public void run() { System.out.println(v); }
        }.start();
    }

    // An anonymous class inside a member that is NOT inlined (its constructor
    // runs a field initializer): its spelling keeps only its own `$`.
    static class Holder {
        static Object make() {
            return new Object() {
                int[] cache = new int[1];
            };
        }
    }

    // An enum constant with a body is an anonymous class of the enum: Java
    // cannot write `new Op(...) { }`, so it is not inlined.
    enum Op {
        PLUS { int apply(int a) { return a; } };
        abstract int apply(int a);
    }

    // The base is a LOCAL class, which nothing outside this method can name.
    public Object localBase() {
        class Loc { int k() { return 1; } }
        return new Loc() { int k() { return 2; } };
    }

    // The captured value is a call the site folds into the argument: reading
    // it again in the body would repeat the call, so it is not inlined.
    public Runnable folded() {
        final String s = String.valueOf(count);
        return new Runnable() {
            public void run() { System.out.println(s); }
        };
    }

    // A member class declared inside the anonymous body.
    public static Runnable memberInside() {
        return new Runnable() {
            class In { }
            public void run() { new In(); }
        };
    }

    // A supplementary-plane identifier read inside an inlined body: the body
    // is sanitised once, with the method it is written into.
    static int 𐀀;
    public static Runnable astral() {
        return new Runnable() {
            public void run() { System.out.println(𐀀); }
        };
    }

    // A loop variable captured per iteration: the site's register is written
    // again below the construction, so the body cannot name it.
    public java.util.List<Runnable> loop(int n) {
        java.util.List<Runnable> out = new java.util.ArrayList<Runnable>();
        for (int i = 0; i < n; i++) {
            final int j = i;
            out.add(new Runnable() { public void run() { System.out.println(j); } });
        }
        return out;
    }

    // The superclass has an overload the argument's own type would bind.
    static class Over {
        Over(Object o) { }
        Over(String s) { }
        void f() { }
    }
    public Over overload(String s) {
        return new Over((Object) s) { void f() { } };
    }

    // The construction is kept in a local first: the local is declared with
    // the type the inline text names.
    public Runnable kept(final int x) {
        Runnable r = new Runnable() { public void run() { System.out.println(x); } };
        System.out.println(r);
        return r;
    }

    // The captured value is a parameter that SplitVariables names in a
    // version of its own; the body must name it the way the site does.
    public Runnable reassign(int x) {
        final int y = x;
        Runnable r = new Runnable() { public void run() { System.out.println(y); } };
        x = x + 5;
        System.out.println(x);
        return r;
    }
}
