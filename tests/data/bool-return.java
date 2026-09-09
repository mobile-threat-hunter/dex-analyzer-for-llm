// Source of tests/data/bool-return.dex — the fixture for dexllm#86.
//
// AUTHORED, not copied: no committed fixture carries a `boolean` method that
// returns a FLAG REGISTER, and that is the whole subject.  Every method here
// exists for one branch of the decision, so a mutant that widens or narrows the
// rule changes an assertion rather than passing unnoticed.
//
// Java cannot express the shapes that need to be REFUSED — a `boolean` local
// used as an arithmetic operand or an array index is a compile error — so those
// arrive by CRAFT: the guard repoints an `(I)I` method's `method_id` at the
// `(I)Z` proto this file already provides (one u2, length-preserving), which
// turns an int-returning method into a Z-returning one whose returned register
// is genuinely int-used.  That is why every craft base below is `(I)I`: the
// protos must match for the repoint to be a rename and nothing more.
//
// Compiled with javac 17.0.17 + d8 35.0.0 (see tests/data/README.md).

public class BoolReturn {

    static int[] ARR = new int[8];
    static int[] ARR2;
    static int IFIELD;
    int instField;

    static void sinkBool(boolean x) { ARR[0] = x ? 1 : 0; }
    static void sinkInt(int x) { ARR[0] = x; }
    static void sinkArr(int[] a) { ARR2 = a; }

    // ---- the defect itself -------------------------------------------------

    // A. The canonical shape.  Dalvik has no boolean, so d8 writes the flag with
    //    `const/4`, DAD types the version from the last write, and the method
    //    returns `int` from a `Z` signature.  Must render `boolean … = true`.
    public static boolean flag(int p) {
        boolean b = true;
        if (p > 3) { b = false; }
        return b;
    }

    // B. The def is a Z-returning INVOKE rather than a constant — the
    //    `r->get_type() == "Z"` arm of the resolver.
    public static boolean viaCall(Object o, int p) {
        boolean b = false;
        if (p > 3) { b = o.equals("x"); }
        return b;
    }

    // C. The def is a boolean PARAM reached through a move — the
    //    `defs_of.end()` arm, which must consult the param's declared type.
    public static boolean viaParam(boolean q, int p) {
        boolean b = q;
        if (p > 3) { b = true; }
        return b;
    }

    // D2. The returned flag's value ARRIVES through another local, and only the
    //     returned one carries the constraint.  Typing that one alone would
    //     leave `boolean b = a;` with `a` still `int` — one invalid line traded
    //     for another — so the fix propagates `Z` backwards along move edges and
    //     BOTH must come out boolean.  This is the corpus's dominant `equals`
    //     shape (two registers that move into each other) in the smallest form
    //     that javac can express.
    public static boolean viaLocal(int p) {
        boolean a = true;
        if (p > 3) { a = false; }
        boolean b;
        if (p > 7) { b = a; } else { b = false; }
        return b;
    }

    // D3. The same, except the source is ALSO used as an int, so propagation
    //     must stop at it: `a` stays `int` and `b` becomes `boolean`.  A build
    //     that propagated unconditionally would type `a` boolean and then emit
    //     `a + p`.
    public static boolean viaLocalConflated(int p) {
        int a = 1;
        if (p > 3) { a = a + p; }
        boolean b;
        if (p > 7) { b = (a != 0); } else { b = false; }
        return b;
    }

    // D4. The flag is ALSO passed at a `boolean` PARAMETER.  `prim_use_vids`
    //     records a NON-boolean primitive position only, so this must still be
    //     fixed — a guard that blocked on any primitive argument would silently
    //     give back a large share of the fix and no other case would notice.
    public static boolean passedAtBoolean(int p) {
        boolean b = true;
        if (p > 3) { b = false; }
        sinkBool(b);
        return b;
    }

    // M. Refused by `prim_use_vids` on the INVOKE-ARGUMENT arm only.  This is
    //    the position whose absence turned valid corpus Java into
    //    `setFlags(boolean)`; it had no committed-fixture case until a delta
    //    review showed the arm was revertible with the CI leg green.
    public static boolean passedAtInt(int p) {
        boolean b = true;
        if (p > 3) { b = false; }
        sinkInt(b ? 1 : 0);
        return b;
    }

    // N. Refused by `prim_use_vids` on the FILLED-NEW-ARRAY arm only — the
    //    FOURTH int-requiring position, found by a delta review after the other
    //    three were closed.  javac + d8 fold the ternary onto the flag's own
    //    register, so `new int[]{boolean}` needs no crafting at all.
    public static boolean fillArr(int p) {
        boolean b = true;
        if (p > 3) { b = false; }
        sinkArr(new int[]{ b ? 1 : 0 });
        return b;
    }

    // O. A WIDE parameter ahead of the flag.  `declared_params` advances the
    //    register by `GetTypeSize`, and nothing exercised that: a mutant using
    //    `+= 1` passed the whole suite while rendering `p3 = 1` here (the flag
    //    is `p3` — the `long` consumes two register slots ahead of it).
    public static boolean wideParam(long w, boolean q, int p) {
        boolean b = q;
        if (p > 3) { b = true; }
        ARR[0] = (int) w;
        return b;
    }

    // ---- controls that must NOT move --------------------------------------

    // D. An int method returning an int flag.  Identical bytecode shape to A;
    //    only the return type differs, so it is what separates "the rule reads
    //    the return type" from "the rule fires on any 0/1 register".
    public static int keepsInt(int p) {
        int n = 1;
        if (p > 3) { n = 0; }
        return n;
    }

    // E. An int method whose local is genuinely an int.
    public static int keepsArith(int p) {
        int n = 1;
        if (p > 3) { n = n + p; }
        return n;
    }

    // ---- craft bases: repointed to (I)Z by the guard -----------------------

    // Each craft base is refused by exactly ONE guard, so a mutant that deletes
    // that guard changes THIS method and nothing else.  A base that tripped two
    // guards at once would let either mutant survive — the first cut of this
    // file had that defect: `intUsed` below is refused by the def-anchor AND by
    // `int_use_vids`, so it is kept only for the def-anchor's arithmetic arm and
    // the two use guards get bases whose defs are 0/1 and therefore clean.

    // F. Refused by the DEF-ANCHOR only (an arithmetic def is not boolean).
    //    Its 0/1 sibling def is what makes the arithmetic one decisive.
    public static int intUsed(int p) {
        int n = 1;
        if (p > 3) { n = n + p; }
        return n;
    }

    // G. Refused by the DEF-ANCHOR only, on the CONSTANT arm: 5 is a genuine
    //    int, not a `true`.  Separates "any int constant" from "0 or 1".
    public static int notBoolean(int p) {
        int n = 5;
        if (p > 3) { n = 0; }
        return n;
    }

    // H. An ARRAY-INDEX use.  Note that an index lands in `int_use_vids` AND in
    //    `int_required_vids`, so this case cannot separate them — H2 below is
    //    what isolates the second, and the mutation matrix is what said so.
    public static int arrayIndex(int p) {
        int n = 1;
        if (p > 3) { n = 0; }
        ARR[n] = 7;
        return n;
    }

    // H2. Refused by `int_required_vids` ONLY.  An array-CREATION size and a
    //     `switch` selector are the two uses recorded there and NOWHERE else
    //     (`note_int` does not `add()` them), so deleting that guard changes
    //     this method and nothing else in the file.
    public static int newArraySize(int p) {
        int n = 1;
        if (p > 3) { n = 0; }
        ARR2 = new int[n];
        return n;
    }

    // I. Refused by `int_use_vids` ONLY — every def is 0/1 and the use is an
    //    ORDERED comparison, which `int_required_vids` does not cover.  The
    //    `==`/`!=` forms are deliberately excluded from that set, so a plain
    //    flag test must NOT land here; that is what method A checks.
    public static int cmpUsed(int p) {
        int n = 1;
        if (p > 3) { n = 0; }
        if (n < p) { ARR[0] = 7; }
        return n;
    }

    // K. Refused by `prim_use_vids` on the FIELD-STORE arm only: every def is
    //     0/1 and the sole reason is `IFIELD` being an `int`.
    public static int fieldStore(int p) {
        int n = 1;
        if (p > 3) { n = 0; }
        IFIELD = n;
        return n;
    }

    // K2. The INSTANCE-field form of K.  `iput` and `sput` are recorded by two
    //     separate arms, so a case using only a static field leaves the other
    //     unguarded — measured: the mutant that stops recording an `iput` value
    //     survived the whole file until this method existed.
    public int fieldStoreInstance(int p) {
        int n = 1;
        if (p > 3) { n = 0; }
        this.instField = n;
        return n;
    }

    // L. Refused by `prim_use_vids` on the ARRAY-STORE VALUE arm only.  Note
    //    the difference from H: there the register is the INDEX, here it is the
    //    stored VALUE, and only one of the two guards sees each.
    public static int arrayValue(int p) {
        int n = 1;
        if (p > 3) { n = 0; }
        ARR[0] = n;
        return n;
    }

    // J. A WIDE local.  Repointed, `is_narrow_int(cur)` must refuse it so a
    //    long can never be narrowed to a boolean.  `(I)J`, so the guard
    //    repoints it against the `(I)Z` proto the same way.
    public static long wide(int p) {
        long n = 1;
        if (p > 3) { n = 0; }
        return n;
    }
}
