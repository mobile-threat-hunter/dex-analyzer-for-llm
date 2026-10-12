# dexllm#94 fixture. Authored in smali: each shape needs a register that DAD's
# last-write typing leaves holding the WRONG width for one of its versions, and
# that depends on register reuse and block build order, which Java cannot pin.
.class public LIntReuse;
.super Ljava/lang/Object;

# POSITIVE. The corpus shape (LookupTableInterpolator.getInterpolation): an
# `I`-returning call into a register that is later reused for an `aget` off a
# float[], so the register's last write is a float. The result version's own
# def is the call; it is used as an array INDEX.
.method public static minIdx([FF)F
    .registers 5
    array-length v0, p0
    add-int/lit8 v1, v0, -0x1
    invoke-static {v1, v0}, Ljava/lang/Math;->min(II)I
    move-result v0
    aget v1, p0, v0
    add-float/2addr v1, p1
    aget v0, p0, v0
    add-float/2addr v1, v0
    return v1
.end method

# POSITIVE, and the one only the SplitVariables half can fix: the same call
# result used ONLY in int arithmetic (no index, switch or array size), so no
# use pins it an int. `float v0 = Math.min(..)` compiles; `v0 / 2` would then
# be FLOAT division, a wrong value rather than a compile error.
.method public static minHalf([FI)F
    .registers 4
    const/4 v0, 0x7
    invoke-static {p1, v0}, Ljava/lang/Math;->min(II)I
    move-result v0
    div-int/lit8 v1, v0, 0x2
    add-int/2addr v1, v0
    int-to-float v1, v1
    aget v0, p0, p1
    add-float/2addr v1, v0
    return v1
.end method

# POSITIVE. The QuantizerWu.createBoxes shape: v0 is ONE version (the const and
# the move both reach the index), so SplitVariables never re-types it, and the
# `move v0, v1` copies v1's type at BUILD time. The bfs builds `:exit` (which
# writes v1 from a `cmpg-double`, type D) before `:mv`, so v0 inherits D.
.method public static unsplitIdx([DIID)V
    .registers 8
    const/4 v0, 0x0
    const/4 v1, 0x1
    if-lez p1, :exit
    if-lez p2, :skip
    move v0, v1
    :skip
    aput-wide p3, p0, v0
    return-void
    :exit
    cmpg-double v1, p3, p3
    if-gez v1, :done
    :done
    return-void
.end method

# POSITIVE, the WIDTH half of the move opcode (ActionMenuView.onMeasureExactFormat
# shape). Both `move v0, v1` are PLAIN moves of the int 3, but the bfs builds the
# `int-to-long v1` block first, so each move copies v1's build-time type `J` and
# the version is declared `long` - then returned from an `int` method. A plain
# move copies 32 bits; its destination cannot be `long`. Two defs, so
# RegisterPropagation keeps the declaration.
.method public static plainWide([JII)I
    .registers 6
    const/4 v1, 0x3
    if-lez p1, :mv
    int-to-long v1, p1
    aput-wide v1, p0, p1
    const/4 v0, 0x0
    return v0
    :mv
    if-lez p2, :m2
    move v0, v1
    goto :use
    :m2
    move v0, v1
    :use
    add-int v2, v0, p2
    mul-int/2addr v2, v0
    return v2
.end method

# NEGATIVE (review-of-self: the first cut regressed corpus code this way). A
# `B`-returning call and an `int` producer reach ONE version; first-def-wins
# would type it `byte` and emit the narrowing `v = (v | (x << 7))` into a byte.
# The two narrow widths must JOIN to `int`.
.method public static joinBI(Ljava/lang/Byte;)I
    .registers 3
    invoke-virtual {p0}, Ljava/lang/Byte;->byteValue()B
    move-result v0
    if-gez v0, :done
    and-int/lit8 v0, v0, 0x7f
    shl-int/lit8 v1, v0, 0x7
    or-int/2addr v0, v1
    :done
    return v0
.end method

# NEGATIVE, lenient-only: a genuine `long` used as an index. Invalid Dalvik, so
# no compiler emits it; the narrowing branch must still leave it alone, because
# its defs resolve to `J`, not to an int width. Two defs, so RegisterPropagation
# cannot fold the constant into the index and leave nothing to type.
.method public static wideIdx([II)I
    .registers 5
    const-wide/16 v0, 0x5
    if-lez p1, :a
    const-wide/16 v0, 0x6
    :a
    aget v2, p0, v0
    return v2
.end method

# NEGATIVE (review-of-self, the corpus's MatcherMatchResult.contains). A `Z`
# producer and a 0/1 constant in ONE split version: first-def-wins keeps it
# `boolean`. `Z` is NOT in the narrow join, or this would become
# `int v = (p instanceof String)`.
.method public static instZ(Ljava/lang/Object;)I
    .registers 3
    if-nez p0, :i
    const/4 v0, 0x1
    goto :u
    :i
    instance-of v0, p0, Ljava/lang/String;
    :u
    if-eqz v0, :f
    const/4 v0, 0x7
    return v0
    :f
    const/4 v0, 0x0
    return v0
.end method

# NEGATIVE for the move-width rule: two plain moves whose SOURCES disagree (an
# `int` and a `float`), both of which copied a stale `long`. The value is a
# genuine int/float conflation, so no single 32-bit type is right and the rule
# must leave it - it re-types only when the sources agree.
.method public static mixW([JII)I
    .registers 7
    const/4 v1, 0x3
    int-to-float v2, p2
    if-lez p1, :mv
    int-to-long v1, p1
    aput-wide v1, p0, p1
    int-to-long v2, p1
    aput-wide v2, p0, p2
    const/4 v0, 0x0
    return v0
    :mv
    if-lez p2, :m2
    move v0, v1
    goto :use
    :m2
    move v0, v2
    :use
    add-int v3, v0, p2
    mul-int/2addr v3, v0
    return v3
.end method

# NEGATIVES (adversarial review). A `Z` call result and an `I` call result in
# ONE version, then used as an int: ART merges Boolean with Integer to Integer.
# First-def-wins picked by def ORDER, so the join must not - the two methods are
# the same bytecode with the paths swapped, and both must say `int`.
.method public static zMerge(Ljava/lang/String;Z[I)I
    .registers 5
    const/4 v0, 0x2
    aget v1, p2, v0
    if-eqz p1, :b
    invoke-virtual {p0}, Ljava/lang/String;->length()I
    move-result v0
    goto :u
    :b
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v0
    :u
    add-int/2addr v1, v0
    const/4 v0, 0x3
    aput v1, p2, v0
    return v1
.end method

.method public static zMergeSwap(Ljava/lang/String;Z[I)I
    .registers 5
    const/4 v0, 0x2
    aget v1, p2, v0
    if-eqz p1, :b
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v0
    goto :u
    :b
    invoke-virtual {p0}, Ljava/lang/String;->length()I
    move-result v0
    :u
    add-int/2addr v1, v0
    const/4 v0, 0x3
    aput v1, p2, v0
    return v1
.end method

# NEGATIVE (adversarial review). `byte` and `short` call results in one version:
# ART's merge is `short`, not `int` - `Short.valueOf(int)` does not compile.
.method public static bsMerge(Ljava/lang/Short;Ljava/lang/Byte;Z[S)V
    .registers 6
    const/4 v0, 0x2
    aget-short v1, p3, v0
    if-eqz p2, :b
    invoke-virtual {p0}, Ljava/lang/Short;->shortValue()S
    move-result v0
    goto :u
    :b
    invoke-virtual {p1}, Ljava/lang/Byte;->byteValue()B
    move-result v0
    :u
    invoke-static {v0}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;
    aget-short v0, p3, v1
    aput-short v0, p3, v1
    return-void
.end method

# POSITIVE, the int/float CLASS half of the move-width rule (ConstraintLayout's
# `float v22 = v1_6`). Two plain moves of the int 3, built after `int-to-float
# v1`, so the version copied `F` and rendered the 3 as `4.20389539e-45f` - a
# wrong VALUE. A plain move copies the source's bits AND its class.
.method public static plainClass([FII)I
    .registers 6
    const/4 v1, 0x3
    if-lez p1, :mv
    int-to-float v1, p1
    aput v1, p0, p1
    const/4 v0, 0x0
    return v0
    :mv
    if-lez p2, :m2
    move v0, v1
    goto :use
    :m2
    move v0, v1
    :use
    add-int v2, v0, p2
    mul-int/2addr v2, v0
    return v2
.end method

# POSITIVES (correctness review, Base64Coder.<clinit>). A constant is untyped in
# Dalvik, so it is NEUTRAL in the join: `const/16 v0, 65` beside an
# `int-to-char` is a `char` - an `int` here makes the `char[]` store a lossy
# conversion (OFF typed all three `int`: the constant came first). Only a value
# that does not FIT widens: 3 fits `byte`, 200 does not.
# Each has a second, separate def of v0 so the version is SPLIT - an unsplit
# register never reaches the join (and `byte v0 = 200` there is pre-existing).
.method public static charConst([CI)V
    .registers 4
    const/16 v0, 0x41
    :loop
    if-ge v0, p1, :done
    aput-char v0, p0, v0
    add-int/lit8 v1, v0, 0x1
    int-to-char v0, v1
    goto :loop
    :done
    const/4 v0, 0x1
    aput-char v0, p0, v0
    return-void
.end method

.method public static byteConstFit(Ljava/lang/Byte;Z)Ljava/lang/Byte;
    .registers 3
    const/4 v0, 0x3
    if-eqz p1, :u
    invoke-virtual {p0}, Ljava/lang/Byte;->byteValue()B
    move-result v0
    :u
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;
    move-result-object v1
    const/4 v0, 0x7
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;
    return-object v1
.end method

.method public static byteConstWide(Ljava/lang/Byte;Z)I
    .registers 3
    const/16 v0, 0xc8
    if-eqz p1, :u
    invoke-virtual {p0}, Ljava/lang/Byte;->byteValue()B
    move-result v0
    :u
    add-int v1, v0, v0
    const/4 v0, 0x7
    add-int/2addr v1, v0
    return v1
.end method

# NEGATIVE (correctness review): past `short` the widening goes to `int`.
# `byteConstWide`'s 200 widens `byte` only to `short` (ART's merge); 40000
# fits neither, so this one is `int`.
.method public static byteConstWider(Ljava/lang/Byte;Z)I
    .registers 3
    const v0, 0x9c40
    if-eqz p1, :u
    invoke-virtual {p0}, Ljava/lang/Byte;->byteValue()B
    move-result v0
    :u
    add-int v1, v0, v0
    const/4 v0, 0x7
    add-int/2addr v1, v0
    return v1
.end method

# ---------------------------------------------------------------------------
# The narrow-integral FORWARD DATAFLOW (boolean/byte/short/char/int decided over
# moves and bitwise ops, after every other re-type). Each shape is one a cut of
# the design got wrong on the corpus.
# ---------------------------------------------------------------------------
.field static sI:I

# POSITIVE: `flag |= cond` - a bitwise `or` of booleans is a boolean, so the
# result and its operands are typed together (OFF `int`, and `Boolean.valueOf`).
.method public static flagOr(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Boolean;
    .registers 4
    const/4 v0, 0x0
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v1
    or-int/2addr v0, v1
    invoke-virtual {p1}, Ljava/lang/String;->isEmpty()Z
    move-result v1
    or-int/2addr v0, v1
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v1
    return-object v1
.end method

# POSITIVE (ConstraintWidget.addToSolver): a `Z` result moved into a register
# that started at 0 - both ends are boolean (OFF `int`, passed at a `Z`).
.method public static zMoveChain(Ljava/lang/String;ZZ)Ljava/lang/Boolean;
    .registers 5
    const/4 v1, 0x0
    if-eqz p1, :a
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v0
    goto :b
    :a
    const/4 v0, 0x1
    :b
    if-eqz p2, :c
    move v1, v0
    :c
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v0
    return-object v0
.end method

# POSITIVE (CombineKt.combineInternal): an `int` field value moved in, then
# `int-to-byte` - the join is `int` (OFF `byte`, a lossy `v1 = v0`). A first cut
# that ignored move SOURCES picked `byte`.
.method public static intThroughMove(I)V
    .registers 4
    const/4 v1, 0x0
    :loop
    if-ge v1, p0, :done
    sget v0, LIntReuse;->sI:I
    if-lez v0, :inc
    move v1, v0
    :inc
    add-int/lit8 v2, v1, 0x1
    int-to-byte v1, v2
    sput v1, LIntReuse;->sI:I
    goto :loop
    :done
    return-void
.end method

# NEGATIVE (ToolbarActionBar.onKeyShortcut): the `0` passed at an `I` parameter
# and the `Z` result returned share a register. Only that constant reaches the
# argument - ART types a register per instruction - so it does not rule out
# `boolean`; a per-version rule turned this `int`.
.method public static shortcutFlag(Landroid/view/Menu;Landroid/view/KeyEvent;I)Z
    .registers 5
    const/4 v0, 0x0
    if-eqz p0, :done
    invoke-interface {p0, p2, p1, v0}, Landroid/view/Menu;->performShortcut(ILandroid/view/KeyEvent;I)Z
    move-result v0
    :done
    return v0
.end method

# POSITIVE (SwitchCompat.stopDrag): a 0/1 parked in its own register and moved
# into the flag takes the flag's type (OFF `int`).
.method public static parkedFlag(Ljava/lang/String;ZI)Ljava/lang/Boolean;
    .registers 6
    const/4 v1, 0x1
    if-ne p2, v1, :x
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v0
    if-eqz p1, :use
    const/4 v1, 0x0
    move v0, v1
    goto :use
    :x
    const/4 v0, 0x0
    :use
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v2
    return-object v2
.end method

# NEGATIVE (ClassesInfoCache.hasLifecycleMethods): a loop counter starts from
# the same `0` the boolean holds. Values flow FORWARD through a move, so the
# counter's int uses say nothing about the boolean; a union-by-component cut
# made it `int`.
.method public static loopFlag([Ljava/lang/Object;Ljava/lang/Boolean;)Z
    .registers 6
    const/4 v0, 0x0
    if-eqz p1, :scan
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z
    move-result v0
    goto :done
    :scan
    move v1, v0
    :loop
    array-length v2, p0
    if-ge v1, v2, :done
    aget-object v3, p0, v1
    if-eqz v3, :next
    const/4 v0, 0x1
    goto :done
    :next
    add-int/lit8 v1, v1, 0x1
    goto :loop
    :done
    return v0
.end method

# NEGATIVE: a `Z` result used as a NUMBER twice (ART allows add-int on a
# boolean; Java does not). `int` costs the one declaration, `boolean` both uses,
# so a numeric use refuses `Z`.
.method public static zArith(Ljava/lang/String;)I
    .registers 4
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v0
    add-int/lit8 v1, v0, 0x1
    mul-int/2addr v1, v0
    return v1
.end method

# NEGATIVE: `Z` and `I` call results merge to `int` whichever path comes first,
# with no numeric use to decide it (only `if-eqz`). Swapped twin below.
.method public static zMergeEq(Ljava/lang/String;Z)I
    .registers 4
    if-eqz p1, :b
    invoke-virtual {p0}, Ljava/lang/String;->length()I
    move-result v0
    goto :u
    :b
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v0
    :u
    if-eqz v0, :z
    const/4 v0, 0x7
    return v0
    :z
    const/4 v0, 0x3
    return v0
.end method

.method public static zMergeEqSwap(Ljava/lang/String;Z)I
    .registers 4
    if-eqz p1, :b
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v0
    goto :u
    :b
    invoke-virtual {p0}, Ljava/lang/String;->length()I
    move-result v0
    :u
    if-eqz v0, :z
    const/4 v0, 0x7
    return v0
    :z
    const/4 v0, 0x3
    return v0
.end method

# NEGATIVE (BackStackRecord.interactsWith, register for register): `move v0, v3`
# right after `const/4 v3, 0` copies a lone constant (rendered `v0 = 0`), so the
# `int` destination is no claim on the boolean result `v3`.
.method public static containerMatch([II)Z
    .registers 6
    const/4 v3, 0x0
    array-length v1, p0
    const/4 v2, 0x0
    :loop
    if-ge v2, v1, :ret
    aget v0, p0, v2
    :test
    if-eqz v0, :next
    if-ne v0, p1, :mv
    const/4 v3, 0x1
    :ret
    return v3
    :mv
    move v0, v3
    goto :test
    :next
    add-int/lit8 v2, v2, 0x1
    goto :loop
.end method

# POSITIVE (SwitchCompat.stopDrag, register for register): `v2` holds 1 or 0
# and is moved into the flag; its compare use only ever sees the lone `1`. The
# flag is boolean, so `v2` is too (OFF typed all of them `int`).
.method public static stopDrag(IZZFZ)Ljava/lang/Boolean;
    .registers 9
    const/4 v2, 0x1
    if-ne p0, v2, :notup
    move v1, p1
    goto :have
    :notup
    const/4 v1, 0x0
    :have
    move v3, p2
    if-eqz v1, :keep
    const/4 v0, 0x0
    cmpl-float v0, p3, v0
    if-lez v0, :target
    if-eqz p4, :ltr
    const/4 v2, 0x0
    :ltr
    move v1, v2
    goto :use
    :target
    move v1, p2
    goto :use
    :keep
    move v1, v3
    :use
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v0
    return-object v0
.end method

# POSITIVE (DependencyGraph.directMeasure): a `boolean` parameter whose register
# is written later in the method. The write corrupted the shared Variable before
# the parameter version was made, so `p0 & 1` read `int & int`; the parameter
# version takes its DECLARED type, and the `1` beside it is spelled `true`.
.method public static paramFlag(ZI)Ljava/lang/Boolean;
    .registers 4
    const/4 v0, 0x1
    and-int/2addr p0, v0
    if-eqz p0, :f
    const/4 p0, 0x0
    :f
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v1
    return-object v1
.end method

# A constant beside a NESTED bitwise of booleans is `true`: the rule recurses.
.method public static nestedFlag(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Boolean;
    .registers 4
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v0
    invoke-virtual {p1}, Ljava/lang/String;->isEmpty()Z
    move-result v1
    or-int/2addr v0, v1
    or-int/lit8 v0, v0, 0x1
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v1
    return-object v1
.end method

# NEGATIVE: a bitwise of constants alone is not boolean-valued, so the `1`
# beside it stays a number.
.method public static constOnly()I
    .registers 2
    const/4 v0, 0x0
    or-int/lit8 v0, v0, 0x1
    or-int/lit8 v0, v0, 0x1
    return v0
.end method

# NEGATIVE: only 0 and 1 are booleans; a `2` beside a boolean stays `2`.
.method public static zAndTwo(Ljava/lang/String;)I
    .registers 2
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v0
    and-int/lit8 v0, v0, 0x2
    return v0
.end method

# d8's `!b` at several boolean parameters: each `xor-int/lit8` defines its own
# version from the SAME source, so whatever order the dataflow visits them in,
# some come before the source is resolved — each must still come out `Z`.
.method public static manyNot(Ljava/lang/String;)V
    .registers 4
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v0
    xor-int/lit8 v1, v0, 0x1
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v1
    xor-int/lit8 v1, v0, 0x1
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v1
    xor-int/lit8 v1, v0, 0x1
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v1
    xor-int/lit8 v1, v0, 0x1
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v1
    xor-int/lit8 v1, v0, 0x1
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v1
    xor-int/lit8 v1, v0, 0x1
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v1
    xor-int/lit8 v1, v0, 0x1
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v1
    xor-int/lit8 v1, v0, 0x1
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v1
    xor-int/lit8 v1, v0, 0x1
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v1
    xor-int/lit8 v1, v0, 0x1
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v1
    xor-int/lit8 v1, v0, 0x1
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v1
    xor-int/lit8 v1, v0, 0x1
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v1
    return-void
.end method

# NEGATIVE (TransitionSet.getOrdering): d8's `b ? 0 : 1` returned from an `int`
# method is a NUMBER — the return rules `boolean` out, so the `1` stays `1`.
.method public static ordering(Ljava/lang/String;)I
    .registers 2
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v0
    xor-int/lit8 v0, v0, 0x1
    return v0
.end method

# A boolean xor tested by `if-eqz` is `!(a ^ b)`, not `(a ^ b) == 0`.
.method public static sameEmpty(Ljava/lang/String;Ljava/lang/String;)I
    .registers 4
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v0
    invoke-virtual {p1}, Ljava/lang/String;->isEmpty()Z
    move-result v1
    xor-int/2addr v0, v1
    if-eqz v0, :same
    const/4 v0, 0x2
    return v0
    :same
    const/4 v0, 0x3
    return v0
.end method

# A `boolean` parameter read UNWRITTEN keeps its declared type even though a
# later write to its register re-typed the shared Param: `if (!p1)`, not
# `if (p1 == 0)`.
.method public static paramCond(ZI)I
    .registers 3
    if-eqz p0, :l
    const/4 p0, 0x5
    add-int/2addr p0, p1
    return p0
    :l
    const/4 v0, 0x1
    return v0
.end method

# A CYCLE of constant-only versions (v0 <-> v1) has no producer to start
# from, so neither step types it; a version it flows into must agree with the
# type it keeps (ConstraintWidgetContainer.layout) - `int v2`, not a
# `boolean v2` assigned from an `int v0`.
.method public static cycleFlag(Ljava/lang/String;I)Ljava/lang/Boolean;
    .registers 5
    const/4 v0, 0x0
    :loop
    if-eqz p1, :done
    move v1, v0
    move v0, v1
    add-int/lit8 p1, p1, -0x1
    goto :loop
    :done
    if-nez p1, :other
    move v2, v0
    goto :out
    :other
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v2
    :out
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v3
    return-object v3
.end method
# A constant-like source with TWO uses is printed, not inlined, so a version
# it is moved into agrees with the type it is printed with
# (FragmentTransition): it is moved into a `boolean` and an array index.
.method public static sharedConst(Ljava/lang/String;Z[I)Ljava/lang/Boolean;
    .registers 6
    const/4 v0, 0x0
    if-eqz p1, :z
    const/4 v0, 0x1
    :z
    if-eqz p1, :b
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v1
    goto :j
    :b
    move v1, v0
    :j
    invoke-virtual {p0}, Ljava/lang/String;->length()I
    move-result v2
    if-eqz p1, :c
    move v2, v0
    :c
    aget v3, p2, v2
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v3
    return-object v3
.end method
# A 0/1 constant-like version tested by `if-eqz` and moved into a flag takes
# the flag's type: an `== 0` test does not rule `boolean` out
# (ExoPlayerImplInternal.doSomeWork).
.method public static testedFlag(Ljava/lang/String;Z)Ljava/lang/Boolean;
    .registers 5
    const/4 v0, 0x1
    if-eqz p1, :a
    const/4 v0, 0x0
    :a
    if-eqz v0, :skip
    invoke-virtual {p0}, Ljava/lang/String;->trim()Ljava/lang/String;
    :skip
    if-eqz p1, :b
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v1
    goto :j
    :b
    move v1, v0
    :j
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v2
    return-object v2
.end method

# POSITIVE (adversarial review). The compound-assignment form of a boolean
# bitwise op: `v0 = v0 ^ 1` renders `v0 ^= …`, and the 1 must be `true` there
# as in the binary form (`boolean ^= 1` does not compile). `and` with 0 too.
.method public static cmpXor(Ljava/lang/String;I)Z
    .registers 3
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v0
    if-lez p1, :skip
    xor-int/lit8 v0, v0, 0x1
    :skip
    return v0
.end method

.method public static cmpAnd(Ljava/lang/String;I)Z
    .registers 3
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v0
    if-lez p1, :skip
    and-int/lit8 v0, v0, 0x0
    :skip
    return v0
.end method

# RESOURCE (adversarial review). A ladder of 30 diamonds of constant-only
# moves. The constant-like summary must be a RANGE: a list of reaching values
# doubles at every level (2^30 entries here, far past any memory budget).
.method public static diamondLadder(I)I
    .registers 65
    const/4 v0, 0x0
    const/4 v1, 0x1
    if-eqz p0, :a1
    move/from16 v2, v0
    move/from16 v3, v1
    goto :j1
    :a1
    move/from16 v2, v1
    move/from16 v3, v0
    :j1
    if-eqz p0, :a2
    move/from16 v4, v2
    move/from16 v5, v3
    goto :j2
    :a2
    move/from16 v4, v3
    move/from16 v5, v2
    :j2
    if-eqz p0, :a3
    move/from16 v6, v4
    move/from16 v7, v5
    goto :j3
    :a3
    move/from16 v6, v5
    move/from16 v7, v4
    :j3
    if-eqz p0, :a4
    move/from16 v8, v6
    move/from16 v9, v7
    goto :j4
    :a4
    move/from16 v8, v7
    move/from16 v9, v6
    :j4
    if-eqz p0, :a5
    move/from16 v10, v8
    move/from16 v11, v9
    goto :j5
    :a5
    move/from16 v10, v9
    move/from16 v11, v8
    :j5
    if-eqz p0, :a6
    move/from16 v12, v10
    move/from16 v13, v11
    goto :j6
    :a6
    move/from16 v12, v11
    move/from16 v13, v10
    :j6
    if-eqz p0, :a7
    move/from16 v14, v12
    move/from16 v15, v13
    goto :j7
    :a7
    move/from16 v14, v13
    move/from16 v15, v12
    :j7
    if-eqz p0, :a8
    move/from16 v16, v14
    move/from16 v17, v15
    goto :j8
    :a8
    move/from16 v16, v15
    move/from16 v17, v14
    :j8
    if-eqz p0, :a9
    move/from16 v18, v16
    move/from16 v19, v17
    goto :j9
    :a9
    move/from16 v18, v17
    move/from16 v19, v16
    :j9
    if-eqz p0, :a10
    move/from16 v20, v18
    move/from16 v21, v19
    goto :j10
    :a10
    move/from16 v20, v19
    move/from16 v21, v18
    :j10
    if-eqz p0, :a11
    move/from16 v22, v20
    move/from16 v23, v21
    goto :j11
    :a11
    move/from16 v22, v21
    move/from16 v23, v20
    :j11
    if-eqz p0, :a12
    move/from16 v24, v22
    move/from16 v25, v23
    goto :j12
    :a12
    move/from16 v24, v23
    move/from16 v25, v22
    :j12
    if-eqz p0, :a13
    move/from16 v26, v24
    move/from16 v27, v25
    goto :j13
    :a13
    move/from16 v26, v25
    move/from16 v27, v24
    :j13
    if-eqz p0, :a14
    move/from16 v28, v26
    move/from16 v29, v27
    goto :j14
    :a14
    move/from16 v28, v27
    move/from16 v29, v26
    :j14
    if-eqz p0, :a15
    move/from16 v30, v28
    move/from16 v31, v29
    goto :j15
    :a15
    move/from16 v30, v29
    move/from16 v31, v28
    :j15
    if-eqz p0, :a16
    move/from16 v32, v30
    move/from16 v33, v31
    goto :j16
    :a16
    move/from16 v32, v31
    move/from16 v33, v30
    :j16
    if-eqz p0, :a17
    move/from16 v34, v32
    move/from16 v35, v33
    goto :j17
    :a17
    move/from16 v34, v33
    move/from16 v35, v32
    :j17
    if-eqz p0, :a18
    move/from16 v36, v34
    move/from16 v37, v35
    goto :j18
    :a18
    move/from16 v36, v35
    move/from16 v37, v34
    :j18
    if-eqz p0, :a19
    move/from16 v38, v36
    move/from16 v39, v37
    goto :j19
    :a19
    move/from16 v38, v37
    move/from16 v39, v36
    :j19
    if-eqz p0, :a20
    move/from16 v40, v38
    move/from16 v41, v39
    goto :j20
    :a20
    move/from16 v40, v39
    move/from16 v41, v38
    :j20
    if-eqz p0, :a21
    move/from16 v42, v40
    move/from16 v43, v41
    goto :j21
    :a21
    move/from16 v42, v41
    move/from16 v43, v40
    :j21
    if-eqz p0, :a22
    move/from16 v44, v42
    move/from16 v45, v43
    goto :j22
    :a22
    move/from16 v44, v43
    move/from16 v45, v42
    :j22
    if-eqz p0, :a23
    move/from16 v46, v44
    move/from16 v47, v45
    goto :j23
    :a23
    move/from16 v46, v45
    move/from16 v47, v44
    :j23
    if-eqz p0, :a24
    move/from16 v48, v46
    move/from16 v49, v47
    goto :j24
    :a24
    move/from16 v48, v47
    move/from16 v49, v46
    :j24
    if-eqz p0, :a25
    move/from16 v50, v48
    move/from16 v51, v49
    goto :j25
    :a25
    move/from16 v50, v49
    move/from16 v51, v48
    :j25
    if-eqz p0, :a26
    move/from16 v52, v50
    move/from16 v53, v51
    goto :j26
    :a26
    move/from16 v52, v51
    move/from16 v53, v50
    :j26
    if-eqz p0, :a27
    move/from16 v54, v52
    move/from16 v55, v53
    goto :j27
    :a27
    move/from16 v54, v53
    move/from16 v55, v52
    :j27
    if-eqz p0, :a28
    move/from16 v56, v54
    move/from16 v57, v55
    goto :j28
    :a28
    move/from16 v56, v55
    move/from16 v57, v54
    :j28
    if-eqz p0, :a29
    move/from16 v58, v56
    move/from16 v59, v57
    goto :j29
    :a29
    move/from16 v58, v57
    move/from16 v59, v56
    :j29
    if-eqz p0, :a30
    move/from16 v60, v58
    move/from16 v61, v59
    goto :j30
    :a30
    move/from16 v60, v59
    move/from16 v61, v58
    :j30
    move/from16 v62, v60
    add-int/lit8 v62, v62, 0x1
    move/from16 v0, v62
    return v0
.end method

# CONVERGENCE (adversarial review). A ladder of 300 diamonds moving two
# `!isEmpty()` flags between registers, returned from a `Z` method. Every
# version is a boolean; a round-capped round-robin stopped part-way and left
# `boolean`/`int` disagreeing across a move.
.method public static boolLadder(Ljava/lang/String;I)Z
    .registers 620
    move/16 v2, v619
    invoke-virtual/range {v618 .. v618}, Ljava/lang/String;->isEmpty()Z
    move-result v0
    xor-int/lit8 v0, v0, 0x1
    invoke-virtual/range {v618 .. v618}, Ljava/lang/String;->isBlank()Z
    move-result v1
    xor-int/lit8 v1, v1, 0x1
    move/16 v16, v0
    move/16 v17, v1
    if-eqz v2, :b1
    move/16 v18, v16
    move/16 v19, v17
    goto :k1
    :b1
    move/16 v18, v17
    move/16 v19, v16
    :k1
    if-eqz v2, :b2
    move/16 v20, v18
    move/16 v21, v19
    goto :k2
    :b2
    move/16 v20, v19
    move/16 v21, v18
    :k2
    if-eqz v2, :b3
    move/16 v22, v20
    move/16 v23, v21
    goto :k3
    :b3
    move/16 v22, v21
    move/16 v23, v20
    :k3
    if-eqz v2, :b4
    move/16 v24, v22
    move/16 v25, v23
    goto :k4
    :b4
    move/16 v24, v23
    move/16 v25, v22
    :k4
    if-eqz v2, :b5
    move/16 v26, v24
    move/16 v27, v25
    goto :k5
    :b5
    move/16 v26, v25
    move/16 v27, v24
    :k5
    if-eqz v2, :b6
    move/16 v28, v26
    move/16 v29, v27
    goto :k6
    :b6
    move/16 v28, v27
    move/16 v29, v26
    :k6
    if-eqz v2, :b7
    move/16 v30, v28
    move/16 v31, v29
    goto :k7
    :b7
    move/16 v30, v29
    move/16 v31, v28
    :k7
    if-eqz v2, :b8
    move/16 v32, v30
    move/16 v33, v31
    goto :k8
    :b8
    move/16 v32, v31
    move/16 v33, v30
    :k8
    if-eqz v2, :b9
    move/16 v34, v32
    move/16 v35, v33
    goto :k9
    :b9
    move/16 v34, v33
    move/16 v35, v32
    :k9
    if-eqz v2, :b10
    move/16 v36, v34
    move/16 v37, v35
    goto :k10
    :b10
    move/16 v36, v35
    move/16 v37, v34
    :k10
    if-eqz v2, :b11
    move/16 v38, v36
    move/16 v39, v37
    goto :k11
    :b11
    move/16 v38, v37
    move/16 v39, v36
    :k11
    if-eqz v2, :b12
    move/16 v40, v38
    move/16 v41, v39
    goto :k12
    :b12
    move/16 v40, v39
    move/16 v41, v38
    :k12
    if-eqz v2, :b13
    move/16 v42, v40
    move/16 v43, v41
    goto :k13
    :b13
    move/16 v42, v41
    move/16 v43, v40
    :k13
    if-eqz v2, :b14
    move/16 v44, v42
    move/16 v45, v43
    goto :k14
    :b14
    move/16 v44, v43
    move/16 v45, v42
    :k14
    if-eqz v2, :b15
    move/16 v46, v44
    move/16 v47, v45
    goto :k15
    :b15
    move/16 v46, v45
    move/16 v47, v44
    :k15
    if-eqz v2, :b16
    move/16 v48, v46
    move/16 v49, v47
    goto :k16
    :b16
    move/16 v48, v47
    move/16 v49, v46
    :k16
    if-eqz v2, :b17
    move/16 v50, v48
    move/16 v51, v49
    goto :k17
    :b17
    move/16 v50, v49
    move/16 v51, v48
    :k17
    if-eqz v2, :b18
    move/16 v52, v50
    move/16 v53, v51
    goto :k18
    :b18
    move/16 v52, v51
    move/16 v53, v50
    :k18
    if-eqz v2, :b19
    move/16 v54, v52
    move/16 v55, v53
    goto :k19
    :b19
    move/16 v54, v53
    move/16 v55, v52
    :k19
    if-eqz v2, :b20
    move/16 v56, v54
    move/16 v57, v55
    goto :k20
    :b20
    move/16 v56, v55
    move/16 v57, v54
    :k20
    if-eqz v2, :b21
    move/16 v58, v56
    move/16 v59, v57
    goto :k21
    :b21
    move/16 v58, v57
    move/16 v59, v56
    :k21
    if-eqz v2, :b22
    move/16 v60, v58
    move/16 v61, v59
    goto :k22
    :b22
    move/16 v60, v59
    move/16 v61, v58
    :k22
    if-eqz v2, :b23
    move/16 v62, v60
    move/16 v63, v61
    goto :k23
    :b23
    move/16 v62, v61
    move/16 v63, v60
    :k23
    if-eqz v2, :b24
    move/16 v64, v62
    move/16 v65, v63
    goto :k24
    :b24
    move/16 v64, v63
    move/16 v65, v62
    :k24
    if-eqz v2, :b25
    move/16 v66, v64
    move/16 v67, v65
    goto :k25
    :b25
    move/16 v66, v65
    move/16 v67, v64
    :k25
    if-eqz v2, :b26
    move/16 v68, v66
    move/16 v69, v67
    goto :k26
    :b26
    move/16 v68, v67
    move/16 v69, v66
    :k26
    if-eqz v2, :b27
    move/16 v70, v68
    move/16 v71, v69
    goto :k27
    :b27
    move/16 v70, v69
    move/16 v71, v68
    :k27
    if-eqz v2, :b28
    move/16 v72, v70
    move/16 v73, v71
    goto :k28
    :b28
    move/16 v72, v71
    move/16 v73, v70
    :k28
    if-eqz v2, :b29
    move/16 v74, v72
    move/16 v75, v73
    goto :k29
    :b29
    move/16 v74, v73
    move/16 v75, v72
    :k29
    if-eqz v2, :b30
    move/16 v76, v74
    move/16 v77, v75
    goto :k30
    :b30
    move/16 v76, v75
    move/16 v77, v74
    :k30
    if-eqz v2, :b31
    move/16 v78, v76
    move/16 v79, v77
    goto :k31
    :b31
    move/16 v78, v77
    move/16 v79, v76
    :k31
    if-eqz v2, :b32
    move/16 v80, v78
    move/16 v81, v79
    goto :k32
    :b32
    move/16 v80, v79
    move/16 v81, v78
    :k32
    if-eqz v2, :b33
    move/16 v82, v80
    move/16 v83, v81
    goto :k33
    :b33
    move/16 v82, v81
    move/16 v83, v80
    :k33
    if-eqz v2, :b34
    move/16 v84, v82
    move/16 v85, v83
    goto :k34
    :b34
    move/16 v84, v83
    move/16 v85, v82
    :k34
    if-eqz v2, :b35
    move/16 v86, v84
    move/16 v87, v85
    goto :k35
    :b35
    move/16 v86, v85
    move/16 v87, v84
    :k35
    if-eqz v2, :b36
    move/16 v88, v86
    move/16 v89, v87
    goto :k36
    :b36
    move/16 v88, v87
    move/16 v89, v86
    :k36
    if-eqz v2, :b37
    move/16 v90, v88
    move/16 v91, v89
    goto :k37
    :b37
    move/16 v90, v89
    move/16 v91, v88
    :k37
    if-eqz v2, :b38
    move/16 v92, v90
    move/16 v93, v91
    goto :k38
    :b38
    move/16 v92, v91
    move/16 v93, v90
    :k38
    if-eqz v2, :b39
    move/16 v94, v92
    move/16 v95, v93
    goto :k39
    :b39
    move/16 v94, v93
    move/16 v95, v92
    :k39
    if-eqz v2, :b40
    move/16 v96, v94
    move/16 v97, v95
    goto :k40
    :b40
    move/16 v96, v95
    move/16 v97, v94
    :k40
    if-eqz v2, :b41
    move/16 v98, v96
    move/16 v99, v97
    goto :k41
    :b41
    move/16 v98, v97
    move/16 v99, v96
    :k41
    if-eqz v2, :b42
    move/16 v100, v98
    move/16 v101, v99
    goto :k42
    :b42
    move/16 v100, v99
    move/16 v101, v98
    :k42
    if-eqz v2, :b43
    move/16 v102, v100
    move/16 v103, v101
    goto :k43
    :b43
    move/16 v102, v101
    move/16 v103, v100
    :k43
    if-eqz v2, :b44
    move/16 v104, v102
    move/16 v105, v103
    goto :k44
    :b44
    move/16 v104, v103
    move/16 v105, v102
    :k44
    if-eqz v2, :b45
    move/16 v106, v104
    move/16 v107, v105
    goto :k45
    :b45
    move/16 v106, v105
    move/16 v107, v104
    :k45
    if-eqz v2, :b46
    move/16 v108, v106
    move/16 v109, v107
    goto :k46
    :b46
    move/16 v108, v107
    move/16 v109, v106
    :k46
    if-eqz v2, :b47
    move/16 v110, v108
    move/16 v111, v109
    goto :k47
    :b47
    move/16 v110, v109
    move/16 v111, v108
    :k47
    if-eqz v2, :b48
    move/16 v112, v110
    move/16 v113, v111
    goto :k48
    :b48
    move/16 v112, v111
    move/16 v113, v110
    :k48
    if-eqz v2, :b49
    move/16 v114, v112
    move/16 v115, v113
    goto :k49
    :b49
    move/16 v114, v113
    move/16 v115, v112
    :k49
    if-eqz v2, :b50
    move/16 v116, v114
    move/16 v117, v115
    goto :k50
    :b50
    move/16 v116, v115
    move/16 v117, v114
    :k50
    if-eqz v2, :b51
    move/16 v118, v116
    move/16 v119, v117
    goto :k51
    :b51
    move/16 v118, v117
    move/16 v119, v116
    :k51
    if-eqz v2, :b52
    move/16 v120, v118
    move/16 v121, v119
    goto :k52
    :b52
    move/16 v120, v119
    move/16 v121, v118
    :k52
    if-eqz v2, :b53
    move/16 v122, v120
    move/16 v123, v121
    goto :k53
    :b53
    move/16 v122, v121
    move/16 v123, v120
    :k53
    if-eqz v2, :b54
    move/16 v124, v122
    move/16 v125, v123
    goto :k54
    :b54
    move/16 v124, v123
    move/16 v125, v122
    :k54
    if-eqz v2, :b55
    move/16 v126, v124
    move/16 v127, v125
    goto :k55
    :b55
    move/16 v126, v125
    move/16 v127, v124
    :k55
    if-eqz v2, :b56
    move/16 v128, v126
    move/16 v129, v127
    goto :k56
    :b56
    move/16 v128, v127
    move/16 v129, v126
    :k56
    if-eqz v2, :b57
    move/16 v130, v128
    move/16 v131, v129
    goto :k57
    :b57
    move/16 v130, v129
    move/16 v131, v128
    :k57
    if-eqz v2, :b58
    move/16 v132, v130
    move/16 v133, v131
    goto :k58
    :b58
    move/16 v132, v131
    move/16 v133, v130
    :k58
    if-eqz v2, :b59
    move/16 v134, v132
    move/16 v135, v133
    goto :k59
    :b59
    move/16 v134, v133
    move/16 v135, v132
    :k59
    if-eqz v2, :b60
    move/16 v136, v134
    move/16 v137, v135
    goto :k60
    :b60
    move/16 v136, v135
    move/16 v137, v134
    :k60
    if-eqz v2, :b61
    move/16 v138, v136
    move/16 v139, v137
    goto :k61
    :b61
    move/16 v138, v137
    move/16 v139, v136
    :k61
    if-eqz v2, :b62
    move/16 v140, v138
    move/16 v141, v139
    goto :k62
    :b62
    move/16 v140, v139
    move/16 v141, v138
    :k62
    if-eqz v2, :b63
    move/16 v142, v140
    move/16 v143, v141
    goto :k63
    :b63
    move/16 v142, v141
    move/16 v143, v140
    :k63
    if-eqz v2, :b64
    move/16 v144, v142
    move/16 v145, v143
    goto :k64
    :b64
    move/16 v144, v143
    move/16 v145, v142
    :k64
    if-eqz v2, :b65
    move/16 v146, v144
    move/16 v147, v145
    goto :k65
    :b65
    move/16 v146, v145
    move/16 v147, v144
    :k65
    if-eqz v2, :b66
    move/16 v148, v146
    move/16 v149, v147
    goto :k66
    :b66
    move/16 v148, v147
    move/16 v149, v146
    :k66
    if-eqz v2, :b67
    move/16 v150, v148
    move/16 v151, v149
    goto :k67
    :b67
    move/16 v150, v149
    move/16 v151, v148
    :k67
    if-eqz v2, :b68
    move/16 v152, v150
    move/16 v153, v151
    goto :k68
    :b68
    move/16 v152, v151
    move/16 v153, v150
    :k68
    if-eqz v2, :b69
    move/16 v154, v152
    move/16 v155, v153
    goto :k69
    :b69
    move/16 v154, v153
    move/16 v155, v152
    :k69
    if-eqz v2, :b70
    move/16 v156, v154
    move/16 v157, v155
    goto :k70
    :b70
    move/16 v156, v155
    move/16 v157, v154
    :k70
    if-eqz v2, :b71
    move/16 v158, v156
    move/16 v159, v157
    goto :k71
    :b71
    move/16 v158, v157
    move/16 v159, v156
    :k71
    if-eqz v2, :b72
    move/16 v160, v158
    move/16 v161, v159
    goto :k72
    :b72
    move/16 v160, v159
    move/16 v161, v158
    :k72
    if-eqz v2, :b73
    move/16 v162, v160
    move/16 v163, v161
    goto :k73
    :b73
    move/16 v162, v161
    move/16 v163, v160
    :k73
    if-eqz v2, :b74
    move/16 v164, v162
    move/16 v165, v163
    goto :k74
    :b74
    move/16 v164, v163
    move/16 v165, v162
    :k74
    if-eqz v2, :b75
    move/16 v166, v164
    move/16 v167, v165
    goto :k75
    :b75
    move/16 v166, v165
    move/16 v167, v164
    :k75
    if-eqz v2, :b76
    move/16 v168, v166
    move/16 v169, v167
    goto :k76
    :b76
    move/16 v168, v167
    move/16 v169, v166
    :k76
    if-eqz v2, :b77
    move/16 v170, v168
    move/16 v171, v169
    goto :k77
    :b77
    move/16 v170, v169
    move/16 v171, v168
    :k77
    if-eqz v2, :b78
    move/16 v172, v170
    move/16 v173, v171
    goto :k78
    :b78
    move/16 v172, v171
    move/16 v173, v170
    :k78
    if-eqz v2, :b79
    move/16 v174, v172
    move/16 v175, v173
    goto :k79
    :b79
    move/16 v174, v173
    move/16 v175, v172
    :k79
    if-eqz v2, :b80
    move/16 v176, v174
    move/16 v177, v175
    goto :k80
    :b80
    move/16 v176, v175
    move/16 v177, v174
    :k80
    if-eqz v2, :b81
    move/16 v178, v176
    move/16 v179, v177
    goto :k81
    :b81
    move/16 v178, v177
    move/16 v179, v176
    :k81
    if-eqz v2, :b82
    move/16 v180, v178
    move/16 v181, v179
    goto :k82
    :b82
    move/16 v180, v179
    move/16 v181, v178
    :k82
    if-eqz v2, :b83
    move/16 v182, v180
    move/16 v183, v181
    goto :k83
    :b83
    move/16 v182, v181
    move/16 v183, v180
    :k83
    if-eqz v2, :b84
    move/16 v184, v182
    move/16 v185, v183
    goto :k84
    :b84
    move/16 v184, v183
    move/16 v185, v182
    :k84
    if-eqz v2, :b85
    move/16 v186, v184
    move/16 v187, v185
    goto :k85
    :b85
    move/16 v186, v185
    move/16 v187, v184
    :k85
    if-eqz v2, :b86
    move/16 v188, v186
    move/16 v189, v187
    goto :k86
    :b86
    move/16 v188, v187
    move/16 v189, v186
    :k86
    if-eqz v2, :b87
    move/16 v190, v188
    move/16 v191, v189
    goto :k87
    :b87
    move/16 v190, v189
    move/16 v191, v188
    :k87
    if-eqz v2, :b88
    move/16 v192, v190
    move/16 v193, v191
    goto :k88
    :b88
    move/16 v192, v191
    move/16 v193, v190
    :k88
    if-eqz v2, :b89
    move/16 v194, v192
    move/16 v195, v193
    goto :k89
    :b89
    move/16 v194, v193
    move/16 v195, v192
    :k89
    if-eqz v2, :b90
    move/16 v196, v194
    move/16 v197, v195
    goto :k90
    :b90
    move/16 v196, v195
    move/16 v197, v194
    :k90
    if-eqz v2, :b91
    move/16 v198, v196
    move/16 v199, v197
    goto :k91
    :b91
    move/16 v198, v197
    move/16 v199, v196
    :k91
    if-eqz v2, :b92
    move/16 v200, v198
    move/16 v201, v199
    goto :k92
    :b92
    move/16 v200, v199
    move/16 v201, v198
    :k92
    if-eqz v2, :b93
    move/16 v202, v200
    move/16 v203, v201
    goto :k93
    :b93
    move/16 v202, v201
    move/16 v203, v200
    :k93
    if-eqz v2, :b94
    move/16 v204, v202
    move/16 v205, v203
    goto :k94
    :b94
    move/16 v204, v203
    move/16 v205, v202
    :k94
    if-eqz v2, :b95
    move/16 v206, v204
    move/16 v207, v205
    goto :k95
    :b95
    move/16 v206, v205
    move/16 v207, v204
    :k95
    if-eqz v2, :b96
    move/16 v208, v206
    move/16 v209, v207
    goto :k96
    :b96
    move/16 v208, v207
    move/16 v209, v206
    :k96
    if-eqz v2, :b97
    move/16 v210, v208
    move/16 v211, v209
    goto :k97
    :b97
    move/16 v210, v209
    move/16 v211, v208
    :k97
    if-eqz v2, :b98
    move/16 v212, v210
    move/16 v213, v211
    goto :k98
    :b98
    move/16 v212, v211
    move/16 v213, v210
    :k98
    if-eqz v2, :b99
    move/16 v214, v212
    move/16 v215, v213
    goto :k99
    :b99
    move/16 v214, v213
    move/16 v215, v212
    :k99
    if-eqz v2, :b100
    move/16 v216, v214
    move/16 v217, v215
    goto :k100
    :b100
    move/16 v216, v215
    move/16 v217, v214
    :k100
    if-eqz v2, :b101
    move/16 v218, v216
    move/16 v219, v217
    goto :k101
    :b101
    move/16 v218, v217
    move/16 v219, v216
    :k101
    if-eqz v2, :b102
    move/16 v220, v218
    move/16 v221, v219
    goto :k102
    :b102
    move/16 v220, v219
    move/16 v221, v218
    :k102
    if-eqz v2, :b103
    move/16 v222, v220
    move/16 v223, v221
    goto :k103
    :b103
    move/16 v222, v221
    move/16 v223, v220
    :k103
    if-eqz v2, :b104
    move/16 v224, v222
    move/16 v225, v223
    goto :k104
    :b104
    move/16 v224, v223
    move/16 v225, v222
    :k104
    if-eqz v2, :b105
    move/16 v226, v224
    move/16 v227, v225
    goto :k105
    :b105
    move/16 v226, v225
    move/16 v227, v224
    :k105
    if-eqz v2, :b106
    move/16 v228, v226
    move/16 v229, v227
    goto :k106
    :b106
    move/16 v228, v227
    move/16 v229, v226
    :k106
    if-eqz v2, :b107
    move/16 v230, v228
    move/16 v231, v229
    goto :k107
    :b107
    move/16 v230, v229
    move/16 v231, v228
    :k107
    if-eqz v2, :b108
    move/16 v232, v230
    move/16 v233, v231
    goto :k108
    :b108
    move/16 v232, v231
    move/16 v233, v230
    :k108
    if-eqz v2, :b109
    move/16 v234, v232
    move/16 v235, v233
    goto :k109
    :b109
    move/16 v234, v233
    move/16 v235, v232
    :k109
    if-eqz v2, :b110
    move/16 v236, v234
    move/16 v237, v235
    goto :k110
    :b110
    move/16 v236, v235
    move/16 v237, v234
    :k110
    if-eqz v2, :b111
    move/16 v238, v236
    move/16 v239, v237
    goto :k111
    :b111
    move/16 v238, v237
    move/16 v239, v236
    :k111
    if-eqz v2, :b112
    move/16 v240, v238
    move/16 v241, v239
    goto :k112
    :b112
    move/16 v240, v239
    move/16 v241, v238
    :k112
    if-eqz v2, :b113
    move/16 v242, v240
    move/16 v243, v241
    goto :k113
    :b113
    move/16 v242, v241
    move/16 v243, v240
    :k113
    if-eqz v2, :b114
    move/16 v244, v242
    move/16 v245, v243
    goto :k114
    :b114
    move/16 v244, v243
    move/16 v245, v242
    :k114
    if-eqz v2, :b115
    move/16 v246, v244
    move/16 v247, v245
    goto :k115
    :b115
    move/16 v246, v245
    move/16 v247, v244
    :k115
    if-eqz v2, :b116
    move/16 v248, v246
    move/16 v249, v247
    goto :k116
    :b116
    move/16 v248, v247
    move/16 v249, v246
    :k116
    if-eqz v2, :b117
    move/16 v250, v248
    move/16 v251, v249
    goto :k117
    :b117
    move/16 v250, v249
    move/16 v251, v248
    :k117
    if-eqz v2, :b118
    move/16 v252, v250
    move/16 v253, v251
    goto :k118
    :b118
    move/16 v252, v251
    move/16 v253, v250
    :k118
    if-eqz v2, :b119
    move/16 v254, v252
    move/16 v255, v253
    goto :k119
    :b119
    move/16 v254, v253
    move/16 v255, v252
    :k119
    if-eqz v2, :b120
    move/16 v256, v254
    move/16 v257, v255
    goto :k120
    :b120
    move/16 v256, v255
    move/16 v257, v254
    :k120
    if-eqz v2, :b121
    move/16 v258, v256
    move/16 v259, v257
    goto :k121
    :b121
    move/16 v258, v257
    move/16 v259, v256
    :k121
    if-eqz v2, :b122
    move/16 v260, v258
    move/16 v261, v259
    goto :k122
    :b122
    move/16 v260, v259
    move/16 v261, v258
    :k122
    if-eqz v2, :b123
    move/16 v262, v260
    move/16 v263, v261
    goto :k123
    :b123
    move/16 v262, v261
    move/16 v263, v260
    :k123
    if-eqz v2, :b124
    move/16 v264, v262
    move/16 v265, v263
    goto :k124
    :b124
    move/16 v264, v263
    move/16 v265, v262
    :k124
    if-eqz v2, :b125
    move/16 v266, v264
    move/16 v267, v265
    goto :k125
    :b125
    move/16 v266, v265
    move/16 v267, v264
    :k125
    if-eqz v2, :b126
    move/16 v268, v266
    move/16 v269, v267
    goto :k126
    :b126
    move/16 v268, v267
    move/16 v269, v266
    :k126
    if-eqz v2, :b127
    move/16 v270, v268
    move/16 v271, v269
    goto :k127
    :b127
    move/16 v270, v269
    move/16 v271, v268
    :k127
    if-eqz v2, :b128
    move/16 v272, v270
    move/16 v273, v271
    goto :k128
    :b128
    move/16 v272, v271
    move/16 v273, v270
    :k128
    if-eqz v2, :b129
    move/16 v274, v272
    move/16 v275, v273
    goto :k129
    :b129
    move/16 v274, v273
    move/16 v275, v272
    :k129
    if-eqz v2, :b130
    move/16 v276, v274
    move/16 v277, v275
    goto :k130
    :b130
    move/16 v276, v275
    move/16 v277, v274
    :k130
    if-eqz v2, :b131
    move/16 v278, v276
    move/16 v279, v277
    goto :k131
    :b131
    move/16 v278, v277
    move/16 v279, v276
    :k131
    if-eqz v2, :b132
    move/16 v280, v278
    move/16 v281, v279
    goto :k132
    :b132
    move/16 v280, v279
    move/16 v281, v278
    :k132
    if-eqz v2, :b133
    move/16 v282, v280
    move/16 v283, v281
    goto :k133
    :b133
    move/16 v282, v281
    move/16 v283, v280
    :k133
    if-eqz v2, :b134
    move/16 v284, v282
    move/16 v285, v283
    goto :k134
    :b134
    move/16 v284, v283
    move/16 v285, v282
    :k134
    if-eqz v2, :b135
    move/16 v286, v284
    move/16 v287, v285
    goto :k135
    :b135
    move/16 v286, v285
    move/16 v287, v284
    :k135
    if-eqz v2, :b136
    move/16 v288, v286
    move/16 v289, v287
    goto :k136
    :b136
    move/16 v288, v287
    move/16 v289, v286
    :k136
    if-eqz v2, :b137
    move/16 v290, v288
    move/16 v291, v289
    goto :k137
    :b137
    move/16 v290, v289
    move/16 v291, v288
    :k137
    if-eqz v2, :b138
    move/16 v292, v290
    move/16 v293, v291
    goto :k138
    :b138
    move/16 v292, v291
    move/16 v293, v290
    :k138
    if-eqz v2, :b139
    move/16 v294, v292
    move/16 v295, v293
    goto :k139
    :b139
    move/16 v294, v293
    move/16 v295, v292
    :k139
    if-eqz v2, :b140
    move/16 v296, v294
    move/16 v297, v295
    goto :k140
    :b140
    move/16 v296, v295
    move/16 v297, v294
    :k140
    if-eqz v2, :b141
    move/16 v298, v296
    move/16 v299, v297
    goto :k141
    :b141
    move/16 v298, v297
    move/16 v299, v296
    :k141
    if-eqz v2, :b142
    move/16 v300, v298
    move/16 v301, v299
    goto :k142
    :b142
    move/16 v300, v299
    move/16 v301, v298
    :k142
    if-eqz v2, :b143
    move/16 v302, v300
    move/16 v303, v301
    goto :k143
    :b143
    move/16 v302, v301
    move/16 v303, v300
    :k143
    if-eqz v2, :b144
    move/16 v304, v302
    move/16 v305, v303
    goto :k144
    :b144
    move/16 v304, v303
    move/16 v305, v302
    :k144
    if-eqz v2, :b145
    move/16 v306, v304
    move/16 v307, v305
    goto :k145
    :b145
    move/16 v306, v305
    move/16 v307, v304
    :k145
    if-eqz v2, :b146
    move/16 v308, v306
    move/16 v309, v307
    goto :k146
    :b146
    move/16 v308, v307
    move/16 v309, v306
    :k146
    if-eqz v2, :b147
    move/16 v310, v308
    move/16 v311, v309
    goto :k147
    :b147
    move/16 v310, v309
    move/16 v311, v308
    :k147
    if-eqz v2, :b148
    move/16 v312, v310
    move/16 v313, v311
    goto :k148
    :b148
    move/16 v312, v311
    move/16 v313, v310
    :k148
    if-eqz v2, :b149
    move/16 v314, v312
    move/16 v315, v313
    goto :k149
    :b149
    move/16 v314, v313
    move/16 v315, v312
    :k149
    if-eqz v2, :b150
    move/16 v316, v314
    move/16 v317, v315
    goto :k150
    :b150
    move/16 v316, v315
    move/16 v317, v314
    :k150
    if-eqz v2, :b151
    move/16 v318, v316
    move/16 v319, v317
    goto :k151
    :b151
    move/16 v318, v317
    move/16 v319, v316
    :k151
    if-eqz v2, :b152
    move/16 v320, v318
    move/16 v321, v319
    goto :k152
    :b152
    move/16 v320, v319
    move/16 v321, v318
    :k152
    if-eqz v2, :b153
    move/16 v322, v320
    move/16 v323, v321
    goto :k153
    :b153
    move/16 v322, v321
    move/16 v323, v320
    :k153
    if-eqz v2, :b154
    move/16 v324, v322
    move/16 v325, v323
    goto :k154
    :b154
    move/16 v324, v323
    move/16 v325, v322
    :k154
    if-eqz v2, :b155
    move/16 v326, v324
    move/16 v327, v325
    goto :k155
    :b155
    move/16 v326, v325
    move/16 v327, v324
    :k155
    if-eqz v2, :b156
    move/16 v328, v326
    move/16 v329, v327
    goto :k156
    :b156
    move/16 v328, v327
    move/16 v329, v326
    :k156
    if-eqz v2, :b157
    move/16 v330, v328
    move/16 v331, v329
    goto :k157
    :b157
    move/16 v330, v329
    move/16 v331, v328
    :k157
    if-eqz v2, :b158
    move/16 v332, v330
    move/16 v333, v331
    goto :k158
    :b158
    move/16 v332, v331
    move/16 v333, v330
    :k158
    if-eqz v2, :b159
    move/16 v334, v332
    move/16 v335, v333
    goto :k159
    :b159
    move/16 v334, v333
    move/16 v335, v332
    :k159
    if-eqz v2, :b160
    move/16 v336, v334
    move/16 v337, v335
    goto :k160
    :b160
    move/16 v336, v335
    move/16 v337, v334
    :k160
    if-eqz v2, :b161
    move/16 v338, v336
    move/16 v339, v337
    goto :k161
    :b161
    move/16 v338, v337
    move/16 v339, v336
    :k161
    if-eqz v2, :b162
    move/16 v340, v338
    move/16 v341, v339
    goto :k162
    :b162
    move/16 v340, v339
    move/16 v341, v338
    :k162
    if-eqz v2, :b163
    move/16 v342, v340
    move/16 v343, v341
    goto :k163
    :b163
    move/16 v342, v341
    move/16 v343, v340
    :k163
    if-eqz v2, :b164
    move/16 v344, v342
    move/16 v345, v343
    goto :k164
    :b164
    move/16 v344, v343
    move/16 v345, v342
    :k164
    if-eqz v2, :b165
    move/16 v346, v344
    move/16 v347, v345
    goto :k165
    :b165
    move/16 v346, v345
    move/16 v347, v344
    :k165
    if-eqz v2, :b166
    move/16 v348, v346
    move/16 v349, v347
    goto :k166
    :b166
    move/16 v348, v347
    move/16 v349, v346
    :k166
    if-eqz v2, :b167
    move/16 v350, v348
    move/16 v351, v349
    goto :k167
    :b167
    move/16 v350, v349
    move/16 v351, v348
    :k167
    if-eqz v2, :b168
    move/16 v352, v350
    move/16 v353, v351
    goto :k168
    :b168
    move/16 v352, v351
    move/16 v353, v350
    :k168
    if-eqz v2, :b169
    move/16 v354, v352
    move/16 v355, v353
    goto :k169
    :b169
    move/16 v354, v353
    move/16 v355, v352
    :k169
    if-eqz v2, :b170
    move/16 v356, v354
    move/16 v357, v355
    goto :k170
    :b170
    move/16 v356, v355
    move/16 v357, v354
    :k170
    if-eqz v2, :b171
    move/16 v358, v356
    move/16 v359, v357
    goto :k171
    :b171
    move/16 v358, v357
    move/16 v359, v356
    :k171
    if-eqz v2, :b172
    move/16 v360, v358
    move/16 v361, v359
    goto :k172
    :b172
    move/16 v360, v359
    move/16 v361, v358
    :k172
    if-eqz v2, :b173
    move/16 v362, v360
    move/16 v363, v361
    goto :k173
    :b173
    move/16 v362, v361
    move/16 v363, v360
    :k173
    if-eqz v2, :b174
    move/16 v364, v362
    move/16 v365, v363
    goto :k174
    :b174
    move/16 v364, v363
    move/16 v365, v362
    :k174
    if-eqz v2, :b175
    move/16 v366, v364
    move/16 v367, v365
    goto :k175
    :b175
    move/16 v366, v365
    move/16 v367, v364
    :k175
    if-eqz v2, :b176
    move/16 v368, v366
    move/16 v369, v367
    goto :k176
    :b176
    move/16 v368, v367
    move/16 v369, v366
    :k176
    if-eqz v2, :b177
    move/16 v370, v368
    move/16 v371, v369
    goto :k177
    :b177
    move/16 v370, v369
    move/16 v371, v368
    :k177
    if-eqz v2, :b178
    move/16 v372, v370
    move/16 v373, v371
    goto :k178
    :b178
    move/16 v372, v371
    move/16 v373, v370
    :k178
    if-eqz v2, :b179
    move/16 v374, v372
    move/16 v375, v373
    goto :k179
    :b179
    move/16 v374, v373
    move/16 v375, v372
    :k179
    if-eqz v2, :b180
    move/16 v376, v374
    move/16 v377, v375
    goto :k180
    :b180
    move/16 v376, v375
    move/16 v377, v374
    :k180
    if-eqz v2, :b181
    move/16 v378, v376
    move/16 v379, v377
    goto :k181
    :b181
    move/16 v378, v377
    move/16 v379, v376
    :k181
    if-eqz v2, :b182
    move/16 v380, v378
    move/16 v381, v379
    goto :k182
    :b182
    move/16 v380, v379
    move/16 v381, v378
    :k182
    if-eqz v2, :b183
    move/16 v382, v380
    move/16 v383, v381
    goto :k183
    :b183
    move/16 v382, v381
    move/16 v383, v380
    :k183
    if-eqz v2, :b184
    move/16 v384, v382
    move/16 v385, v383
    goto :k184
    :b184
    move/16 v384, v383
    move/16 v385, v382
    :k184
    if-eqz v2, :b185
    move/16 v386, v384
    move/16 v387, v385
    goto :k185
    :b185
    move/16 v386, v385
    move/16 v387, v384
    :k185
    if-eqz v2, :b186
    move/16 v388, v386
    move/16 v389, v387
    goto :k186
    :b186
    move/16 v388, v387
    move/16 v389, v386
    :k186
    if-eqz v2, :b187
    move/16 v390, v388
    move/16 v391, v389
    goto :k187
    :b187
    move/16 v390, v389
    move/16 v391, v388
    :k187
    if-eqz v2, :b188
    move/16 v392, v390
    move/16 v393, v391
    goto :k188
    :b188
    move/16 v392, v391
    move/16 v393, v390
    :k188
    if-eqz v2, :b189
    move/16 v394, v392
    move/16 v395, v393
    goto :k189
    :b189
    move/16 v394, v393
    move/16 v395, v392
    :k189
    if-eqz v2, :b190
    move/16 v396, v394
    move/16 v397, v395
    goto :k190
    :b190
    move/16 v396, v395
    move/16 v397, v394
    :k190
    if-eqz v2, :b191
    move/16 v398, v396
    move/16 v399, v397
    goto :k191
    :b191
    move/16 v398, v397
    move/16 v399, v396
    :k191
    if-eqz v2, :b192
    move/16 v400, v398
    move/16 v401, v399
    goto :k192
    :b192
    move/16 v400, v399
    move/16 v401, v398
    :k192
    if-eqz v2, :b193
    move/16 v402, v400
    move/16 v403, v401
    goto :k193
    :b193
    move/16 v402, v401
    move/16 v403, v400
    :k193
    if-eqz v2, :b194
    move/16 v404, v402
    move/16 v405, v403
    goto :k194
    :b194
    move/16 v404, v403
    move/16 v405, v402
    :k194
    if-eqz v2, :b195
    move/16 v406, v404
    move/16 v407, v405
    goto :k195
    :b195
    move/16 v406, v405
    move/16 v407, v404
    :k195
    if-eqz v2, :b196
    move/16 v408, v406
    move/16 v409, v407
    goto :k196
    :b196
    move/16 v408, v407
    move/16 v409, v406
    :k196
    if-eqz v2, :b197
    move/16 v410, v408
    move/16 v411, v409
    goto :k197
    :b197
    move/16 v410, v409
    move/16 v411, v408
    :k197
    if-eqz v2, :b198
    move/16 v412, v410
    move/16 v413, v411
    goto :k198
    :b198
    move/16 v412, v411
    move/16 v413, v410
    :k198
    if-eqz v2, :b199
    move/16 v414, v412
    move/16 v415, v413
    goto :k199
    :b199
    move/16 v414, v413
    move/16 v415, v412
    :k199
    if-eqz v2, :b200
    move/16 v416, v414
    move/16 v417, v415
    goto :k200
    :b200
    move/16 v416, v415
    move/16 v417, v414
    :k200
    if-eqz v2, :b201
    move/16 v418, v416
    move/16 v419, v417
    goto :k201
    :b201
    move/16 v418, v417
    move/16 v419, v416
    :k201
    if-eqz v2, :b202
    move/16 v420, v418
    move/16 v421, v419
    goto :k202
    :b202
    move/16 v420, v419
    move/16 v421, v418
    :k202
    if-eqz v2, :b203
    move/16 v422, v420
    move/16 v423, v421
    goto :k203
    :b203
    move/16 v422, v421
    move/16 v423, v420
    :k203
    if-eqz v2, :b204
    move/16 v424, v422
    move/16 v425, v423
    goto :k204
    :b204
    move/16 v424, v423
    move/16 v425, v422
    :k204
    if-eqz v2, :b205
    move/16 v426, v424
    move/16 v427, v425
    goto :k205
    :b205
    move/16 v426, v425
    move/16 v427, v424
    :k205
    if-eqz v2, :b206
    move/16 v428, v426
    move/16 v429, v427
    goto :k206
    :b206
    move/16 v428, v427
    move/16 v429, v426
    :k206
    if-eqz v2, :b207
    move/16 v430, v428
    move/16 v431, v429
    goto :k207
    :b207
    move/16 v430, v429
    move/16 v431, v428
    :k207
    if-eqz v2, :b208
    move/16 v432, v430
    move/16 v433, v431
    goto :k208
    :b208
    move/16 v432, v431
    move/16 v433, v430
    :k208
    if-eqz v2, :b209
    move/16 v434, v432
    move/16 v435, v433
    goto :k209
    :b209
    move/16 v434, v433
    move/16 v435, v432
    :k209
    if-eqz v2, :b210
    move/16 v436, v434
    move/16 v437, v435
    goto :k210
    :b210
    move/16 v436, v435
    move/16 v437, v434
    :k210
    if-eqz v2, :b211
    move/16 v438, v436
    move/16 v439, v437
    goto :k211
    :b211
    move/16 v438, v437
    move/16 v439, v436
    :k211
    if-eqz v2, :b212
    move/16 v440, v438
    move/16 v441, v439
    goto :k212
    :b212
    move/16 v440, v439
    move/16 v441, v438
    :k212
    if-eqz v2, :b213
    move/16 v442, v440
    move/16 v443, v441
    goto :k213
    :b213
    move/16 v442, v441
    move/16 v443, v440
    :k213
    if-eqz v2, :b214
    move/16 v444, v442
    move/16 v445, v443
    goto :k214
    :b214
    move/16 v444, v443
    move/16 v445, v442
    :k214
    if-eqz v2, :b215
    move/16 v446, v444
    move/16 v447, v445
    goto :k215
    :b215
    move/16 v446, v445
    move/16 v447, v444
    :k215
    if-eqz v2, :b216
    move/16 v448, v446
    move/16 v449, v447
    goto :k216
    :b216
    move/16 v448, v447
    move/16 v449, v446
    :k216
    if-eqz v2, :b217
    move/16 v450, v448
    move/16 v451, v449
    goto :k217
    :b217
    move/16 v450, v449
    move/16 v451, v448
    :k217
    if-eqz v2, :b218
    move/16 v452, v450
    move/16 v453, v451
    goto :k218
    :b218
    move/16 v452, v451
    move/16 v453, v450
    :k218
    if-eqz v2, :b219
    move/16 v454, v452
    move/16 v455, v453
    goto :k219
    :b219
    move/16 v454, v453
    move/16 v455, v452
    :k219
    if-eqz v2, :b220
    move/16 v456, v454
    move/16 v457, v455
    goto :k220
    :b220
    move/16 v456, v455
    move/16 v457, v454
    :k220
    if-eqz v2, :b221
    move/16 v458, v456
    move/16 v459, v457
    goto :k221
    :b221
    move/16 v458, v457
    move/16 v459, v456
    :k221
    if-eqz v2, :b222
    move/16 v460, v458
    move/16 v461, v459
    goto :k222
    :b222
    move/16 v460, v459
    move/16 v461, v458
    :k222
    if-eqz v2, :b223
    move/16 v462, v460
    move/16 v463, v461
    goto :k223
    :b223
    move/16 v462, v461
    move/16 v463, v460
    :k223
    if-eqz v2, :b224
    move/16 v464, v462
    move/16 v465, v463
    goto :k224
    :b224
    move/16 v464, v463
    move/16 v465, v462
    :k224
    if-eqz v2, :b225
    move/16 v466, v464
    move/16 v467, v465
    goto :k225
    :b225
    move/16 v466, v465
    move/16 v467, v464
    :k225
    if-eqz v2, :b226
    move/16 v468, v466
    move/16 v469, v467
    goto :k226
    :b226
    move/16 v468, v467
    move/16 v469, v466
    :k226
    if-eqz v2, :b227
    move/16 v470, v468
    move/16 v471, v469
    goto :k227
    :b227
    move/16 v470, v469
    move/16 v471, v468
    :k227
    if-eqz v2, :b228
    move/16 v472, v470
    move/16 v473, v471
    goto :k228
    :b228
    move/16 v472, v471
    move/16 v473, v470
    :k228
    if-eqz v2, :b229
    move/16 v474, v472
    move/16 v475, v473
    goto :k229
    :b229
    move/16 v474, v473
    move/16 v475, v472
    :k229
    if-eqz v2, :b230
    move/16 v476, v474
    move/16 v477, v475
    goto :k230
    :b230
    move/16 v476, v475
    move/16 v477, v474
    :k230
    if-eqz v2, :b231
    move/16 v478, v476
    move/16 v479, v477
    goto :k231
    :b231
    move/16 v478, v477
    move/16 v479, v476
    :k231
    if-eqz v2, :b232
    move/16 v480, v478
    move/16 v481, v479
    goto :k232
    :b232
    move/16 v480, v479
    move/16 v481, v478
    :k232
    if-eqz v2, :b233
    move/16 v482, v480
    move/16 v483, v481
    goto :k233
    :b233
    move/16 v482, v481
    move/16 v483, v480
    :k233
    if-eqz v2, :b234
    move/16 v484, v482
    move/16 v485, v483
    goto :k234
    :b234
    move/16 v484, v483
    move/16 v485, v482
    :k234
    if-eqz v2, :b235
    move/16 v486, v484
    move/16 v487, v485
    goto :k235
    :b235
    move/16 v486, v485
    move/16 v487, v484
    :k235
    if-eqz v2, :b236
    move/16 v488, v486
    move/16 v489, v487
    goto :k236
    :b236
    move/16 v488, v487
    move/16 v489, v486
    :k236
    if-eqz v2, :b237
    move/16 v490, v488
    move/16 v491, v489
    goto :k237
    :b237
    move/16 v490, v489
    move/16 v491, v488
    :k237
    if-eqz v2, :b238
    move/16 v492, v490
    move/16 v493, v491
    goto :k238
    :b238
    move/16 v492, v491
    move/16 v493, v490
    :k238
    if-eqz v2, :b239
    move/16 v494, v492
    move/16 v495, v493
    goto :k239
    :b239
    move/16 v494, v493
    move/16 v495, v492
    :k239
    if-eqz v2, :b240
    move/16 v496, v494
    move/16 v497, v495
    goto :k240
    :b240
    move/16 v496, v495
    move/16 v497, v494
    :k240
    if-eqz v2, :b241
    move/16 v498, v496
    move/16 v499, v497
    goto :k241
    :b241
    move/16 v498, v497
    move/16 v499, v496
    :k241
    if-eqz v2, :b242
    move/16 v500, v498
    move/16 v501, v499
    goto :k242
    :b242
    move/16 v500, v499
    move/16 v501, v498
    :k242
    if-eqz v2, :b243
    move/16 v502, v500
    move/16 v503, v501
    goto :k243
    :b243
    move/16 v502, v501
    move/16 v503, v500
    :k243
    if-eqz v2, :b244
    move/16 v504, v502
    move/16 v505, v503
    goto :k244
    :b244
    move/16 v504, v503
    move/16 v505, v502
    :k244
    if-eqz v2, :b245
    move/16 v506, v504
    move/16 v507, v505
    goto :k245
    :b245
    move/16 v506, v505
    move/16 v507, v504
    :k245
    if-eqz v2, :b246
    move/16 v508, v506
    move/16 v509, v507
    goto :k246
    :b246
    move/16 v508, v507
    move/16 v509, v506
    :k246
    if-eqz v2, :b247
    move/16 v510, v508
    move/16 v511, v509
    goto :k247
    :b247
    move/16 v510, v509
    move/16 v511, v508
    :k247
    if-eqz v2, :b248
    move/16 v512, v510
    move/16 v513, v511
    goto :k248
    :b248
    move/16 v512, v511
    move/16 v513, v510
    :k248
    if-eqz v2, :b249
    move/16 v514, v512
    move/16 v515, v513
    goto :k249
    :b249
    move/16 v514, v513
    move/16 v515, v512
    :k249
    if-eqz v2, :b250
    move/16 v516, v514
    move/16 v517, v515
    goto :k250
    :b250
    move/16 v516, v515
    move/16 v517, v514
    :k250
    if-eqz v2, :b251
    move/16 v518, v516
    move/16 v519, v517
    goto :k251
    :b251
    move/16 v518, v517
    move/16 v519, v516
    :k251
    if-eqz v2, :b252
    move/16 v520, v518
    move/16 v521, v519
    goto :k252
    :b252
    move/16 v520, v519
    move/16 v521, v518
    :k252
    if-eqz v2, :b253
    move/16 v522, v520
    move/16 v523, v521
    goto :k253
    :b253
    move/16 v522, v521
    move/16 v523, v520
    :k253
    if-eqz v2, :b254
    move/16 v524, v522
    move/16 v525, v523
    goto :k254
    :b254
    move/16 v524, v523
    move/16 v525, v522
    :k254
    if-eqz v2, :b255
    move/16 v526, v524
    move/16 v527, v525
    goto :k255
    :b255
    move/16 v526, v525
    move/16 v527, v524
    :k255
    if-eqz v2, :b256
    move/16 v528, v526
    move/16 v529, v527
    goto :k256
    :b256
    move/16 v528, v527
    move/16 v529, v526
    :k256
    if-eqz v2, :b257
    move/16 v530, v528
    move/16 v531, v529
    goto :k257
    :b257
    move/16 v530, v529
    move/16 v531, v528
    :k257
    if-eqz v2, :b258
    move/16 v532, v530
    move/16 v533, v531
    goto :k258
    :b258
    move/16 v532, v531
    move/16 v533, v530
    :k258
    if-eqz v2, :b259
    move/16 v534, v532
    move/16 v535, v533
    goto :k259
    :b259
    move/16 v534, v533
    move/16 v535, v532
    :k259
    if-eqz v2, :b260
    move/16 v536, v534
    move/16 v537, v535
    goto :k260
    :b260
    move/16 v536, v535
    move/16 v537, v534
    :k260
    if-eqz v2, :b261
    move/16 v538, v536
    move/16 v539, v537
    goto :k261
    :b261
    move/16 v538, v537
    move/16 v539, v536
    :k261
    if-eqz v2, :b262
    move/16 v540, v538
    move/16 v541, v539
    goto :k262
    :b262
    move/16 v540, v539
    move/16 v541, v538
    :k262
    if-eqz v2, :b263
    move/16 v542, v540
    move/16 v543, v541
    goto :k263
    :b263
    move/16 v542, v541
    move/16 v543, v540
    :k263
    if-eqz v2, :b264
    move/16 v544, v542
    move/16 v545, v543
    goto :k264
    :b264
    move/16 v544, v543
    move/16 v545, v542
    :k264
    if-eqz v2, :b265
    move/16 v546, v544
    move/16 v547, v545
    goto :k265
    :b265
    move/16 v546, v545
    move/16 v547, v544
    :k265
    if-eqz v2, :b266
    move/16 v548, v546
    move/16 v549, v547
    goto :k266
    :b266
    move/16 v548, v547
    move/16 v549, v546
    :k266
    if-eqz v2, :b267
    move/16 v550, v548
    move/16 v551, v549
    goto :k267
    :b267
    move/16 v550, v549
    move/16 v551, v548
    :k267
    if-eqz v2, :b268
    move/16 v552, v550
    move/16 v553, v551
    goto :k268
    :b268
    move/16 v552, v551
    move/16 v553, v550
    :k268
    if-eqz v2, :b269
    move/16 v554, v552
    move/16 v555, v553
    goto :k269
    :b269
    move/16 v554, v553
    move/16 v555, v552
    :k269
    if-eqz v2, :b270
    move/16 v556, v554
    move/16 v557, v555
    goto :k270
    :b270
    move/16 v556, v555
    move/16 v557, v554
    :k270
    if-eqz v2, :b271
    move/16 v558, v556
    move/16 v559, v557
    goto :k271
    :b271
    move/16 v558, v557
    move/16 v559, v556
    :k271
    if-eqz v2, :b272
    move/16 v560, v558
    move/16 v561, v559
    goto :k272
    :b272
    move/16 v560, v559
    move/16 v561, v558
    :k272
    if-eqz v2, :b273
    move/16 v562, v560
    move/16 v563, v561
    goto :k273
    :b273
    move/16 v562, v561
    move/16 v563, v560
    :k273
    if-eqz v2, :b274
    move/16 v564, v562
    move/16 v565, v563
    goto :k274
    :b274
    move/16 v564, v563
    move/16 v565, v562
    :k274
    if-eqz v2, :b275
    move/16 v566, v564
    move/16 v567, v565
    goto :k275
    :b275
    move/16 v566, v565
    move/16 v567, v564
    :k275
    if-eqz v2, :b276
    move/16 v568, v566
    move/16 v569, v567
    goto :k276
    :b276
    move/16 v568, v567
    move/16 v569, v566
    :k276
    if-eqz v2, :b277
    move/16 v570, v568
    move/16 v571, v569
    goto :k277
    :b277
    move/16 v570, v569
    move/16 v571, v568
    :k277
    if-eqz v2, :b278
    move/16 v572, v570
    move/16 v573, v571
    goto :k278
    :b278
    move/16 v572, v571
    move/16 v573, v570
    :k278
    if-eqz v2, :b279
    move/16 v574, v572
    move/16 v575, v573
    goto :k279
    :b279
    move/16 v574, v573
    move/16 v575, v572
    :k279
    if-eqz v2, :b280
    move/16 v576, v574
    move/16 v577, v575
    goto :k280
    :b280
    move/16 v576, v575
    move/16 v577, v574
    :k280
    if-eqz v2, :b281
    move/16 v578, v576
    move/16 v579, v577
    goto :k281
    :b281
    move/16 v578, v577
    move/16 v579, v576
    :k281
    if-eqz v2, :b282
    move/16 v580, v578
    move/16 v581, v579
    goto :k282
    :b282
    move/16 v580, v579
    move/16 v581, v578
    :k282
    if-eqz v2, :b283
    move/16 v582, v580
    move/16 v583, v581
    goto :k283
    :b283
    move/16 v582, v581
    move/16 v583, v580
    :k283
    if-eqz v2, :b284
    move/16 v584, v582
    move/16 v585, v583
    goto :k284
    :b284
    move/16 v584, v583
    move/16 v585, v582
    :k284
    if-eqz v2, :b285
    move/16 v586, v584
    move/16 v587, v585
    goto :k285
    :b285
    move/16 v586, v585
    move/16 v587, v584
    :k285
    if-eqz v2, :b286
    move/16 v588, v586
    move/16 v589, v587
    goto :k286
    :b286
    move/16 v588, v587
    move/16 v589, v586
    :k286
    if-eqz v2, :b287
    move/16 v590, v588
    move/16 v591, v589
    goto :k287
    :b287
    move/16 v590, v589
    move/16 v591, v588
    :k287
    if-eqz v2, :b288
    move/16 v592, v590
    move/16 v593, v591
    goto :k288
    :b288
    move/16 v592, v591
    move/16 v593, v590
    :k288
    if-eqz v2, :b289
    move/16 v594, v592
    move/16 v595, v593
    goto :k289
    :b289
    move/16 v594, v593
    move/16 v595, v592
    :k289
    if-eqz v2, :b290
    move/16 v596, v594
    move/16 v597, v595
    goto :k290
    :b290
    move/16 v596, v595
    move/16 v597, v594
    :k290
    if-eqz v2, :b291
    move/16 v598, v596
    move/16 v599, v597
    goto :k291
    :b291
    move/16 v598, v597
    move/16 v599, v596
    :k291
    if-eqz v2, :b292
    move/16 v600, v598
    move/16 v601, v599
    goto :k292
    :b292
    move/16 v600, v599
    move/16 v601, v598
    :k292
    if-eqz v2, :b293
    move/16 v602, v600
    move/16 v603, v601
    goto :k293
    :b293
    move/16 v602, v601
    move/16 v603, v600
    :k293
    if-eqz v2, :b294
    move/16 v604, v602
    move/16 v605, v603
    goto :k294
    :b294
    move/16 v604, v603
    move/16 v605, v602
    :k294
    if-eqz v2, :b295
    move/16 v606, v604
    move/16 v607, v605
    goto :k295
    :b295
    move/16 v606, v605
    move/16 v607, v604
    :k295
    if-eqz v2, :b296
    move/16 v608, v606
    move/16 v609, v607
    goto :k296
    :b296
    move/16 v608, v607
    move/16 v609, v606
    :k296
    if-eqz v2, :b297
    move/16 v610, v608
    move/16 v611, v609
    goto :k297
    :b297
    move/16 v610, v609
    move/16 v611, v608
    :k297
    if-eqz v2, :b298
    move/16 v612, v610
    move/16 v613, v611
    goto :k298
    :b298
    move/16 v612, v611
    move/16 v613, v610
    :k298
    if-eqz v2, :b299
    move/16 v614, v612
    move/16 v615, v613
    goto :k299
    :b299
    move/16 v614, v613
    move/16 v615, v612
    :k299
    if-eqz v2, :b300
    move/16 v616, v614
    move/16 v617, v615
    goto :k300
    :b300
    move/16 v616, v615
    move/16 v617, v614
    :k300
    move/16 v0, v616
    return v0
.end method

# NEGATIVE (correctness review). `cycleFlag` plus one more move: the
# consistency closure demotes `v2` to `int` (its source is a constant-only
# cycle), and that demotion has to travel ON to `v3`, which `v2` is moved
# into — or `boolean v3 = v2` is left beside an `int v2`.
.method public static cycleChain(Ljava/lang/String;I)Ljava/lang/Boolean;
    .registers 6
    const/4 v0, 0x0
    :loop
    if-eqz p1, :done
    move v1, v0
    move v0, v1
    add-int/lit8 p1, p1, -0x1
    goto :loop
    :done
    if-nez p1, :other
    move v2, v0
    goto :out
    :other
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v2
    :out
    if-eqz p1, :m
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v3
    goto :n
    :m
    move v3, v2
    :n
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v4
    return-object v4
.end method

# NEGATIVE (mutation matrix). A constant-like version is summarised as the
# RANGE of the constants reaching it, and BOTH ends must fit the type it is
# given: 0 fits byte, 200 does not, so v0 is not taken into the byte
# it is moved into.
#
# POSITIVE (mutation matrix). A ladder of constant-only moves whose register
# names cross the sorted order (v10 < v2) and end in a boolean: every rung is
# boolean, which needs the worklist to revisit a version once its source
# is resolved.
.method public static rangeByte(Ljava/lang/Byte;I)I
    .registers 4
    if-eqz p1, :a
    const/4 v0, 0x0
    goto :b
    :a
    const/16 v0, 0xc8
    :b
    move v1, v0
    if-lez p1, :c
    invoke-virtual {p0}, Ljava/lang/Byte;->byteValue()B
    move-result v1
    :c
    add-int/lit8 v2, v1, 0x1
    return v2
.end method

.method public static constLadder(Ljava/lang/String;I)Z
    .registers 17
    const/4 v0, 0x0
    const/4 v1, 0x1
    if-eqz p1, :a1
    move v2, v0
    move v3, v1
    goto :j1
    :a1
    move v2, v1
    move v3, v0
    :j1
    if-eqz p1, :a2
    move v4, v2
    move v5, v3
    goto :j2
    :a2
    move v4, v3
    move v5, v2
    :j2
    if-eqz p1, :a3
    move v6, v4
    move v7, v5
    goto :j3
    :a3
    move v6, v5
    move v7, v4
    :j3
    if-eqz p1, :a4
    move v8, v6
    move v9, v7
    goto :j4
    :a4
    move v8, v7
    move v9, v6
    :j4
    if-eqz p1, :a5
    move v10, v8
    move v11, v9
    goto :j5
    :a5
    move v10, v9
    move v11, v8
    :j5
    if-eqz p1, :a6
    move v12, v10
    move v13, v11
    goto :j6
    :a6
    move v12, v11
    move v13, v10
    :j6
    if-eqz p1, :x
    move v14, v12
    goto :y
    :x
    move v14, v13
    :y
    if-lez p1, :e
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v14
    :e
    return v14
.end method

# NEGATIVE (delta review). The closure's constant-like skip is tested against
# the destination's own type, never the partial join of the sources already
# visited: with v6 (S) visited first, v5 (0 or 200) used to be skipped and v0
# came out short beside int v5; with the branches swapped it was
# int. Both orders are int now.
.method public static defOrder(Ljava/lang/Byte;ILjava/lang/Short;)V
    .registers 11
    const/4 v7, 0x0
    if-eqz p1, :L1
    invoke-virtual {p2}, Ljava/lang/Short;->shortValue()S
    move-result v7
    invoke-static {v7}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;
    return-void
    :L1
    move v6, v7
    if-eqz v6, :L2
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;
    :L2
    const/4 v5, 0x0
    if-gez p1, :L3
    const/16 v5, 0xc8
    :L3
    if-lez p1, :A
    invoke-virtual {p0}, Ljava/lang/Byte;->byteValue()B
    move-result v0
    goto :J
    :A
    if-gez p1, :B
    move v0, v6
    goto :J
    :B
    move v0, v5
    :J
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;
    return-void
.end method

# NEGATIVE (delta review). A constant-like source the assignment step typed
# boolean from its destination must rise WITH it when the closure raises
# that destination (a constant-only cycle beside it), or the move between them
# reads boolean v3 … int v2 … v2 = v3.
.method public static raisedDest(Ljava/lang/String;IZ)Ljava/lang/Boolean;
    .registers 8
    const/4 v0, 0x0
    :loop
    if-eqz p1, :done
    move v1, v0
    move v0, v1
    add-int/lit8 p1, p1, -0x1
    goto :loop
    :done
    const/4 v3, 0x0
    if-eqz p2, :k
    const/4 v3, 0x1
    :k
    if-nez p1, :other
    move v2, v0
    goto :out
    :other
    if-eqz p2, :third
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v2
    goto :out
    :third
    move v2, v3
    :out
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v4
    return-object v4
.end method

# NEGATIVE (hack-gate review): a bitwise def whose OTHER operand is still
# unresolved, but whose constant (2, 7) cannot be a boolean. It must not be
# stamped Z — the first cut deferred it forever and rendered `(false | 2)`.
.method public static skipBit(Ljava/lang/String;Z)I
    .registers 4
    if-eqz p1, :b
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v0
    goto :j
    :b
    const/4 v1, 0x0
    or-int/lit8 v0, v1, 0x2
    :j
    if-eqz v0, :z
    const/4 v1, 0x5
    return v1
    :z
    const/4 v1, 0x6
    return v1
.end method

.method public static skipBit2(Ljava/lang/String;Z)I
    .registers 4
    if-eqz p1, :b
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v0
    goto :j
    :b
    const/4 v1, 0x1
    xor-int/lit8 v0, v1, 0x7
    :j
    if-eqz v0, :z
    const/4 v1, 0x5
    return v1
    :z
    const/4 v1, 0x6
    return v1
.end method

# POSITIVE (adversarial review): d8 parks ONE `const/4 0` and moves it into a
# boolean slot; the parked register is an int elsewhere (same version). The
# move carries the constant, not the int — GMS SafeParcelable readers
# (weardrawers `zzbgr.createFromParcel`).
.method public static parkedConst(Ljava/lang/String;I[I)Ljava/lang/Boolean;
    .registers 6
    const/4 v1, 0x0
    move v0, v1
    if-eqz p1, :a
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v0
    invoke-virtual {p0}, Ljava/lang/String;->length()I
    move-result v1
    :a
    aput v1, p2, v1
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v2
    return-object v2
.end method

# NEGATIVE (mutation matrix): the carried constant must still be CHECKED — a
# parked 2 moved into a slot that also takes a Z result makes that slot int.
.method public static parkedTwo(Ljava/lang/String;I[I)Ljava/lang/Boolean;
    .registers 6
    const/4 v1, 0x2
    move v0, v1
    if-eqz p1, :a
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v0
    invoke-virtual {p0}, Ljava/lang/String;->length()I
    move-result v1
    :a
    aput v1, p2, v1
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v2
    return-object v2
.end method

# POSITIVE (mutation matrix): a flag whose EVERY def is a move of a lone
# constant takes the type of the registers they were parked in — nothing else
# decides one (`ToolbarActionBar.onKeyShortcut`'s setQwertyMode flag).
.method public static loneHint(Ljava/lang/String;Z)Z
    .registers 6
    const/4 v0, 0x1
    const/4 v1, 0x0
    if-eqz p1, :x
    move v2, v0
    goto :u
    :x
    move v2, v1
    :u
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;
    move-result-object v3
    if-nez v2, :r
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z
    move-result v1
    :r
    return v1
.end method
