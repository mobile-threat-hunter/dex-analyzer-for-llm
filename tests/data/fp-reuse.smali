# dexllm#88 fixture. Authored in smali, not Java: d8 duplicates a `return` into
# every predecessor, so no Java source reaches the shape the defect needs — a
# float constant and an int sharing ONE register version that meets at a use.
.class public LFpReuse;
.super Ljava/lang/Object;

.field static sOut:F
.field static sInt:I
.field static sD:D
.field static sInteger:Ljava/lang/Integer;
.field private mValues:[F
.field private mStepSize:F
.field private mD:[D

# POSITIVE, `return` in an F method. Byte-for-byte the shape of the corpus's
# android.support.v4.view.animation.LookupTableInterpolator.getInterpolation:
# v4 holds 1.0f, 0f (moved in from v5) or the computed float, and is reused as
# the int index along the way.
.method public interp(F)F
    .registers 9
    const/high16 v4, 0x3f800000
    const/4 v5, 0x0
    cmpl-float v6, p1, v4
    if-ltz v6, :lt1
    :ret
    return v4
    :lt1
    cmpg-float v4, p1, v5
    if-gtz v4, :pos
    move v4, v5
    goto :ret
    :pos
    iget-object v4, p0, LFpReuse;->mValues:[F
    array-length v4, v4
    add-int/lit8 v4, v4, -0x1
    int-to-float v4, v4
    mul-float/2addr v4, p1
    float-to-int v4, v4
    iget-object v5, p0, LFpReuse;->mValues:[F
    array-length v5, v5
    add-int/lit8 v5, v5, -0x2
    invoke-static {v4, v5}, Ljava/lang/Math;->min(II)I
    move-result v1
    int-to-float v4, v1
    iget v5, p0, LFpReuse;->mStepSize:F
    mul-float v2, v4, v5
    sub-float v0, p1, v2
    iget v4, p0, LFpReuse;->mStepSize:F
    div-float v3, v0, v4
    iget-object v4, p0, LFpReuse;->mValues:[F
    aget v4, v4, v1
    iget-object v5, p0, LFpReuse;->mValues:[F
    add-int/lit8 v6, v1, 0x1
    aget v5, v5, v6
    iget-object v6, p0, LFpReuse;->mValues:[F
    aget v6, v6, v1
    sub-float/2addr v5, v6
    mul-float/2addr v5, v3
    add-float/2addr v4, v5
    goto :ret
.end method

# POSITIVE, `return-wide` in a D method — the wide twin (const-wide/high16).
.method public interpD(D)D
    .registers 10
    const-wide/high16 v4, 0x3ff0000000000000L
    const-wide/16 v6, 0x0
    cmpl-double v0, p1, v4
    if-ltz v0, :lt1
    :ret
    return-wide v4
    :lt1
    cmpg-double v4, p1, v6
    if-gtz v4, :pos
    move-wide v4, v6
    goto :ret
    :pos
    iget-object v0, p0, LFpReuse;->mD:[D
    array-length v4, v0
    add-int/lit8 v4, v4, -0x2
    aget-wide v4, v0, v4
    goto :ret
.end method

# POSITIVE, a FIELD STORE and a float operation in a void method: v2 holds
# 1.0f or Math.abs(p1) and is reused as the int array length before that.
.method public store(F[I)V
    .registers 7
    array-length v2, p2
    add-int/lit8 v2, v2, -0x1
    int-to-float v3, v2
    const/4 v0, 0x0
    cmpl-float v0, p1, v0
    if-eqz v0, :one
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F
    move-result v2
    goto :use
    :one
    const/high16 v2, 0x3f800000
    :use
    mul-float/2addr v3, v2
    sput v3, LFpReuse;->sOut:F
    return-void
.end method

# POSITIVE, an ARGUMENT at an F parameter, reached only through a MOVE. v1 has
# TWO constant defs (so RegisterPropagation cannot inline it into the move) and
# no float use of its own — its only use is the move into v0 — and it is reused
# as an int afterwards, so DAD types it `int`. It is typed by the backwards
# propagation from v0.
.method public static viaMove(FI[I)F
    .registers 6
    const/high16 v1, 0x40000000
    if-lez p1, :b
    const/high16 v1, 0x40400000
    :b
    move v0, v1
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F
    move-result v2
    array-length v1, p2
    int-to-float v1, v1
    add-float/2addr v2, v1
    return v2
.end method

# NEGATIVE, a genuine int flag: never used as a float, must stay `int`.
.method public static flags(I)I
    .registers 2
    const/high16 v0, 0x10000000
    if-lez p0, :done
    move v0, p0
    :done
    return v0
.end method

# NEGATIVE, a constant used as BOTH an int and a float on one version (legal:
# a Dalvik constant is untyped). No single Java type fits, so it stays `int`.
# Two defs, so RegisterPropagation cannot inline the constant into each use.
.method public static mixed(IF)F
    .registers 4
    const/high16 v0, 0x3f800000
    if-lez p0, :b
    const/high16 v0, 0x40000000
    :b
    add-int/lit8 v1, v0, 0x1
    sput v1, LFpReuse;->sInt:I
    add-float v1, v0, p1
    return v1
.end method

# NEGATIVE, a genuine int PRODUCER (add-int) on one path into a float use. Not
# legal Dalvik, but the structural verifier does not check dataflow, so it
# loads; the def anchor must refuse it rather than call an int a float.
.method public static intDef(FI)F
    .registers 3
    add-int/lit8 v0, p1, 0x1
    if-lez p1, :use
    const/high16 v0, 0x3f800000
    :use
    add-float v1, v0, p0
    return v1
.end method

# ---------------------------------------------------------------------------
# ISOLATED sources. Each method below has exactly ONE use of v0, in the one
# position it names, and TWO constant defs so RegisterPropagation cannot inline
# it away. A `const` builds an int-typed value, so DAD declares v0 `int` and
# only that one use can prove it a float — which is what lets a mutant that
# drops one source position be killed by one method.
# ---------------------------------------------------------------------------
.method public static retF(I)F
    .registers 2
    const/high16 v0, 0x3f800000
    if-lez p0, :b
    const/high16 v0, 0x40000000
    :b
    return v0
.end method

.method public static retD(I)D
    .registers 3
    const-wide/high16 v0, 0x3ff0000000000000L
    if-lez p0, :b
    const-wide/high16 v0, 0x4000000000000000L
    :b
    return-wide v0
.end method

.method public static cmpF(IF)I
    .registers 4
    const/high16 v0, 0x3f800000
    if-lez p0, :b
    const/high16 v0, 0x40000000
    :b
    cmpl-float v1, v0, p1
    return v1
.end method

.method public static negF(I)F
    .registers 3
    const/high16 v0, 0x3f800000
    if-lez p0, :b
    const/high16 v0, 0x40000000
    :b
    neg-float v1, v0
    return v1
.end method

.method public static castF(I)I
    .registers 3
    const/high16 v0, 0x3fc00000
    if-lez p0, :b
    const/high16 v0, 0x40200000
    :b
    float-to-int v1, v0
    return v1
.end method

.method public static binF(IF)F
    .registers 4
    const/high16 v0, 0x3f800000
    if-lez p0, :b
    const/high16 v0, 0x40000000
    :b
    add-float v1, v0, p1
    return v1
.end method

.method public static argF(I)V
    .registers 2
    const/high16 v0, 0x3f800000
    if-lez p0, :b
    const/high16 v0, 0x40000000
    :b
    invoke-static {v0}, LFpReuse;->sinkF(F)V
    return-void
.end method

.method public static sputF(I)V
    .registers 2
    const/high16 v0, 0x3f800000
    if-lez p0, :b
    const/high16 v0, 0x40000000
    :b
    sput v0, LFpReuse;->sOut:F
    return-void
.end method

.method public iputF(I)V
    .registers 3
    const/high16 v0, 0x3f800000
    if-lez p1, :b
    const/high16 v0, 0x40000000
    :b
    iput v0, p0, LFpReuse;->mStepSize:F
    return-void
.end method

.method public static aputF([FI)V
    .registers 3
    const/high16 v0, 0x3f800000
    if-lez p1, :b
    const/high16 v0, 0x40000000
    :b
    aput v0, p0, p1
    return-void
.end method

# NEGATIVE twin of sputF: the same constants stored into an INT field. Nothing
# proves a float here, so v0 stays `int`.
.method public static sputI(I)V
    .registers 2
    const/high16 v0, 0x3f800000
    if-lez p0, :b
    const/high16 v0, 0x40000000
    :b
    sput v0, LFpReuse;->sInt:I
    return-void
.end method

# NEGATIVE twin of aputF: an `int[]` element.
.method public static aputI([II)V
    .registers 3
    const/high16 v0, 0x3f800000
    if-lez p1, :b
    const/high16 v0, 0x40000000
    :b
    aput v0, p0, p1
    return-void
.end method

# A PARAMETER whose register is overwritten by a float constant. Its version
# carries the implicit incoming definition `defs_of` does not hold, so only the
# DECLARED type can decide: declared `I` must stay int, declared `F` may be
# float. (The Param's own get_type() is corrupted by the write.)
.method public static paramI(IZ)F
    .registers 3
    if-eqz p1, :use
    const/high16 p0, 0x3f800000
    :use
    add-float v0, p0, p0
    return v0
.end method

.method public static paramF(FZ)F
    .registers 3
    if-eqz p1, :use
    const/high16 p0, 0x3f800000
    :use
    add-float v0, p0, p0
    return v0
.end method

.method public static sinkF(F)V
    .registers 1
    return-void
.end method

# POSITIVE through a REFERENCE-typed version. v1 is first a `float[]` (so the
# register's type is a reference) and is then overwritten by a constant that is
# moved into v0; SplitConflatedVersion sees a reference move plus a nonzero
# constant and types v0 `Object`, and the use-driven ref->prim branch would then
# narrow it to the constant's `I`. The `drawShadow` shape from the corpus.
.method public refConf(I)F
    .registers 5
    const/high16 v1, 0x3f800000
    const/high16 v0, 0x40000000
    if-lez p1, :b
    move v0, v1
    :b
    iget-object v1, p0, LFpReuse;->mValues:[F
    array-length v2, v1
    int-to-float v3, v2
    div-float v2, v0, v3
    invoke-static {v2, v0}, LFpReuse;->sink2(FF)V
    return v0
.end method

.method public static sink2(FF)V
    .registers 2
    return-void
.end method

# A move CYCLE with constant ground truth: v0 -> v1 -> v2 -> v0 around a loop.
# The back edge of the def walk must be NEUTRAL, or the cycle blocks the proof.
.method public static swap(I)F
    .registers 4
    const/high16 v0, 0x3f800000
    const/high16 v1, 0x40000000
    :top
    if-lez p0, :out
    move v2, v0
    move v0, v1
    move v1, v2
    add-int/lit8 p0, p0, -0x1
    goto :top
    :out
    return v0
.end method

# NEGATIVE (lenient-only shape): NARROW constants reaching a DOUBLE use. Not
# legal Dalvik — a wide pair must be written by a wide instruction — but it
# loads; the def proof must refuse it rather than reinterpret 32 bits as 64.
.method public static narrowD(I)D
    .registers 3
    const/high16 v0, 0x3f800000
    if-lez p0, :b
    const/high16 v0, 0x40000000
    :b
    return-wide v0
.end method

# NEGATIVE (lenient-only shape): one register version used as a FLOAT and as
# the low half of a DOUBLE — two widths, no single type.
.method public static twoWidths(ID)F
    .registers 6
    const/high16 v0, 0x3f800000
    if-lez p0, :b
    const/high16 v0, 0x40000000
    :b
    add-float v1, v0, v0
    add-double v2, v0, p1
    sput-wide v2, LFpReuse;->sD:D
    return v1
.end method

# NEGATIVE (lenient-only shape): a pure move cycle with NO producer anywhere —
# v0 and v1 are read before they are ever written. An all-quantifier over its
# defs is satisfied vacuously; the `ground` requirement refuses it.
.method public static noGround(I)F
    .registers 3
    :top
    move v0, v1
    move v1, v0
    if-lez p0, :top
    return v0
.end method

# POSITIVE through the backwards propagation from a destination that is ALREADY
# float: v0's register is last written by a `float` move-result, so the version
# the move defines is typed `float` from the start and needs no re-type of its
# own — it can still prove its SOURCE a float. v1 has no float use of its own.
.method public static viaMoveF(I)F
    .registers 3
    const/high16 v1, 0x40000000
    if-lez p0, :b
    const/high16 v1, 0x40400000
    :b
    move v0, v1
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F
    move-result v0
    return v0
.end method

# ---------------------------------------------------------------------------
# NEGATIVES a correctness review constructed against the first cut; each
# turned valid Java invalid there. All legal Dalvik: a constant is untyped.
# ---------------------------------------------------------------------------

# ONE register at a float position AND an int position of ONE instruction —
# the index and the value of an `aput` into a float[].
.method public static aputIdx([FI)V
    .registers 3
    const/4 v0, 0x0
    if-lez p1, :b
    const/4 v0, 0x1
    :b
    aput v0, p0, v0
    return-void
.end method

# The same, at an F and an I parameter of one invoke.
.method public static invFI(I)V
    .registers 2
    const/4 v0, 0x0
    if-lez p0, :b
    const/4 v0, 0x1
    :b
    invoke-static {v0, v0}, LFpReuse;->sinkFI(FI)V
    return-void
.end method

.method public static sinkFI(FI)V
    .registers 2
    return-void
.end method

# One source moved into an int-used register AND a float-used one: the int use
# is behind a move, so it must travel back to the source.
.method public static fanout(I)F
    .registers 6
    const/high16 v1, 0x3f800000
    if-lez p0, :b
    const/high16 v1, 0x40000000
    :b
    move v4, v1
    add-int/lit8 v2, v4, 0x1
    sput v2, LFpReuse;->sInt:I
    move v0, v1
    add-float v3, v0, v0
    return v3
.end method

# The source has a float use of its OWN and an int use behind a move — the
# seed branch, not only the propagation, must see it.
.method public static seedBehindMove(I)F
    .registers 5
    const/high16 v1, 0x3f800000
    if-lez p0, :b
    const/high16 v1, 0x40000000
    :b
    add-float v3, v1, v1
    move v2, v1
    add-int/lit8 v0, v2, 0x1
    sput v0, LFpReuse;->sInt:I
    return v3
.end method

# The destination is float-used and the SOURCE is int-used: the destination's
# value is the same int-used value, so it is not provably a float either. v0
# has a second def so RegisterPropagation cannot inline the move away and hide
# a `float v0 = v1` widening of the int bits.
.method public static srcInt(I)F
    .registers 5
    const/high16 v1, 0x3f800000
    if-lez p0, :b
    const/high16 v1, 0x40000000
    :b
    add-int/lit8 v2, v1, 0x1
    sput v2, LFpReuse;->sInt:I
    const/high16 v0, 0x40400000
    if-gez p0, :c
    move v0, v1
    :c
    add-float v3, v0, v0
    return v3
.end method

# (lenient-only shape) a `cmpl-float` RESULT — an int, though the IR node
# carries the operand width "F" — merged with a float constant.
.method public static cmpAsF(FFI)F
    .registers 4
    cmpl-float v0, p0, p1
    if-lez p2, :b
    const/high16 v0, 0x3f800000
    :b
    return v0
.end method

# POSITIVE: a float moved into a register that DAD leaves UNSPLIT — on the other
# path it holds a `float[]`, and the merged version is passed as a `float[]`
# argument. A reference position cannot carry a float in verified Dalvik, so it
# must not travel back through the move and block the float source (it did in a
# first cut of the move rule; `GradientColorInflaterCompat` lost three fixes).
.method public refBehindMove(I)V
    .registers 4
    const/high16 v0, 0x3f800000
    if-lez p1, :b
    const/high16 v0, 0x40000000
    :b
    invoke-static {v0}, LFpReuse;->sinkF(F)V
    if-lez p1, :arr
    move v1, v0
    goto :use
    :arr
    iget-object v1, p0, LFpReuse;->mValues:[F
    :use
    invoke-static {v1}, LFpReuse;->sinkA([F)V
    return-void
.end method

.method public static sinkA([F)V
    .registers 1
    return-void
.end method

# ---------------------------------------------------------------------------
# NEGATIVES a DELTA review constructed against the review responses.
# ---------------------------------------------------------------------------

# FORWARD partial re-type: v0 is float-used and moved into v1, which is refused
# (its OTHER arm, v2, is an int). Typing v0 alone would print `v1 = v0` with an
# `int v1` and a `float v0` — so v0 must stay `int` too.
.method public static forwardOrphan(FI)F
    .registers 8
    const/high16 v0, 0x3f800000
    if-lez p1, :c0
    const/high16 v0, 0x40000000
    :c0
    add-float v3, v0, p0
    sput v3, LFpReuse;->sOut:F
    const/4 v2, 0x5
    if-gez p1, :c1
    const/4 v2, 0x6
    :c1
    add-int/lit8 v4, v2, 0x1
    sput v4, LFpReuse;->sInt:I
    if-lez p1, :a
    move v1, v0
    goto :j
    :a
    move v1, v2
    :j
    add-float v3, v1, p0
    return v3
.end method

# A ZERO is also `null` (ART's Zero type): legal Dalvik moves the float-used 0
# into an `Integer` slot. `Integer v1 = v0` with a float `v0` does not compile.
.method public static zeroToInteger(FI)F
    .registers 6
    const/4 v0, 0x0
    if-lez p1, :b
    const/4 v0, 0x0
    :b
    add-float v2, v0, p0
    move v1, v0
    sput-object v1, LFpReuse;->sInteger:Ljava/lang/Integer;
    sput-object v1, LFpReuse;->sInteger:Ljava/lang/Integer;
    return v2
.end method

# (ill-typed, but strict-verify-valid here) a NONZERO float moved by a PLAIN
# move into a register used only as a reference. Unlike `refBehindMove`, the
# destination has no reference arm of its own, so nothing marks it an unsplit
# register: the source is dropped rather than printing `int v1 = v0`.
.method public static plainIntoRef(FI)F
    .registers 6
    const/high16 v0, 0x3f800000
    if-lez p1, :b
    const/high16 v0, 0x40000000
    :b
    add-float v2, v0, p0
    move v1, v0
    sput-object v1, LFpReuse;->sInteger:Ljava/lang/Integer;
    sput-object v1, LFpReuse;->sInteger:Ljava/lang/Integer;
    return v2
.end method

# POSITIVE through FORWARD adoption: v1 receives the float by a move and is
# never used (DeadCodeElimination runs AFTER this pass, so the move is still
# there). DAD types v1 `int` — a move source's primitive type is not trusted —
# so without adopting the destination the move rule would drop the SOURCE
# (`ArcCurveFit$Arc.buildTable`'s loop-exit copy).
.method public static deadCarrier(I)F
    .registers 4
    const/high16 v0, 0x3f800000
    if-lez p0, :b
    const/high16 v0, 0x40000000
    :b
    move v1, v0
    add-float v2, v0, v0
    return v2
.end method

# NEGATIVE: a 0 moved into a register that DOES have a reference arm (an
# `Integer` on the other path) and is used as an `Integer`. The unsplit-register
# exception must not apply to a source that can be 0 — 0 is also `null`.
.method public static zeroIntoUnsplit(FI)F
    .registers 5
    const/4 v0, 0x0
    if-lez p1, :b
    const/4 v0, 0x0
    :b
    add-float v2, v0, p0
    if-gez p1, :o
    move v1, v0
    goto :u
    :o
    sget-object v1, LFpReuse;->sInteger:Ljava/lang/Integer;
    :u
    sput-object v1, LFpReuse;->sInteger:Ljava/lang/Integer;
    return v2
.end method

# ---------------------------------------------------------------------------
# From a FINAL delta review.
# ---------------------------------------------------------------------------

# NEGATIVE: a float ARITHMETIC def is a value edge too. v0 is float-used by
# `neg-float`, but the result v2 also takes a constant that `if-eqz` reads as an
# int, so v2 stays `int` — and a float v0 would render `int v2 = (- v0)`. ART
# verifies this method (const ⊔ Float at the `sput`), so it is not GIGO.
.method public static negIntoInt(I)V
    .registers 4
    const/high16 v0, 0x3f800000
    if-lez p0, :a
    const/high16 v0, 0x40000000
    :a
    const/high16 v1, 0x3f000000
    if-eqz v1, :b
    :b
    if-lez p0, :c
    neg-float v2, v0
    goto :d
    :c
    move v2, v1
    :d
    sput v2, LFpReuse;->sOut:F
    return-void
.end method

# POSITIVE: a float PARAMETER as a move source. It has no defs, so only its
# DECLARED type can say it is a float; without that the move rule read it as
# non-float and dropped the destination.
.method public static paramSrc(FI)F
    .registers 5
    const/high16 v0, 0x40000000
    if-lez p1, :b
    move v0, p0
    :b
    add-float v1, v0, v0
    const/4 v0, 0x5
    sput v0, LFpReuse;->sInt:I
    return v1
.end method
