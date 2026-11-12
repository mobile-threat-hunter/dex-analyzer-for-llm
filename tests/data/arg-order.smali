# dexllm#125 — an operand Java evaluates EARLIER must not hold an expression
# that ran LATER in the bytecode when the two touch the same memory.
# Authored for this project; assembled with the smali assembler (see README).
.class public LW;
.super Ljava/lang/Object;

.field public static F:I
.field public static OBJ:LW;
.field public f:I
.field public final ff:I
.field public final gg:I
.field public static final FF:I
.field public static final HH:I

.method public constructor <init>(I)V
    .registers 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput p1, p0, LW;->ff:I
    # inside W's own initializer a final field can still change: stays ordered
    iget v0, p0, LW;->ff:I
    invoke-virtual {p0}, LW;->mutate()I
    move-result v1
    invoke-static {v1, v0}, LW;->useII(II)V
    return-void
.end method

.method public static next()I
    .registers 1
    sget v0, LW;->F:I
    add-int/lit8 v0, v0, 0x1
    sput v0, LW;->F:I
    return v0
.end method

.method public static a()I
    .registers 1
    const/4 v0, 0x1
    return v0
.end method

.method public static b()I
    .registers 1
    const/4 v0, 0x2
    return v0
.end method

.method public static arr()[I
    .registers 1
    const/4 v0, 0x3
    new-array v0, v0, [I
    return-object v0
.end method

.method public mutate()I
    .registers 2
    const/4 v0, 0x7
    iput v0, p0, LW;->f:I
    return v0
.end method

.method public m(I)V
    .registers 2
    return-void
.end method

.method public static useJI(JI)V
    .registers 3
    return-void
.end method

.method public static useII(II)V
    .registers 2
    return-void
.end method

.method public static useI(I)V
    .registers 1
    return-void
.end method

# int x = F; useJI((long) next(), x);  -- the issue's shape
.method public static castThenStatic()V
    .registers 4
    sget v0, LW;->F:I
    invoke-static {}, LW;->next()I
    move-result v1
    int-to-long v2, v1
    invoke-static {v2, v3, v0}, LW;->useJI(JI)V
    return-void
.end method

# int x = F; useII(next() + 1, x);
.method public static arithThenStatic()V
    .registers 3
    sget v0, LW;->F:I
    invoke-static {}, LW;->next()I
    move-result v1
    add-int/lit8 v2, v1, 0x1
    invoke-static {v2, v0}, LW;->useII(II)V
    return-void
.end method

# control: next() runs first, then F is read -- useII(next(), F) is the same order
.method public static callFirst()V
    .registers 2
    invoke-static {}, LW;->next()I
    move-result v1
    sget v0, LW;->F:I
    invoke-static {v1, v0}, LW;->useII(II)V
    return-void
.end method

# int x = this.f; useII(mutate(), x);
.method public instanceThenCall()V
    .registers 3
    iget v0, p0, LW;->f:I
    invoke-virtual {p0}, LW;->mutate()I
    move-result v1
    invoke-static {v1, v0}, LW;->useII(II)V
    return-void
.end method

# int x = a[0]; useII(next(), x);  (next() does not write a, but a call may)
.method public static elementThenCall([I)V
    .registers 4
    const/4 v2, 0x0
    aget v0, p0, v2
    invoke-static {}, LW;->next()I
    move-result v1
    invoke-static {v1, v0}, LW;->useII(II)V
    return-void
.end method

# int x = a(); useII(b(), x);  -- two calls swapped
.method public static twoCallsSwapped()V
    .registers 2
    invoke-static {}, LW;->a()I
    move-result v0
    invoke-static {}, LW;->b()I
    move-result v1
    invoke-static {v1, v0}, LW;->useII(II)V
    return-void
.end method

# control: useII(a(), b()) in bytecode order
.method public static twoCallsInOrder()V
    .registers 2
    invoke-static {}, LW;->a()I
    move-result v0
    invoke-static {}, LW;->b()I
    move-result v1
    invoke-static {v0, v1}, LW;->useII(II)V
    return-void
.end method

# int x = F; useI(next() + x);  -- binary operands
.method public static binaryOperands()V
    .registers 3
    sget v0, LW;->F:I
    invoke-static {}, LW;->next()I
    move-result v1
    add-int v2, v1, v0
    invoke-static {v2}, LW;->useI(I)V
    return-void
.end method

# int v = next(); arr()[0] = v;  -- the array is evaluated before the value
.method public static storeValueFirst()V
    .registers 3
    invoke-static {}, LW;->next()I
    move-result v0
    invoke-static {}, LW;->arr()[I
    move-result-object v1
    const/4 v2, 0x0
    aput v0, v1, v2
    return-void
.end method

# control: the receiver is evaluated first, and it was read first: OBJ.m(next())
.method public static receiverFirst()V
    .registers 2
    sget-object v0, LW;->OBJ:LW;
    invoke-static {}, LW;->next()I
    move-result v1
    invoke-virtual {v0, v1}, LW;->m(I)V
    return-void
.end method

# int x = this.ff; useII(mutate(), x);  -- ff is final: no call can change it
.method public finalInstanceThenCall()V
    .registers 3
    iget v0, p0, LW;->ff:I
    invoke-virtual {p0}, LW;->mutate()I
    move-result v1
    invoke-static {v1, v0}, LW;->useII(II)V
    return-void
.end method

# int x = FF; useII(next(), x);  -- FF is final
.method public static finalStaticThenCall()V
    .registers 2
    sget v0, LW;->FF:I
    invoke-static {}, LW;->next()I
    move-result v1
    invoke-static {v1, v0}, LW;->useII(II)V
    return-void
.end method

# W r = OBJ is read AFTER next() ran, but Java evaluates the receiver first:
# int x = next(); OBJ.m(x);
.method public static receiverAfterCall()V
    .registers 2
    invoke-static {}, LW;->next()I
    move-result v1
    sget-object v0, LW;->OBJ:LW;
    invoke-virtual {v0, v1}, LW;->m(I)V
    return-void
.end method

# int y = next(); int x = this.ff; useII(x, y); useI(x);  -- x stays a
# statement (two uses); moving next() past a FINAL field read changes nothing
.method public callPastFinalRead()V
    .registers 3
    invoke-static {}, LW;->next()I
    move-result v1
    iget v0, p0, LW;->ff:I
    invoke-static {v0, v1}, LW;->useII(II)V
    invoke-static {v0}, LW;->useI(I)V
    return-void
.end method

# the same with a non-final field: next() stays before the read
.method public callPastRead()V
    .registers 3
    invoke-static {}, LW;->next()I
    move-result v1
    iget v0, p0, LW;->f:I
    invoke-static {v0, v1}, LW;->useII(II)V
    invoke-static {v0}, LW;->useI(I)V
    return-void
.end method

# gg is final but setGG(), an ordinary method of W, writes it -- ART allows a
# class to write its own final field -- so its read stays ordered
.method public setGG()I
    .registers 2
    const/4 v0, 0x7
    iput v0, p0, LW;->gg:I
    return v0
.end method

# int x = this.gg; useII(setGG(), x);
.method public writtenFinalThenCall()V
    .registers 3
    iget v0, p0, LW;->gg:I
    invoke-virtual {p0}, LW;->setGG()I
    move-result v1
    invoke-static {v1, v0}, LW;->useII(II)V
    return-void
.end method

# int x = V.X; useII(next(), x);  -- V.X is final, but reading it first runs
# V.<clinit>, so it stays before next()
.method public static otherClassStaticFinal()V
    .registers 2
    sget v0, LV;->X:I
    invoke-static {}, LW;->next()I
    move-result v1
    invoke-static {v1, v0}, LW;->useII(II)V
    return-void
.end method

# HH is a static final W itself writes outside <clinit> (sput in setHH)
.method public static setHH()I
    .registers 1
    const/4 v0, 0x5
    sput v0, LW;->HH:I
    return v0
.end method

# int x = HH; useII(setHH(), x);
.method public static writtenStaticFinalThenCall()V
    .registers 2
    sget v0, LW;->HH:I
    invoke-static {}, LW;->setHH()I
    move-result v1
    invoke-static {v1, v0}, LW;->useII(II)V
    return-void
.end method

# int x = F; int y = next(); int z = x (two plain copies); useII(y, z); useI(z);
# folding the copies re-points a MoveExpression's operand and leaves the old
# id in its var_map: that must not read as an operand of unknown order
.method public static copyChainThenCall()V
    .registers 4
    sget v0, LW;->F:I
    invoke-static {}, LW;->next()I
    move-result v3
    move v1, v0
    move v2, v1
    invoke-static {v3, v2}, LW;->useII(II)V
    invoke-static {v2}, LW;->useI(I)V
    return-void
.end method

# control: the same copies with no call -- they fold away
.method public static copyChainNoCall()V
    .registers 3
    sget v0, LW;->F:I
    move v1, v0
    move v2, v1
    invoke-static {v2}, LW;->useI(I)V
    invoke-static {v2}, LW;->useI(I)V
    return-void
.end method
