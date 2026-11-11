# dexllm#124 — a call NESTED in an expression is a side effect too.
# Authored for this project; assembled with the smali assembler (see README).
.class public LN;
.super Ljava/lang/Object;

.field public static F:I
.field public f:I
.field public g:I

.method public static next()I
    .registers 1
    sget v0, LN;->F:I
    add-int/lit8 v0, v0, 0x1
    sput v0, LN;->F:I
    return v0
.end method

.method public static arr()[I
    .registers 1
    const/4 v0, 0x3
    new-array v0, v0, [I
    return-object v0
.end method

.method public static obj()Ljava/lang/Object;
    .registers 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public static mark()V
    .registers 0
    return-void
.end method

.method public static sinkJ(J)V
    .registers 2
    return-void
.end method

.method public static sinkI(I)V
    .registers 1
    return-void
.end method

.method public static two(Ljava/lang/Object;Ljava/lang/Object;)V
    .registers 2
    return-void
.end method

.method public mutate()I
    .registers 2
    const/4 v0, 0x7
    iput v0, p0, LN;->f:I
    return v0
.end method

# long t = (long) next(); for (..) sinkJ(t);  — the cast's call runs once
.method public static castIntoLoop(I)V
    .registers 5
    invoke-static {}, LN;->next()I
    move-result v0
    int-to-long v0, v0
    const/4 v2, 0x0
    :H
    invoke-static {v0, v1}, LN;->sinkJ(J)V
    add-int/lit8 v2, v2, 0x1
    if-lt v2, p0, :H
    return-void
.end method

# int n = arr().length; for (..) sinkI(n);
.method public static lengthIntoLoop(I)V
    .registers 3
    invoke-static {}, LN;->arr()[I
    move-result-object v0
    array-length v0, v0
    const/4 v1, 0x0
    :H
    invoke-static {v0}, LN;->sinkI(I)V
    add-int/lit8 v1, v1, 0x1
    if-lt v1, p0, :H
    return-void
.end method

# long t = (long) next(); mark(); sinkJ(t);  — next() runs before mark()
.method public static castPastCall()V
    .registers 2
    invoke-static {}, LN;->next()I
    move-result v0
    int-to-long v0, v0
    invoke-static {}, LN;->mark()V
    invoke-static {v0, v1}, LN;->sinkJ(J)V
    return-void
.end method

# int x = F; if (next() > 0) return x;  — F is read before next() runs
.method public static staticThenIf()I
    .registers 2
    sget v0, LN;->F:I
    invoke-static {}, LN;->next()I
    move-result v1
    if-lez v1, :Z
    return v0
    :Z
    const/4 v0, 0x0
    return v0
.end method

# int x = this.f; if (mutate() != 0) return x;
.method public fieldThenIf()I
    .registers 3
    iget v0, p0, LN;->f:I
    invoke-virtual {p0}, LN;->mutate()I
    move-result v1
    if-eqz v1, :Z
    return v0
    :Z
    const/4 v0, 0x0
    return v0
.end method

# int x = F; this.g = next(); return x;  — the store's value is a call
.method public staticPastFieldStore()I
    .registers 3
    sget v0, LN;->F:I
    invoke-static {}, LN;->next()I
    move-result v1
    iput v1, p0, LN;->g:I
    return v0
.end method

# Object o = obj(); two(o, o);  — one call, its value passed twice
.method public static readTwice()V
    .registers 1
    invoke-static {}, LN;->obj()Ljava/lang/Object;
    move-result-object v0
    invoke-static {v0, v0}, LN;->two(Ljava/lang/Object;Ljava/lang/Object;)V
    return-void
.end method

# int x = next(); return x * x;
.method public static square()I
    .registers 1
    invoke-static {}, LN;->next()I
    move-result v0
    mul-int/2addr v0, v0
    return v0
.end method

# the control: a call that stands as its own statement, read once — it folds
.method public static control()V
    .registers 2
    invoke-static {}, LN;->next()I
    move-result v0
    int-to-long v0, v0
    invoke-static {v0, v1}, LN;->sinkJ(J)V
    return-void
.end method

# long t = (long) next(); try { sinkJ(t); } catch (RuntimeException e) {}
# — next() is outside the try, so its exception is not the handler's
.method public static castIntoTry()V
    .registers 3
    invoke-static {}, LN;->next()I
    move-result v0
    int-to-long v0, v0
    :ts
    invoke-static {v0, v1}, LN;->sinkJ(J)V
    :te
    .catch Ljava/lang/RuntimeException; {:ts .. :te} :h
    return-void
    :h
    return-void
.end method

.field public w:J
.field public w2:J

# int x = F; long t = (long) next(); this.w = t; this.w2 = t; return x;
# — the only call between is nested in an assignment's rhs (kept because t is
# read twice); the field stores cannot write F
.method public staticPastAssignedCall()I
    .registers 5
    sget v0, LN;->F:I
    invoke-static {}, LN;->next()I
    move-result v1
    int-to-long v2, v1
    iput-wide v2, p0, LN;->w:J
    iput-wide v2, p0, LN;->w2:J
    return v0
.end method

.field public self:LN;

# int i = next(); a[i] = i;  — one call, an aput reading it as index and value
.method public static aputSame([I)V
    .registers 2
    invoke-static {}, LN;->next()I
    move-result v0
    aput v0, p0, v0
    return-void
.end method

.method public static mk()LN;
    .registers 1
    new-instance v0, LN;
    invoke-direct {v0}, LN;-><init>()V
    return-object v0
.end method

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

# N n = mk(); n.self = n;  — an iput reading it as object and value
.method public static iputSame()V
    .registers 1
    invoke-static {}, LN;->mk()LN;
    move-result-object v0
    iput-object v0, v0, LN;->self:LN;
    return-void
.end method

# int x = next(); if (x != x) ...  — a condition reading it twice
.method public static ifSame()I
    .registers 1
    invoke-static {}, LN;->next()I
    move-result v0
    if-ne v0, v0, :Z
    const/4 v0, 0x1
    return v0
    :Z
    const/4 v0, 0x0
    return v0
.end method

# int x = a[0]; <fill a with {7, 8}>; sinkI(x);  — fill-array-data writes a
.method public static readBeforeFill([I)V
    .registers 3
    const/4 v1, 0x0
    aget v0, p0, v1
    fill-array-data p0, :D
    invoke-static {v0}, LN;->sinkI(I)V
    return-void
    :D
    .array-data 4
        0x7
        0x8
    .end array-data
.end method
