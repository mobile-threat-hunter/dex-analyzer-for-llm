# dexllm#123 fixture: a move a call was folded into keeps the call's side effect.
#
# RegisterPropagation first folds `v1 = make()` into the move that copies it
# (`v0 = make()`). DAD's MoveExpression answers "no side effect" whatever its
# rhs, so the folded call was then carried past a side-effecting statement --
# the constructor ran AFTER the store in the decompiled text. Written in smali:
# the copy register is what d8 produces and javac does not.

.class public LD;
.super Ljava/lang/Object;

.field public static I:I

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static make()Ljava/lang/Object;
    .registers 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public static use(Ljava/lang/Object;)V
    .registers 1
    return-void
.end method

# a constructor, copied, then a static store, then the copy returned
.method public static ctorThenStore()LD;
    .registers 3
    new-instance v1, LD;
    invoke-direct {v1}, LD;-><init>()V
    move-object v0, v1
    const/4 v2, 0x5
    sput v2, LD;->I:I
    return-object v0
.end method

# the same with a plain call
.method public static callThenStore()Ljava/lang/Object;
    .registers 3
    invoke-static {}, LD;->make()Ljava/lang/Object;
    move-result-object v1
    move-object v0, v1
    const/4 v2, 0x5
    sput v2, LD;->I:I
    return-object v0
.end method

# the control: no store in between, the call folds all the way
.method public static callNoStore()Ljava/lang/Object;
    .registers 2
    invoke-static {}, LD;->make()Ljava/lang/Object;
    move-result-object v1
    move-object v0, v1
    return-object v0
.end method

# a plain register COPY, then a call folded into a move, then the copy used: the
# copy still propagates (a call cannot change a register), as it did before
.method public static copyAcrossFoldedCall()V
    .registers 4
    invoke-static {}, LD;->make()Ljava/lang/Object;
    move-result-object v1
    move-object v0, v1
    invoke-static {}, LD;->make()Ljava/lang/Object;
    move-result-object v2
    move-object v3, v2
    invoke-static {v3}, LD;->use(Ljava/lang/Object;)V
    invoke-static {v0}, LD;->use(Ljava/lang/Object;)V
    invoke-static {v1}, LD;->use(Ljava/lang/Object;)V
    return-void
.end method

# the copy's SOURCE is redefined before the copy is used: the copy must stay a
# copy (reading the source at the use would read the new value)
.method public static copySourceRedefined()V
    .registers 2
    invoke-static {}, LD;->make()Ljava/lang/Object;
    move-result-object v1
    move-object v0, v1
    invoke-static {v1}, LD;->use(Ljava/lang/Object;)V
    invoke-static {}, LD;->make()Ljava/lang/Object;
    move-result-object v1
    invoke-static {v1}, LD;->use(Ljava/lang/Object;)V
    invoke-static {v0}, LD;->use(Ljava/lang/Object;)V
    return-void
.end method

.field public f:Ljava/lang/Object;

.method public change()V
    .registers 2
    const/4 v0, 0x0
    iput-object v0, p0, LD;->f:Ljava/lang/Object;
    return-void
.end method

# a FIELD READ folded into a move is not a plain copy: a call in between may
# change the field, so the read must stay before the call
.method public fieldAcrossCall()V
    .registers 3
    iget-object v1, p0, LD;->f:Ljava/lang/Object;
    move-object v0, v1
    invoke-virtual {p0}, LD;->change()V
    invoke-static {v0}, LD;->use(Ljava/lang/Object;)V
    return-void
.end method

.method public static useI(I)V
    .registers 1
    return-void
.end method

# a copy inside a loop whose source is redefined before the copy is read: the
# source keeps ONE name around the loop (its versions merge), so only the
# redefinition check keeps the copy from reading the new value
.method public static copyInLoop()V
    .registers 2
    const/4 v1, 0x0
    :loop
    move v0, v1
    add-int/lit8 v1, v1, 0x1
    invoke-static {v0}, LD;->useI(I)V
    const/4 v0, 0x3
    if-lt v1, v0, :loop
    return-void
.end method

# a copy carried across a call into a ONE-block loop whose block redefines the
# copy's source AFTER the use: on the second iteration the source holds the new
# value, so the copy must not be replaced by it (the use's own block reaches the
# use again over its back edge)
.method public static loopCopy(Z)V
    .registers 3
    invoke-static {}, LD;->make()Ljava/lang/Object;
    move-result-object v1
    move-object v0, v1
    invoke-static {}, LD;->make()Ljava/lang/Object;
    :H
    invoke-static {v0}, LD;->use(Ljava/lang/Object;)V
    invoke-static {v1}, LD;->use(Ljava/lang/Object;)V
    const-string v1, "x"
    if-eqz p0, :H
    return-void
.end method

# the same with no call in between: DAD propagates the copy here too
.method public static loopNoCall(Z)V
    .registers 3
    invoke-static {}, LD;->make()Ljava/lang/Object;
    move-result-object v1
    move-object v0, v1
    :H
    invoke-static {v0}, LD;->use(Ljava/lang/Object;)V
    invoke-static {v1}, LD;->use(Ljava/lang/Object;)V
    const-string v1, "x"
    if-eqz p0, :H
    return-void
.end method

# a call defined before a loop and read in it runs ONCE: it must not move into
# the loop, where it would run once per iteration
.method public static callIntoLoop()V
    .registers 3
    invoke-static {}, LD;->make()Ljava/lang/Object;
    move-result-object v2
    const/4 v0, 0x0
    :H
    invoke-static {v2}, LD;->use(Ljava/lang/Object;)V
    add-int/lit8 v0, v0, 0x1
    const/4 v1, 0x3
    if-lt v0, v1, :H
    return-void
.end method

# a field read before a loop whose body changes the field: the read stays out
.method public fieldIntoLoop()V
    .registers 4
    iget-object v2, p0, LD;->f:Ljava/lang/Object;
    const/4 v0, 0x0
    :H
    invoke-static {v2}, LD;->use(Ljava/lang/Object;)V
    invoke-virtual {p0}, LD;->change()V
    add-int/lit8 v0, v0, 0x1
    const/4 v1, 0x3
    if-lt v0, v1, :H
    return-void
.end method

# a plain copy before a loop whose body has a call but leaves the source alone:
# a call cannot change a register, so the copy still folds
.method public static copyIntoLoop()V
    .registers 4
    invoke-static {}, LD;->make()Ljava/lang/Object;
    move-result-object v3
    move-object v2, v3
    const/4 v0, 0x0
    :H
    invoke-static {v2}, LD;->use(Ljava/lang/Object;)V
    invoke-static {}, LD;->make()Ljava/lang/Object;
    add-int/lit8 v0, v0, 0x1
    const/4 v1, 0x3
    if-lt v0, v1, :H
    invoke-static {v3}, LD;->use(Ljava/lang/Object;)V
    return-void
.end method

# the definition is in the loop, in another block: it runs again on the way
# round, so the tail's redefinition of its source does not matter
.method public static defInLoop(I)V
    .registers 4
    const/4 v1, 0x0
    :H
    add-int/lit8 v0, v1, 0x7
    if-eqz p0, :U
    const/4 v2, 0x1
    :U
    invoke-static {v0}, LD;->useI(I)V
    add-int/lit8 v1, v1, 0x1
    const/4 v2, 0x3
    if-lt v1, v2, :H
    return-void
.end method

# the loop body ends in a goto, so the source's redefinition is the LAST
# instruction of the use's block (a goto is not an instruction of the block)
.method public static loopGoto(Z)V
    .registers 3
    invoke-static {}, LD;->make()Ljava/lang/Object;
    move-result-object v1
    move-object v0, v1
    :H
    if-eqz p0, :X
    invoke-static {v0}, LD;->use(Ljava/lang/Object;)V
    invoke-static {v1}, LD;->use(Ljava/lang/Object;)V
    const-string v1, "x"
    goto :H
    :X
    return-void
.end method

.method public static num()I
    .registers 1
    const/4 v0, 0x1
    return v0
.end method

# a call before a loop read in the loop by an instruction with no side effect of
# its own (an add): the call must still not move in
.method public static callIntoLoopArith()V
    .registers 4
    invoke-static {}, LD;->num()I
    move-result v2
    const/4 v0, 0x0
    :H
    add-int v3, v2, v0
    add-int/lit8 v0, v0, 0x1
    const/4 v1, 0x3
    if-lt v0, v1, :H
    invoke-static {v3}, LD;->useI(I)V
    return-void
.end method

.field public static G:I

# a static field read, then a store to the field, then the read value: the read
# names no register, so nothing used to keep it before the store (d8 emits this
# for `int x = G; G = 7; use(x);`)
.method public static sgetThenPut()V
    .registers 2
    sget v0, LD;->G:I
    const/4 v1, 0x7
    sput v1, LD;->G:I
    invoke-static {v0}, LD;->useI(I)V
    return-void
.end method

# the same read before a loop that stores to the field
.method public static sgetIntoLoop(I)V
    .registers 3
    sget v0, LD;->G:I
    const/4 v1, 0x0
    :H
    invoke-static {v0}, LD;->useI(I)V
    sput v1, LD;->G:I
    add-int/lit8 v1, v1, 0x1
    if-lt v1, p0, :H
    return-void
.end method

.method public static wrap(Ljava/lang/Object;)Ljava/lang/Object;
    .registers 1
    return-object p0
.end method

# a call with an argument, folded into a move, read inside a try: the call is
# outside the try in the bytecode, so its exception is not the handler's
.method public static callIntoTry(Ljava/lang/Object;)V
    .registers 3
    invoke-static {p0}, LD;->wrap(Ljava/lang/Object;)Ljava/lang/Object;
    move-result-object v1
    move-object v0, v1
    :ts
    invoke-static {v0}, LD;->use(Ljava/lang/Object;)V
    :te
    .catch Ljava/lang/RuntimeException; {:ts .. :te} :h
    return-void
    :h
    return-void
.end method

# a static field read across a CALL (which may write any static field): kept
.method public static sgetPastCall()V
    .registers 1
    sget v0, LD;->G:I
    invoke-static {}, LD;->make()Ljava/lang/Object;
    invoke-static {v0}, LD;->useI(I)V
    return-void
.end method

# a static field read across an array store (which cannot write a static
# field): it still folds into its use
.method public static sgetPastArrayStore([I)V
    .registers 3
    sget v0, LD;->G:I
    const/4 v1, 0x0
    aput v1, p0, v1
    invoke-static {v0}, LD;->useI(I)V
    return-void
.end method
