# dexllm#121 fixture: a move-object copy of an UNINITIALIZED new-instance.
#
# `new-instance vA` makes an uninitialized reference and `invoke-direct <init>`
# initializes that same object in place, so after the constructor every copy of
# vA refers to the constructed object. d8 emits such copies all the time: the
# /range form copies the allocation into the first register of the window and
# runs <init> on the COPY, and the enum <clinit> pattern copies it before the
# constructor and stores the copy in $VALUES. Written in smali because register
# reuse and the order of the copy cannot be pinned from Java.

.class public LAlias;
.super Ljava/lang/Object;

.field public static A:LAlias;
.field public static V:[LAlias;

.method public constructor <init>(Ljava/lang/String;I)V
    .registers 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

# one copy before construction, the copy goes into an array
.method public static oneCopy()V
    .registers 4
    new-instance v1, LAlias;
    move-object v0, v1
    const-string v2, "A"
    const/4 v3, 0x0
    invoke-direct {v1, v2, v3}, LAlias;-><init>(Ljava/lang/String;I)V
    sput-object v1, LAlias;->A:LAlias;
    filled-new-array {v0}, [LAlias;
    move-result-object v0
    sput-object v0, LAlias;->V:[LAlias;
    return-void
.end method

# the copy only
.method public static copyOnly()LAlias;
    .registers 4
    new-instance v1, LAlias;
    move-object v0, v1
    const-string v2, "A"
    const/4 v3, 0x0
    invoke-direct {v1, v2, v3}, LAlias;-><init>(Ljava/lang/String;I)V
    return-object v0
.end method

# no copy: the control
.method public static noCopy()LAlias;
    .registers 4
    new-instance v1, LAlias;
    const-string v2, "A"
    const/4 v3, 0x0
    invoke-direct {v1, v2, v3}, LAlias;-><init>(Ljava/lang/String;I)V
    return-object v1
.end method

# d8's /range shape: the <init> receiver is the COPY, the original is used after
.method public static recvIsCopy()LAlias;
    .registers 4
    new-instance v3, LAlias;
    const-string v1, "A"
    const/4 v2, 0x0
    move-object v0, v3
    invoke-direct/range {v0 .. v2}, LAlias;-><init>(Ljava/lang/String;I)V
    sput-object v3, LAlias;->A:LAlias;
    return-object v3
.end method

# a copy of a copy, receiver is the second copy
.method public static chain()LAlias;
    .registers 5
    new-instance v4, LAlias;
    move-object v3, v4
    move-object v0, v3
    const-string v1, "A"
    const/4 v2, 0x0
    invoke-direct {v0, v1, v2}, LAlias;-><init>(Ljava/lang/String;I)V
    sput-object v3, LAlias;->A:LAlias;
    return-object v4
.end method

# the copy's destination is overwritten before the <init>: must be left alone
.method public static destKilled()Ljava/lang/Object;
    .registers 4
    new-instance v1, LAlias;
    move-object v0, v1
    const-string v0, "B"
    const-string v2, "A"
    const/4 v3, 0x0
    invoke-direct {v1, v2, v3}, LAlias;-><init>(Ljava/lang/String;I)V
    sput-object v1, LAlias;->A:LAlias;
    return-object v0
.end method

# the receiver's register holds something else BEFORE it becomes the copy
# (androidx AlertController$AlertParams.createListView)
.method public static recvReused(Ljava/lang/String;)LAlias;
    .registers 5
    new-instance v3, LAlias;
    move-object v0, p0
    const/4 v2, 0x0
    move-object v1, v0
    move-object v0, v3
    invoke-direct {v0, v1, v2}, LAlias;-><init>(Ljava/lang/String;I)V
    return-object v3
.end method

# the alias passed as an ARGUMENT of its own <init>: invalid Dalvik (an
# uninitialized reference is not an argument), so the pass must refuse
.method public static aliasAsArg()LAlias;
    .registers 3
    new-instance v1, LAlias;
    move-object v0, v1
    const/4 v2, 0x0
    invoke-direct {v1, v0, v2}, LAlias;-><init>(Ljava/lang/String;I)V
    return-object v0
.end method

# the copy is read before the <init>: also invalid Dalvik; refused
.method public static readBetween()LAlias;
    .registers 4
    new-instance v1, LAlias;
    move-object v0, v1
    invoke-static {v0}, LAlias;->sink(Ljava/lang/Object;)V
    const-string v2, "A"
    const/4 v3, 0x0
    invoke-direct {v1, v2, v3}, LAlias;-><init>(Ljava/lang/String;I)V
    return-object v0
.end method

# the <init> is in another block (after a branch): out of the pass's scope
.method public static crossBlock(Z)LAlias;
    .registers 5
    new-instance v1, LAlias;
    move-object v0, v1
    const-string v2, "A"
    if-eqz p0, :zero
    const/4 v3, 0x1
    goto :go
    :zero
    const/4 v3, 0x0
    :go
    invoke-direct {v1, v2, v3}, LAlias;-><init>(Ljava/lang/String;I)V
    return-object v0
.end method

.method public static sink(Ljava/lang/Object;)V
    .registers 1
    return-void
.end method

# a PLAIN `move` of the uninitialized reference: a 32-bit-primitive move of a
# reference is invalid Dalvik, so the opcode does not prove the copy; refused
.method public static plainMove()LAlias;
    .registers 4
    new-instance v1, LAlias;
    move v0, v1
    const-string v2, "A"
    const/4 v3, 0x0
    invoke-direct {v1, v2, v3}, LAlias;-><init>(Ljava/lang/String;I)V
    return-object v0
.end method

# the allocation lands in the RECEIVER register of an instance method: DAD
# builds the <init> with no left-hand side when its base is `this`, so the
# constructor cannot be matched and the pass must refuse
.method public reuseThis()LAlias;
    .registers 4
    new-instance p0, LAlias;
    move-object v0, p0
    const-string v1, "A"
    const/4 v2, 0x0
    invoke-direct {p0, v1, v2}, LAlias;-><init>(Ljava/lang/String;I)V
    return-object v0
.end method

.field public static S:Ljava/lang/String;

# the /range receiver is a scratch register that later holds a String
# (a2dp.Vol service.DoDisconnected): the object's type must not follow it
.method public static recvLaterString()LAlias;
    .registers 8
    new-instance v7, LAlias;
    const-string v1, "A"
    const/4 v2, 0x0
    move-object v0, v7
    invoke-direct/range {v0 .. v2}, LAlias;-><init>(Ljava/lang/String;I)V
    sput-object v7, LAlias;->A:LAlias;
    const-string v0, "zz"
    sput-object v0, LAlias;->S:Ljava/lang/String;
    return-object v7
.end method

.field public static I:I

# the copy SURVIVES as its own statement (stored to a second field), and its
# register is later reused for an int: the move-opcode kind and the type the
# copy's register is declared with are what this case is about
.method public static copyLaterInt()V
    .registers 4
    new-instance v1, LAlias;
    move-object v0, v1
    const-string v2, "A"
    const/4 v3, 0x0
    invoke-direct {v1, v2, v3}, LAlias;-><init>(Ljava/lang/String;I)V
    sput-object v1, LAlias;->A:LAlias;
    filled-new-array {v0}, [LAlias;
    move-result-object v2
    sput-object v2, LAlias;->V:[LAlias;
    sput-object v0, LAlias;->A:LAlias;
    const/4 v0, 0x5
    sput v0, LAlias;->I:I
    return-void
.end method

# the /range receiver register is an int elsewhere, and after the <init>
# nothing reads it (kotlin FileTreeWalk / NotificationCompat$CarExtender): a
# re-made `v3 = v0` would be a dead definition that keeps v3 from being split,
# so its int version would take the object's type -- the copy must be dropped
.method public static deadRecv(ZLjava/lang/String;)Ljava/lang/Object;
    .registers 8
    const/4 v1, 0x0
    if-nez p0, :c2
    const/4 v2, 0x0
    const/4 v3, 0x1
    if-eqz p1, :a
    move v2, v3
    :a
    if-eqz v2, :b
    return-object v1
    :b
    return-object p1
    :c2
    new-instance v0, LAlias;
    const/4 v5, 0x0
    move-object v3, v0
    move-object v4, p1
    invoke-direct/range {v3 .. v5}, LAlias;-><init>(Ljava/lang/String;I)V
    invoke-static {v0}, LAlias;->sink(Ljava/lang/Object;)V
    return-object v1
.end method

# the /range receiver copy IS read after the <init>, in another block: it is
# kept, reading the constructed object
.method public static liveRecv(Z)Ljava/lang/Object;
    .registers 5
    new-instance v0, LAlias;
    const-string v2, "A"
    const/4 v3, 0x0
    move-object v1, v0
    invoke-direct/range {v1 .. v3}, LAlias;-><init>(Ljava/lang/String;I)V
    sput-object v0, LAlias;->A:LAlias;
    if-eqz p0, :n
    return-object v1
    :n
    const/4 v1, 0x0
    return-object v1
.end method

# the receiver register is WRITTEN (an int) before anything reads it again:
# the copy is dead, so it is dropped and the int keeps its own type
.method public static recvKilled(Z)V
    .registers 5
    new-instance v0, LAlias;
    const-string v2, "A"
    const/4 v3, 0x0
    move-object v1, v0
    invoke-direct/range {v1 .. v3}, LAlias;-><init>(Ljava/lang/String;I)V
    sput-object v0, LAlias;->A:LAlias;
    const/4 v1, 0x7
    if-eqz p0, :x
    const/4 v1, 0x6
    :x
    sput v1, LAlias;->I:I
    return-void
.end method

# the receiver register is read only by an exception HANDLER of the call after
# the <init>: that is a read, so the copy is kept
.method public static recvInHandler()Ljava/lang/Object;
    .registers 4
    new-instance v0, LAlias;
    const-string v2, "A"
    const/4 v3, 0x0
    move-object v1, v0
    invoke-direct/range {v1 .. v3}, LAlias;-><init>(Ljava/lang/String;I)V
    :ts
    invoke-static {v0}, LAlias;->sink(Ljava/lang/Object;)V
    :te
    .catch Ljava/lang/RuntimeException; {:ts .. :te} :h
    const/4 v0, 0x0
    return-object v0
    :h
    move-exception v2
    return-object v1
.end method

# deadRecv, but the receiver register is also WRITTEN then read after the
# <init>: still dead at the <init>, so still dropped (a liveness walk that did
# not stop at that write would keep it and leak the object's type into v2)
.method public static deadRecvKilled(ZLjava/lang/String;)Ljava/lang/Object;
    .registers 8
    const/4 v1, 0x0
    if-nez p0, :c2
    const/4 v2, 0x0
    const/4 v3, 0x1
    if-eqz p1, :a
    move v2, v3
    :a
    if-eqz v2, :b
    return-object v1
    :b
    return-object p1
    :c2
    new-instance v0, LAlias;
    const/4 v5, 0x0
    move-object v3, v0
    move-object v4, p1
    invoke-direct/range {v3 .. v5}, LAlias;-><init>(Ljava/lang/String;I)V
    invoke-static {v0}, LAlias;->sink(Ljava/lang/Object;)V
    const/4 v3, 0x2
    sput v3, LAlias;->I:I
    return-object v1
.end method
