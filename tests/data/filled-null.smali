# dexllm#117 fixture: a `filled-new-array` element is a typed position.
#
# Each method builds one array with filled-new-array and returns it, so the
# element the case is about is the only thing that can differ. Written in smali
# because the shapes are the point: javac emits `aconst_null`-style code that d8
# turns into the same filled-new-array only sometimes, and never with one
# register shared between an int[] and an Object[].

.class public LFilledNull;
.super Ljava/lang/Object;

# Object[] {p0, null} -- the issue's shape (HandlerDispatcherKt.asHandler)
.method public static refNull(Ljava/lang/Object;)[Ljava/lang/Object;
    .registers 3
    const/4 v0, 0x0
    filled-new-array {p0, v0}, [Ljava/lang/Object;
    move-result-object v1
    return-object v1
.end method

# String[] {null, "a"} -- a null FIRST, at a more precise element type
.method public static strNullFirst()[Ljava/lang/String;
    .registers 3
    const/4 v0, 0x0
    const-string v1, "a"
    filled-new-array {v0, v1}, [Ljava/lang/String;
    move-result-object v2
    return-object v2
.end method

# int[] {0, 1} -- the control: an int element stays an int
.method public static intZero()[I
    .registers 3
    const/4 v0, 0x0
    const/4 v1, 0x1
    filled-new-array {v0, v1}, [I
    move-result-object v2
    return-object v2
.end method

# int[][] {null} -- an array-typed element is a reference too
.method public static nestedNull()[[I
    .registers 2
    const/4 v0, 0x0
    filled-new-array {v0}, [[I
    move-result-object v1
    return-object v1
.end method

# Object[] {1} -- a nonzero int cannot be a reference: ConstantAt leaves it the
# integer (ART would refuse this at class verification; the structural gate
# accepts it, and the text must not invent a value)
.method public static refOne()[Ljava/lang/Object;
    .registers 2
    const/4 v0, 0x1
    filled-new-array {v0}, [Ljava/lang/Object;
    move-result-object v1
    return-object v1
.end method

# one `const/4 v0, 0` read by an int[] AND an Object[]: one IR constant, two
# positions -- the int[] element is 0, the Object[] element is null
.method public static sharedZero()[Ljava/lang/Object;
    .registers 4
    const/4 v0, 0x0
    filled-new-array {v0}, [I
    move-result-object v1
    filled-new-array {v0, v1}, [Ljava/lang/Object;
    move-result-object v2
    return-object v2
.end method

# filled-new-array/range {v0 .. v2} -- dexllm#97: every register of the range is
# an element (the IR kept the bounds only), and dexllm#117: each zero is null
.method public static rangeNulls()[Ljava/lang/Object;
    .registers 4
    const/4 v0, 0x0
    const-string v1, "a"
    const/4 v2, 0x0
    filled-new-array/range {v0 .. v2}, [Ljava/lang/Object;
    move-result-object v3
    return-object v3
.end method

# filled-new-array/range {v0 .. v0} -- a range of ONE: DAD's two-bounds form
# put the same register in twice
.method public static rangeOne()[I
    .registers 2
    const/4 v0, 0x7
    filled-new-array/range {v0 .. v0}, [I
    move-result-object v1
    return-object v1
.end method

# filled-new-array/range {v0 .. v1} -- a range of TWO: the one width the
# two-bounds form happened to get right (the control)
.method public static rangeTwo()[I
    .registers 3
    const/4 v0, 0x7
    const/4 v1, 0x6
    filled-new-array/range {v0 .. v1}, [I
    move-result-object v2
    return-object v2
.end method
