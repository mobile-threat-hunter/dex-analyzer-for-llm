# dexllm#93 — a fill-array-data payload is spelled by its array's element type.
# Authored for this project; assembled with the smali assembler (see README).
.class public LF;
.super Ljava/lang/Object;

.method public static floats()[F
    .registers 2
    const/4 v0, 0x4
    new-array v0, v0, [F
    fill-array-data v0, :data
    return-object v0
    :data
    .array-data 4
        0x0
        0x3f800000
        0x3f000000
        0x7fc00000
    .end array-data
.end method

.method public static doubles()[D
    .registers 2
    const/4 v0, 0x3
    new-array v0, v0, [D
    fill-array-data v0, :data
    return-object v0
    :data
    .array-data 8
        0x0L
        0x3ff0000000000000L
        0xbff8000000000000L
    .end array-data
.end method

.method public static longs()[J
    .registers 2
    const/4 v0, 0x2
    new-array v0, v0, [J
    fill-array-data v0, :data
    return-object v0
    :data
    .array-data 8
        0x7fffffffffffffffL
        0x5L
    .end array-data
.end method

# control: an int[] payload stays integers
.method public static ints()[I
    .registers 2
    const/4 v0, 0x3
    new-array v0, v0, [I
    fill-array-data v0, :data
    return-object v0
    :data
    .array-data 4
        0x3f800000
        -0x1
        0x7
    .end array-data
.end method

# control: a char[] payload stays integers
.method public static chars()[C
    .registers 2
    const/4 v0, 0x2
    new-array v0, v0, [C
    fill-array-data v0, :data
    return-object v0
    :data
    .array-data 2
        0x41s
        0x42s
    .end array-data
.end method

.method public static obj()Ljava/lang/Object;
    .registers 1
    const/4 v0, 0x0
    return-object v0
.end method

# the array's type is unknown (an Object): the payload width decides, and an
# 8-byte element is a long
.method public static untypedTarget(Ljava/lang/Object;)V
    .registers 1
    fill-array-data p0, :data
    return-void
    :data
    .array-data 8
        0x7fffffffffffffffL
    .end array-data
.end method

# an int[] filled with 8-byte elements (ART rejects it at run time; the
# structural gate does not): the type disagrees with the width, so the width
# decides
.method public static mismatchedWidth()[I
    .registers 2
    const/4 v0, 0x1
    new-array v0, v0, [I
    fill-array-data v0, :data
    return-object v0
    :data
    .array-data 8
        0x7fffffffffffffffL
    .end array-data
.end method

# an int[] parameter filled, then its register reused for a float[]: the later
# write corrupts the shared parameter's type, so the DECLARED type decides and
# the ints stay ints
.method public static intParamThenFloat([I)[F
    .registers 2
    fill-array-data p0, :data
    const/4 v0, 0x1
    new-array p0, v0, [F
    return-object p0
    :data
    .array-data 4
        0x7
        0x3f800000
    .end array-data
.end method

# a char is unsigned: 0xffff is 65535, not -1
.method public static highChar()[C
    .registers 2
    const/4 v0, 0x2
    new-array v0, v0, [C
    fill-array-data v0, :data
    return-object v0
    :data
    .array-data 2
        0xffffs
        0x41s
    .end array-data
.end method

.method public static bools()[Z
    .registers 2
    const/4 v0, 0x2
    new-array v0, v0, [Z
    fill-array-data v0, :data
    return-object v0
    :data
    .array-data 1
        0x1t
        0x0t
    .end array-data
.end method

# one register filled on two branches, as an int[] on one and a float[] on the
# other, then merged: each fill is spelled by the definition that reaches it
.method public static branchMerge(Z)Ljava/lang/Object;
    .registers 3
    const/4 v1, 0x2
    if-eqz p0, :ints
    new-array v0, v1, [F
    fill-array-data v0, :fdata
    goto :done
    :ints
    new-array v0, v1, [I
    fill-array-data v0, :idata
    :done
    return-object v0
    :fdata
    .array-data 4
        0x3f800000
        0x40000000
    .end array-data
    :idata
    .array-data 4
        0x3f800000
        0x7
    .end array-data
.end method

# the fill comes AFTER the merge, so two definitions of different types reach
# it (crafted: ART rejects the merged type): no single type, the width decides
.method public static fillAfterMerge(Z)Ljava/lang/Object;
    .registers 3
    const/4 v1, 0x2
    if-eqz p0, :ints
    new-array v0, v1, [F
    goto :done
    :ints
    new-array v0, v1, [I
    :done
    fill-array-data v0, :data
    return-object v0
    :data
    .array-data 4
        0x3f800000
        0x7
    .end array-data
.end method

# the same with the branches swapped, so neither definition's order can decide
.method public static fillAfterMergeSwapped(Z)Ljava/lang/Object;
    .registers 3
    const/4 v1, 0x2
    if-eqz p0, :floats
    new-array v0, v1, [I
    goto :done
    :floats
    new-array v0, v1, [F
    :done
    fill-array-data v0, :data
    return-object v0
    :data
    .array-data 4
        0x3f800000
        0x7
    .end array-data
.end method
