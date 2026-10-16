# dexllm#102 fixture — an untyped Dalvik constant, and a flag register, at a
# position whose DECLARED type is boolean / a reference / byte-short-char.
# Hand-written smali: register reuse and the merge shapes cannot be pinned
# from Java.  One method per (position, type); NEGATIVES keep the bytecode
# shape at an int position.
.class public LTypedPositions;
.super Ljava/lang/Object;

.field static sZ:Z
.field static sRef:Ljava/lang/Object;
.field iZ:Z
.field iRef:Ljava/lang/Object;
.field iC:C
.field iI:I
.field iF:F

.method static takeZ(Z)V
    .registers 1
    return-void
.end method
.method static takeRef(Ljava/lang/Object;)V
    .registers 1
    return-void
.end method
.method static takeStr(Ljava/lang/String;)V
    .registers 1
    return-void
.end method
.method static takeB(B)V
    .registers 1
    return-void
.end method
.method static takeS(S)V
    .registers 1
    return-void
.end method
.method static takeI(I)V
    .registers 1
    return-void
.end method
.method static takeZI(ZI)V
    .registers 2
    return-void
.end method
.method static takeVoids([Ljava/lang/Void;)V
    .registers 1
    return-void
.end method
.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public constructor <init>(ZLjava/lang/Object;)V
    .registers 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

# ---- invocation context ----
.method static argTrue()V
    .registers 1
    const/4 v0, 0x1
    invoke-static {v0}, LTypedPositions;->takeZ(Z)V
    return-void
.end method
.method static argFalse()V
    .registers 1
    const/4 v0, 0x0
    invoke-static {v0}, LTypedPositions;->takeZ(Z)V
    return-void
.end method
.method static argNull()V
    .registers 1
    const/4 v0, 0x0
    invoke-static {v0}, LTypedPositions;->takeRef(Ljava/lang/Object;)V
    return-void
.end method
.method static argNullStr()V
    .registers 1
    const/4 v0, 0x0
    invoke-static {v0}, LTypedPositions;->takeStr(Ljava/lang/String;)V
    return-void
.end method
.method static argChar(Ljava/lang/StringBuilder;)Ljava/lang/String;
    .registers 2
    const/16 v0, 0x7d
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;
    move-result-object v0
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method
.method static argByte()V
    .registers 1
    const/4 v0, -0x1
    invoke-static {v0}, LTypedPositions;->takeB(B)V
    return-void
.end method
.method static argShort()V
    .registers 1
    const/16 v0, 0x1f4
    invoke-static {v0}, LTypedPositions;->takeS(S)V
    return-void
.end method
.method static ctorArgs()Ljava/lang/Object;
    .registers 4
    new-instance v0, LTypedPositions;
    const/4 v1, 0x1
    const/4 v2, 0x0
    invoke-direct {v0, v1, v2}, LTypedPositions;-><init>(ZLjava/lang/Object;)V
    return-object v0
.end method
# one register, one call, two declared types: `true` AND `1`
.method static mixed()V
    .registers 1
    const/4 v0, 0x1
    invoke-static {v0, v0}, LTypedPositions;->takeZI(ZI)V
    return-void
.end method

# ---- assignment context ----
.method fieldTrue()V
    .registers 2
    const/4 v0, 0x1
    iput-boolean v0, p0, LTypedPositions;->iZ:Z
    return-void
.end method
.method static staticFalse()V
    .registers 1
    const/4 v0, 0x0
    sput-boolean v0, LTypedPositions;->sZ:Z
    return-void
.end method
.method fieldNull()V
    .registers 2
    const/4 v0, 0x0
    iput-object v0, p0, LTypedPositions;->iRef:Ljava/lang/Object;
    return-void
.end method
.method static staticNull()V
    .registers 1
    const/4 v0, 0x0
    sput-object v0, LTypedPositions;->sRef:Ljava/lang/Object;
    return-void
.end method
.method static aputTrue([Z)V
    .registers 3
    const/4 v0, 0x0
    const/4 v1, 0x1
    aput-boolean v1, p0, v0
    return-void
.end method
.method static aputNull([Ljava/lang/Object;)V
    .registers 3
    const/4 v0, 0x1
    const/4 v1, 0x0
    aput-object v1, p0, v0
    return-void
.end method
.method static throwNull()V
    .registers 1
    const/4 v0, 0x0
    throw v0
.end method
.method static checkCastNull()V
    .registers 1
    const/4 v0, 0x0
    check-cast v0, [Ljava/lang/Void;
    invoke-static {v0}, LTypedPositions;->takeVoids([Ljava/lang/Void;)V
    return-void
.end method
.method static retTrue()Z
    .registers 1
    const/4 v0, 0x1
    return v0
.end method
.method static retNull()Ljava/lang/Object;
    .registers 1
    const/4 v0, 0x0
    return-object v0
.end method

# ---- negatives: the same constants at int / char positions ----
.method static argInt()V
    .registers 1
    const/4 v0, 0x1
    invoke-static {v0}, LTypedPositions;->takeI(I)V
    return-void
.end method
.method fieldInt()V
    .registers 2
    const/4 v0, 0x0
    iput v0, p0, LTypedPositions;->iI:I
    return-void
.end method
# assignment context: Java narrows a constant here, so no cast
.method fieldChar()V
    .registers 2
    const/16 v0, 0x78
    iput-char v0, p0, LTypedPositions;->iC:C
    return-void
.end method
.method static retChar()C
    .registers 1
    const/16 v0, 0x79
    return v0
.end method
# values Java cannot spell at that position: left as the integer
.method static argTwoAtZ()V
    .registers 1
    const/4 v0, 0x2
    invoke-static {v0}, LTypedPositions;->takeZ(Z)V
    return-void
.end method
.method static argOneAtRef()V
    .registers 1
    const/4 v0, 0x1
    invoke-static {v0}, LTypedPositions;->takeRef(Ljava/lang/Object;)V
    return-void
.end method

# ---- the VARIABLE half ----
# a flag reaching a Z parameter
.method static varZ(Ljava/lang/Object;)V
    .registers 2
    if-eqz p0, :a
    const/4 v0, 0x1
    goto :b
    :a
    const/4 v0, 0x0
    :b
    invoke-static {v0}, LTypedPositions;->takeZ(Z)V
    return-void
.end method
# a flag stored into a Z field
.method varField(Ljava/lang/Object;)V
    .registers 3
    if-eqz p1, :a
    const/4 v0, 0x0
    goto :b
    :a
    const/4 v0, 0x1
    :b
    iput-boolean v0, p0, LTypedPositions;->iZ:Z
    return-void
.end method
# a flag stored by aput-boolean
.method static varAput([ZLjava/lang/Object;)V
    .registers 4
    const/4 v1, 0x0
    if-eqz p1, :a
    const/4 v0, 0x1
    goto :b
    :a
    const/4 v0, 0x0
    :b
    aput-boolean v0, p0, v1
    return-void
.end method
# AdapterHelper.onItemRangeInserted: v0 is compared and passed at an int
# parameter, but only the constant 1 reaches those uses; the flag it is moved
# into is returned from a Z method
.method static loneConstUses(ILjava/util/List;)Z
    .registers 5
    const/4 v1, 0x0
    const/4 v0, 0x1
    if-ge p0, v0, :go
    return v1
    :go
    invoke-static {v0}, LTypedPositions;->takeI(I)V
    invoke-interface {p1}, Ljava/util/List;->size()I
    move-result v2
    if-ne v2, v0, :zero
    :done
    move v1, v0
    goto :ret
    :zero
    move v0, v1
    goto :done
    :ret
    return v1
.end method
# CoordinatorLayout.offsetChildToAnchor: a flag moved INTO a destination that
# is only tested — both ends of the move must be boolean
.method static forwardMove(Ljava/lang/Object;)V
    .registers 3
    const/4 v1, 0x0
    if-eqz p0, :b
    const/4 v1, 0x1
    :b
    invoke-static {v1}, LTypedPositions;->takeZ(Z)V
    move v0, v1
    if-eqz v0, :c
    invoke-static {}, LTypedPositions;->argTrue()V
    :c
    return-void
.end method
# the move destination SURVIVES RegisterPropagation (its source register is
# reused before the use), so only the FORWARD propagation can type it
.method static forwardKeep(Ljava/lang/Object;)V
    .registers 3
    const/4 v1, 0x0
    if-eqz p0, :b
    const/4 v1, 0x1
    :b
    invoke-static {v1}, LTypedPositions;->takeZ(Z)V
    move v0, v1
    const/16 v1, 0x7
    invoke-static {v1}, LTypedPositions;->takeI(I)V
    if-eqz v0, :c
    invoke-static {}, LTypedPositions;->argTrue()V
    :c
    return-void
.end method
# `v == <nonzero constant>` is a numeric use, but only the constant 1 reaches
# it here; the version is the flag the Z method returns
.method static eqneLone(I)Z
    .registers 3
    const/4 v0, 0x1
    const/4 v1, 0x5
    if-eq v0, v1, :x
    if-eqz p0, :x
    goto :r
    :x
    const/4 v0, 0x0
    :r
    return v0
.end method
# int-reuse.dex sharedConst: the flag's source is ALSO moved into an int index,
# so neither end may become boolean
.method static componentRefused(Ljava/lang/String;Z[I)V
    .registers 6
    const/4 v0, 0x0
    if-eqz p1, :z
    const/4 v0, 0x1
    :z
    invoke-static {v0}, LTypedPositions;->takeZ(Z)V
    invoke-virtual {p0}, Ljava/lang/String;->length()I
    move-result v2
    if-eqz p1, :c
    move v2, v0
    :c
    aget v3, p2, v2
    invoke-static {v3}, LTypedPositions;->takeI(I)V
    return-void
.end method
# Tx3gDecoder.decodeInitializationData: two constant sources, one a flag, one
# an int, moved into a register whose LAST write is a float
.method mixedWidthSources(I)V
    .registers 8
    const/4 v4, 0x1
    const/4 v5, 0x0
    iput v5, p0, LTypedPositions;->iI:I
    sput-boolean v5, LTypedPositions;->sZ:Z
    if-eqz p1, :zero
    move v3, v4
    :set
    iput-boolean v3, p0, LTypedPositions;->iZ:Z
    iget v2, p0, LTypedPositions;->iI:I
    int-to-float v3, v2
    iput v3, p0, LTypedPositions;->iF:F
    return-void
    :zero
    move v3, v5
    goto :set
.end method

# dexllm#102 review: a narrowing cast must not CHANGE the value. ART checks only
# the category at a narrow parameter, so these are legal dex whose callee
# receives 200 / 40000 / -1; `(byte) 200` would say -56. They stay the integer.
.method static argByteOut()V
    .registers 1
    const/16 v0, 0xc8
    invoke-static {v0}, LTypedPositions;->takeB(B)V
    return-void
.end method
.method static argShortOut()V
    .registers 1
    const v0, 0x9c40
    invoke-static {v0}, LTypedPositions;->takeS(S)V
    return-void
.end method
.method static argCharNeg(Ljava/lang/StringBuilder;)Ljava/lang/String;
    .registers 2
    const/4 v0, -0x1
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;
    move-result-object v0
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method
# dexllm#102 review: a 200-link chain of flag moves, each passed at a `Z`
# parameter. Every link is a seed of ONE move component; asking the component
# per seed re-walked it per member and ran the work budget dry part-way, so the
# first links came out `boolean` and the rest `int` -- `boolean v5 = v4` with
# an `int v4`. The component must be typed whole or not at all.
.method static flagChain(Z)Z
    .registers 205
    move/from16 v1, p0
    const/4 v0, 0x1
    if-eqz v1, :a
    const/4 v0, 0x0
    :a
    move/16 v3, v0
    move/16 v4, v3
    invoke-static/range {v4 .. v4}, LTypedPositions;->takeZ(Z)V
    move/16 v5, v4
    invoke-static/range {v5 .. v5}, LTypedPositions;->takeZ(Z)V
    move/16 v6, v5
    invoke-static/range {v6 .. v6}, LTypedPositions;->takeZ(Z)V
    move/16 v7, v6
    invoke-static/range {v7 .. v7}, LTypedPositions;->takeZ(Z)V
    move/16 v8, v7
    invoke-static/range {v8 .. v8}, LTypedPositions;->takeZ(Z)V
    move/16 v9, v8
    invoke-static/range {v9 .. v9}, LTypedPositions;->takeZ(Z)V
    move/16 v10, v9
    invoke-static/range {v10 .. v10}, LTypedPositions;->takeZ(Z)V
    move/16 v11, v10
    invoke-static/range {v11 .. v11}, LTypedPositions;->takeZ(Z)V
    move/16 v12, v11
    invoke-static/range {v12 .. v12}, LTypedPositions;->takeZ(Z)V
    move/16 v13, v12
    invoke-static/range {v13 .. v13}, LTypedPositions;->takeZ(Z)V
    move/16 v14, v13
    invoke-static/range {v14 .. v14}, LTypedPositions;->takeZ(Z)V
    move/16 v15, v14
    invoke-static/range {v15 .. v15}, LTypedPositions;->takeZ(Z)V
    move/16 v16, v15
    invoke-static/range {v16 .. v16}, LTypedPositions;->takeZ(Z)V
    move/16 v17, v16
    invoke-static/range {v17 .. v17}, LTypedPositions;->takeZ(Z)V
    move/16 v18, v17
    invoke-static/range {v18 .. v18}, LTypedPositions;->takeZ(Z)V
    move/16 v19, v18
    invoke-static/range {v19 .. v19}, LTypedPositions;->takeZ(Z)V
    move/16 v20, v19
    invoke-static/range {v20 .. v20}, LTypedPositions;->takeZ(Z)V
    move/16 v21, v20
    invoke-static/range {v21 .. v21}, LTypedPositions;->takeZ(Z)V
    move/16 v22, v21
    invoke-static/range {v22 .. v22}, LTypedPositions;->takeZ(Z)V
    move/16 v23, v22
    invoke-static/range {v23 .. v23}, LTypedPositions;->takeZ(Z)V
    move/16 v24, v23
    invoke-static/range {v24 .. v24}, LTypedPositions;->takeZ(Z)V
    move/16 v25, v24
    invoke-static/range {v25 .. v25}, LTypedPositions;->takeZ(Z)V
    move/16 v26, v25
    invoke-static/range {v26 .. v26}, LTypedPositions;->takeZ(Z)V
    move/16 v27, v26
    invoke-static/range {v27 .. v27}, LTypedPositions;->takeZ(Z)V
    move/16 v28, v27
    invoke-static/range {v28 .. v28}, LTypedPositions;->takeZ(Z)V
    move/16 v29, v28
    invoke-static/range {v29 .. v29}, LTypedPositions;->takeZ(Z)V
    move/16 v30, v29
    invoke-static/range {v30 .. v30}, LTypedPositions;->takeZ(Z)V
    move/16 v31, v30
    invoke-static/range {v31 .. v31}, LTypedPositions;->takeZ(Z)V
    move/16 v32, v31
    invoke-static/range {v32 .. v32}, LTypedPositions;->takeZ(Z)V
    move/16 v33, v32
    invoke-static/range {v33 .. v33}, LTypedPositions;->takeZ(Z)V
    move/16 v34, v33
    invoke-static/range {v34 .. v34}, LTypedPositions;->takeZ(Z)V
    move/16 v35, v34
    invoke-static/range {v35 .. v35}, LTypedPositions;->takeZ(Z)V
    move/16 v36, v35
    invoke-static/range {v36 .. v36}, LTypedPositions;->takeZ(Z)V
    move/16 v37, v36
    invoke-static/range {v37 .. v37}, LTypedPositions;->takeZ(Z)V
    move/16 v38, v37
    invoke-static/range {v38 .. v38}, LTypedPositions;->takeZ(Z)V
    move/16 v39, v38
    invoke-static/range {v39 .. v39}, LTypedPositions;->takeZ(Z)V
    move/16 v40, v39
    invoke-static/range {v40 .. v40}, LTypedPositions;->takeZ(Z)V
    move/16 v41, v40
    invoke-static/range {v41 .. v41}, LTypedPositions;->takeZ(Z)V
    move/16 v42, v41
    invoke-static/range {v42 .. v42}, LTypedPositions;->takeZ(Z)V
    move/16 v43, v42
    invoke-static/range {v43 .. v43}, LTypedPositions;->takeZ(Z)V
    move/16 v44, v43
    invoke-static/range {v44 .. v44}, LTypedPositions;->takeZ(Z)V
    move/16 v45, v44
    invoke-static/range {v45 .. v45}, LTypedPositions;->takeZ(Z)V
    move/16 v46, v45
    invoke-static/range {v46 .. v46}, LTypedPositions;->takeZ(Z)V
    move/16 v47, v46
    invoke-static/range {v47 .. v47}, LTypedPositions;->takeZ(Z)V
    move/16 v48, v47
    invoke-static/range {v48 .. v48}, LTypedPositions;->takeZ(Z)V
    move/16 v49, v48
    invoke-static/range {v49 .. v49}, LTypedPositions;->takeZ(Z)V
    move/16 v50, v49
    invoke-static/range {v50 .. v50}, LTypedPositions;->takeZ(Z)V
    move/16 v51, v50
    invoke-static/range {v51 .. v51}, LTypedPositions;->takeZ(Z)V
    move/16 v52, v51
    invoke-static/range {v52 .. v52}, LTypedPositions;->takeZ(Z)V
    move/16 v53, v52
    invoke-static/range {v53 .. v53}, LTypedPositions;->takeZ(Z)V
    move/16 v54, v53
    invoke-static/range {v54 .. v54}, LTypedPositions;->takeZ(Z)V
    move/16 v55, v54
    invoke-static/range {v55 .. v55}, LTypedPositions;->takeZ(Z)V
    move/16 v56, v55
    invoke-static/range {v56 .. v56}, LTypedPositions;->takeZ(Z)V
    move/16 v57, v56
    invoke-static/range {v57 .. v57}, LTypedPositions;->takeZ(Z)V
    move/16 v58, v57
    invoke-static/range {v58 .. v58}, LTypedPositions;->takeZ(Z)V
    move/16 v59, v58
    invoke-static/range {v59 .. v59}, LTypedPositions;->takeZ(Z)V
    move/16 v60, v59
    invoke-static/range {v60 .. v60}, LTypedPositions;->takeZ(Z)V
    move/16 v61, v60
    invoke-static/range {v61 .. v61}, LTypedPositions;->takeZ(Z)V
    move/16 v62, v61
    invoke-static/range {v62 .. v62}, LTypedPositions;->takeZ(Z)V
    move/16 v63, v62
    invoke-static/range {v63 .. v63}, LTypedPositions;->takeZ(Z)V
    move/16 v64, v63
    invoke-static/range {v64 .. v64}, LTypedPositions;->takeZ(Z)V
    move/16 v65, v64
    invoke-static/range {v65 .. v65}, LTypedPositions;->takeZ(Z)V
    move/16 v66, v65
    invoke-static/range {v66 .. v66}, LTypedPositions;->takeZ(Z)V
    move/16 v67, v66
    invoke-static/range {v67 .. v67}, LTypedPositions;->takeZ(Z)V
    move/16 v68, v67
    invoke-static/range {v68 .. v68}, LTypedPositions;->takeZ(Z)V
    move/16 v69, v68
    invoke-static/range {v69 .. v69}, LTypedPositions;->takeZ(Z)V
    move/16 v70, v69
    invoke-static/range {v70 .. v70}, LTypedPositions;->takeZ(Z)V
    move/16 v71, v70
    invoke-static/range {v71 .. v71}, LTypedPositions;->takeZ(Z)V
    move/16 v72, v71
    invoke-static/range {v72 .. v72}, LTypedPositions;->takeZ(Z)V
    move/16 v73, v72
    invoke-static/range {v73 .. v73}, LTypedPositions;->takeZ(Z)V
    move/16 v74, v73
    invoke-static/range {v74 .. v74}, LTypedPositions;->takeZ(Z)V
    move/16 v75, v74
    invoke-static/range {v75 .. v75}, LTypedPositions;->takeZ(Z)V
    move/16 v76, v75
    invoke-static/range {v76 .. v76}, LTypedPositions;->takeZ(Z)V
    move/16 v77, v76
    invoke-static/range {v77 .. v77}, LTypedPositions;->takeZ(Z)V
    move/16 v78, v77
    invoke-static/range {v78 .. v78}, LTypedPositions;->takeZ(Z)V
    move/16 v79, v78
    invoke-static/range {v79 .. v79}, LTypedPositions;->takeZ(Z)V
    move/16 v80, v79
    invoke-static/range {v80 .. v80}, LTypedPositions;->takeZ(Z)V
    move/16 v81, v80
    invoke-static/range {v81 .. v81}, LTypedPositions;->takeZ(Z)V
    move/16 v82, v81
    invoke-static/range {v82 .. v82}, LTypedPositions;->takeZ(Z)V
    move/16 v83, v82
    invoke-static/range {v83 .. v83}, LTypedPositions;->takeZ(Z)V
    move/16 v84, v83
    invoke-static/range {v84 .. v84}, LTypedPositions;->takeZ(Z)V
    move/16 v85, v84
    invoke-static/range {v85 .. v85}, LTypedPositions;->takeZ(Z)V
    move/16 v86, v85
    invoke-static/range {v86 .. v86}, LTypedPositions;->takeZ(Z)V
    move/16 v87, v86
    invoke-static/range {v87 .. v87}, LTypedPositions;->takeZ(Z)V
    move/16 v88, v87
    invoke-static/range {v88 .. v88}, LTypedPositions;->takeZ(Z)V
    move/16 v89, v88
    invoke-static/range {v89 .. v89}, LTypedPositions;->takeZ(Z)V
    move/16 v90, v89
    invoke-static/range {v90 .. v90}, LTypedPositions;->takeZ(Z)V
    move/16 v91, v90
    invoke-static/range {v91 .. v91}, LTypedPositions;->takeZ(Z)V
    move/16 v92, v91
    invoke-static/range {v92 .. v92}, LTypedPositions;->takeZ(Z)V
    move/16 v93, v92
    invoke-static/range {v93 .. v93}, LTypedPositions;->takeZ(Z)V
    move/16 v94, v93
    invoke-static/range {v94 .. v94}, LTypedPositions;->takeZ(Z)V
    move/16 v95, v94
    invoke-static/range {v95 .. v95}, LTypedPositions;->takeZ(Z)V
    move/16 v96, v95
    invoke-static/range {v96 .. v96}, LTypedPositions;->takeZ(Z)V
    move/16 v97, v96
    invoke-static/range {v97 .. v97}, LTypedPositions;->takeZ(Z)V
    move/16 v98, v97
    invoke-static/range {v98 .. v98}, LTypedPositions;->takeZ(Z)V
    move/16 v99, v98
    invoke-static/range {v99 .. v99}, LTypedPositions;->takeZ(Z)V
    move/16 v100, v99
    invoke-static/range {v100 .. v100}, LTypedPositions;->takeZ(Z)V
    move/16 v101, v100
    invoke-static/range {v101 .. v101}, LTypedPositions;->takeZ(Z)V
    move/16 v102, v101
    invoke-static/range {v102 .. v102}, LTypedPositions;->takeZ(Z)V
    move/16 v103, v102
    invoke-static/range {v103 .. v103}, LTypedPositions;->takeZ(Z)V
    move/16 v104, v103
    invoke-static/range {v104 .. v104}, LTypedPositions;->takeZ(Z)V
    move/16 v105, v104
    invoke-static/range {v105 .. v105}, LTypedPositions;->takeZ(Z)V
    move/16 v106, v105
    invoke-static/range {v106 .. v106}, LTypedPositions;->takeZ(Z)V
    move/16 v107, v106
    invoke-static/range {v107 .. v107}, LTypedPositions;->takeZ(Z)V
    move/16 v108, v107
    invoke-static/range {v108 .. v108}, LTypedPositions;->takeZ(Z)V
    move/16 v109, v108
    invoke-static/range {v109 .. v109}, LTypedPositions;->takeZ(Z)V
    move/16 v110, v109
    invoke-static/range {v110 .. v110}, LTypedPositions;->takeZ(Z)V
    move/16 v111, v110
    invoke-static/range {v111 .. v111}, LTypedPositions;->takeZ(Z)V
    move/16 v112, v111
    invoke-static/range {v112 .. v112}, LTypedPositions;->takeZ(Z)V
    move/16 v113, v112
    invoke-static/range {v113 .. v113}, LTypedPositions;->takeZ(Z)V
    move/16 v114, v113
    invoke-static/range {v114 .. v114}, LTypedPositions;->takeZ(Z)V
    move/16 v115, v114
    invoke-static/range {v115 .. v115}, LTypedPositions;->takeZ(Z)V
    move/16 v116, v115
    invoke-static/range {v116 .. v116}, LTypedPositions;->takeZ(Z)V
    move/16 v117, v116
    invoke-static/range {v117 .. v117}, LTypedPositions;->takeZ(Z)V
    move/16 v118, v117
    invoke-static/range {v118 .. v118}, LTypedPositions;->takeZ(Z)V
    move/16 v119, v118
    invoke-static/range {v119 .. v119}, LTypedPositions;->takeZ(Z)V
    move/16 v120, v119
    invoke-static/range {v120 .. v120}, LTypedPositions;->takeZ(Z)V
    move/16 v121, v120
    invoke-static/range {v121 .. v121}, LTypedPositions;->takeZ(Z)V
    move/16 v122, v121
    invoke-static/range {v122 .. v122}, LTypedPositions;->takeZ(Z)V
    move/16 v123, v122
    invoke-static/range {v123 .. v123}, LTypedPositions;->takeZ(Z)V
    move/16 v124, v123
    invoke-static/range {v124 .. v124}, LTypedPositions;->takeZ(Z)V
    move/16 v125, v124
    invoke-static/range {v125 .. v125}, LTypedPositions;->takeZ(Z)V
    move/16 v126, v125
    invoke-static/range {v126 .. v126}, LTypedPositions;->takeZ(Z)V
    move/16 v127, v126
    invoke-static/range {v127 .. v127}, LTypedPositions;->takeZ(Z)V
    move/16 v128, v127
    invoke-static/range {v128 .. v128}, LTypedPositions;->takeZ(Z)V
    move/16 v129, v128
    invoke-static/range {v129 .. v129}, LTypedPositions;->takeZ(Z)V
    move/16 v130, v129
    invoke-static/range {v130 .. v130}, LTypedPositions;->takeZ(Z)V
    move/16 v131, v130
    invoke-static/range {v131 .. v131}, LTypedPositions;->takeZ(Z)V
    move/16 v132, v131
    invoke-static/range {v132 .. v132}, LTypedPositions;->takeZ(Z)V
    move/16 v133, v132
    invoke-static/range {v133 .. v133}, LTypedPositions;->takeZ(Z)V
    move/16 v134, v133
    invoke-static/range {v134 .. v134}, LTypedPositions;->takeZ(Z)V
    move/16 v135, v134
    invoke-static/range {v135 .. v135}, LTypedPositions;->takeZ(Z)V
    move/16 v136, v135
    invoke-static/range {v136 .. v136}, LTypedPositions;->takeZ(Z)V
    move/16 v137, v136
    invoke-static/range {v137 .. v137}, LTypedPositions;->takeZ(Z)V
    move/16 v138, v137
    invoke-static/range {v138 .. v138}, LTypedPositions;->takeZ(Z)V
    move/16 v139, v138
    invoke-static/range {v139 .. v139}, LTypedPositions;->takeZ(Z)V
    move/16 v140, v139
    invoke-static/range {v140 .. v140}, LTypedPositions;->takeZ(Z)V
    move/16 v141, v140
    invoke-static/range {v141 .. v141}, LTypedPositions;->takeZ(Z)V
    move/16 v142, v141
    invoke-static/range {v142 .. v142}, LTypedPositions;->takeZ(Z)V
    move/16 v143, v142
    invoke-static/range {v143 .. v143}, LTypedPositions;->takeZ(Z)V
    move/16 v144, v143
    invoke-static/range {v144 .. v144}, LTypedPositions;->takeZ(Z)V
    move/16 v145, v144
    invoke-static/range {v145 .. v145}, LTypedPositions;->takeZ(Z)V
    move/16 v146, v145
    invoke-static/range {v146 .. v146}, LTypedPositions;->takeZ(Z)V
    move/16 v147, v146
    invoke-static/range {v147 .. v147}, LTypedPositions;->takeZ(Z)V
    move/16 v148, v147
    invoke-static/range {v148 .. v148}, LTypedPositions;->takeZ(Z)V
    move/16 v149, v148
    invoke-static/range {v149 .. v149}, LTypedPositions;->takeZ(Z)V
    move/16 v150, v149
    invoke-static/range {v150 .. v150}, LTypedPositions;->takeZ(Z)V
    move/16 v151, v150
    invoke-static/range {v151 .. v151}, LTypedPositions;->takeZ(Z)V
    move/16 v152, v151
    invoke-static/range {v152 .. v152}, LTypedPositions;->takeZ(Z)V
    move/16 v153, v152
    invoke-static/range {v153 .. v153}, LTypedPositions;->takeZ(Z)V
    move/16 v154, v153
    invoke-static/range {v154 .. v154}, LTypedPositions;->takeZ(Z)V
    move/16 v155, v154
    invoke-static/range {v155 .. v155}, LTypedPositions;->takeZ(Z)V
    move/16 v156, v155
    invoke-static/range {v156 .. v156}, LTypedPositions;->takeZ(Z)V
    move/16 v157, v156
    invoke-static/range {v157 .. v157}, LTypedPositions;->takeZ(Z)V
    move/16 v158, v157
    invoke-static/range {v158 .. v158}, LTypedPositions;->takeZ(Z)V
    move/16 v159, v158
    invoke-static/range {v159 .. v159}, LTypedPositions;->takeZ(Z)V
    move/16 v160, v159
    invoke-static/range {v160 .. v160}, LTypedPositions;->takeZ(Z)V
    move/16 v161, v160
    invoke-static/range {v161 .. v161}, LTypedPositions;->takeZ(Z)V
    move/16 v162, v161
    invoke-static/range {v162 .. v162}, LTypedPositions;->takeZ(Z)V
    move/16 v163, v162
    invoke-static/range {v163 .. v163}, LTypedPositions;->takeZ(Z)V
    move/16 v164, v163
    invoke-static/range {v164 .. v164}, LTypedPositions;->takeZ(Z)V
    move/16 v165, v164
    invoke-static/range {v165 .. v165}, LTypedPositions;->takeZ(Z)V
    move/16 v166, v165
    invoke-static/range {v166 .. v166}, LTypedPositions;->takeZ(Z)V
    move/16 v167, v166
    invoke-static/range {v167 .. v167}, LTypedPositions;->takeZ(Z)V
    move/16 v168, v167
    invoke-static/range {v168 .. v168}, LTypedPositions;->takeZ(Z)V
    move/16 v169, v168
    invoke-static/range {v169 .. v169}, LTypedPositions;->takeZ(Z)V
    move/16 v170, v169
    invoke-static/range {v170 .. v170}, LTypedPositions;->takeZ(Z)V
    move/16 v171, v170
    invoke-static/range {v171 .. v171}, LTypedPositions;->takeZ(Z)V
    move/16 v172, v171
    invoke-static/range {v172 .. v172}, LTypedPositions;->takeZ(Z)V
    move/16 v173, v172
    invoke-static/range {v173 .. v173}, LTypedPositions;->takeZ(Z)V
    move/16 v174, v173
    invoke-static/range {v174 .. v174}, LTypedPositions;->takeZ(Z)V
    move/16 v175, v174
    invoke-static/range {v175 .. v175}, LTypedPositions;->takeZ(Z)V
    move/16 v176, v175
    invoke-static/range {v176 .. v176}, LTypedPositions;->takeZ(Z)V
    move/16 v177, v176
    invoke-static/range {v177 .. v177}, LTypedPositions;->takeZ(Z)V
    move/16 v178, v177
    invoke-static/range {v178 .. v178}, LTypedPositions;->takeZ(Z)V
    move/16 v179, v178
    invoke-static/range {v179 .. v179}, LTypedPositions;->takeZ(Z)V
    move/16 v180, v179
    invoke-static/range {v180 .. v180}, LTypedPositions;->takeZ(Z)V
    move/16 v181, v180
    invoke-static/range {v181 .. v181}, LTypedPositions;->takeZ(Z)V
    move/16 v182, v181
    invoke-static/range {v182 .. v182}, LTypedPositions;->takeZ(Z)V
    move/16 v183, v182
    invoke-static/range {v183 .. v183}, LTypedPositions;->takeZ(Z)V
    move/16 v184, v183
    invoke-static/range {v184 .. v184}, LTypedPositions;->takeZ(Z)V
    move/16 v185, v184
    invoke-static/range {v185 .. v185}, LTypedPositions;->takeZ(Z)V
    move/16 v186, v185
    invoke-static/range {v186 .. v186}, LTypedPositions;->takeZ(Z)V
    move/16 v187, v186
    invoke-static/range {v187 .. v187}, LTypedPositions;->takeZ(Z)V
    move/16 v188, v187
    invoke-static/range {v188 .. v188}, LTypedPositions;->takeZ(Z)V
    move/16 v189, v188
    invoke-static/range {v189 .. v189}, LTypedPositions;->takeZ(Z)V
    move/16 v190, v189
    invoke-static/range {v190 .. v190}, LTypedPositions;->takeZ(Z)V
    move/16 v191, v190
    invoke-static/range {v191 .. v191}, LTypedPositions;->takeZ(Z)V
    move/16 v192, v191
    invoke-static/range {v192 .. v192}, LTypedPositions;->takeZ(Z)V
    move/16 v193, v192
    invoke-static/range {v193 .. v193}, LTypedPositions;->takeZ(Z)V
    move/16 v194, v193
    invoke-static/range {v194 .. v194}, LTypedPositions;->takeZ(Z)V
    move/16 v195, v194
    invoke-static/range {v195 .. v195}, LTypedPositions;->takeZ(Z)V
    move/16 v196, v195
    invoke-static/range {v196 .. v196}, LTypedPositions;->takeZ(Z)V
    move/16 v197, v196
    invoke-static/range {v197 .. v197}, LTypedPositions;->takeZ(Z)V
    move/16 v198, v197
    invoke-static/range {v198 .. v198}, LTypedPositions;->takeZ(Z)V
    move/16 v199, v198
    invoke-static/range {v199 .. v199}, LTypedPositions;->takeZ(Z)V
    move/16 v200, v199
    invoke-static/range {v200 .. v200}, LTypedPositions;->takeZ(Z)V
    move/16 v201, v200
    invoke-static/range {v201 .. v201}, LTypedPositions;->takeZ(Z)V
    move/16 v202, v201
    invoke-static/range {v202 .. v202}, LTypedPositions;->takeZ(Z)V
    move/16 v203, v202
    invoke-static/range {v203 .. v203}, LTypedPositions;->takeZ(Z)V
    move/16 v2, v203
    return v2
.end method
# dexllm#102 review: a component whose OTHER member is used as a number. `v0`
# is a flag passed at a `Z` parameter; it is moved into `v1`, which is then
# incremented and returned. Typing `v0` alone would leave `int v1 = v0` with a
# boolean `v0`, so the whole component stays int.
.method static compNum(II)I
    .registers 4
    const/4 v0, 0x0
    if-eqz p0, :L
    const/4 v0, 0x1
    :L
    invoke-static {v0}, LTypedPositions;->takeZ(Z)V
    const/4 v1, 0x0
    if-eqz p1, :M
    move v1, v0
    :M
    add-int/lit8 v1, v1, 0x1
    return v1
.end method
# dexllm#102 review: a `sput-boolean` is a boolean source on its own
.method static sputSeed(I)V
    .registers 2
    const/4 v0, 0x0
    if-eqz p0, :L
    const/4 v0, 0x1
    :L
    sput-boolean v0, LTypedPositions;->sZ:Z
    return-void
.end method
# dexllm#102 review: a stale-`float` destination of an `{I, Z}` move whose int
# source is a REAL version (incremented, so it stays int). Joining the
# destination to `Z` would give `boolean v3 = v4` with an int `v4`.
.method mixedWidthIntSource(I)V
    .registers 8
    const/4 v4, 0x0
    if-eqz p1, :L
    const/4 v4, 0x1
    :L
    add-int/lit8 v5, v4, 0x2
    iput v5, p0, LTypedPositions;->iI:I
    if-eqz p1, :zero
    move v3, v4
    :set
    iput-boolean v3, p0, LTypedPositions;->iZ:Z
    iget v2, p0, LTypedPositions;->iI:I
    int-to-float v3, v2
    iput v3, p0, LTypedPositions;->iF:F
    return-void
    :zero
    move v3, v4
    goto :set
.end method
# dexllm#102 review: a flag passed at a `Z` parameter AND returned from an
# `int` method. A number return type rules `Z` out (as #94 says), so it stays
# int rather than `return v0;` of a boolean in an int method.
.method static zThenIntReturn(I)I
    .registers 2
    const/4 v0, 0x0
    if-eqz p0, :L
    const/4 v0, 0x1
    :L
    invoke-static {v0}, LTypedPositions;->takeZ(Z)V
    return v0
.end method
# dexllm#109: overloads a bare `null` cannot tell apart. `takeAmb(null)` is
# ambiguous between String and Object[]; `takeSpec(null)` is NOT ambiguous but
# resolves to the more specific String overload while the bytecode calls the
# Object one. A cast to the DECLARED parameter type selects exactly the call.
.method static takeAmb(Ljava/lang/String;)V
    .registers 1
    return-void
.end method
.method static takeAmb([Ljava/lang/Object;)V
    .registers 1
    return-void
.end method
.method static takeSpec(Ljava/lang/Object;)V
    .registers 1
    return-void
.end method
.method static takeSpec(Ljava/lang/String;)V
    .registers 1
    return-void
.end method
.method static argNullAmbiguous()V
    .registers 1
    const/4 v0, 0x0
    invoke-static {v0}, LTypedPositions;->takeAmb(Ljava/lang/String;)V
    return-void
.end method
.method static argNullSpecific()V
    .registers 1
    const/4 v0, 0x0
    invoke-static {v0}, LTypedPositions;->takeSpec(Ljava/lang/Object;)V
    return-void
.end method
.method static argNullArray()V
    .registers 1
    const/4 v0, 0x0
    invoke-static {v0}, LTypedPositions;->takeAmb([Ljava/lang/Object;)V
    return-void
.end method
