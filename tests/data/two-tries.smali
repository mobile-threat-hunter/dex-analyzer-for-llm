# dexllm#122 fixture: two tries back to back.
#
# When a try's handlers rejoin exactly at the start of the next try, CatchStruct
# sets the first TryBlock's follow to that block -- which a LATER TryBlock then
# wraps. DAD never remapped the follow (its TryBlocks are not in graph.nodes),
# so the Writer's stop test missed and the second try, and everything after it,
# rendered INSIDE the first. Authored in smali: the shape is a handler `goto`
# that lands on the next try's first instruction, which javac rarely emits
# without a statement in between and d8 emits all the time. condTry's first
# try ends in an if; nestedTry and loopHeadTry are the two shapes the remap
# must NOT touch (nested regions; a try at a loop header).

.class public LT;
.super Ljava/lang/Object;

.method public static use(Ljava/lang/Object;)V
    .registers 1
    return-void
.end method

.method public static after()V
    .registers 1
    return-void
.end method

# no copy: new + <init> before the try, the object used inside it
.method public static noCopy()V
    .registers 3
    new-instance v0, Ljava/lang/StringBuilder;
    const-string v1, "a"
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V
    :try_start
    invoke-static {v0}, LT;->use(Ljava/lang/Object;)V
    :try_end
    .catch Ljava/lang/Exception; {:try_start .. :try_end} :handler
    :cont
    invoke-static {}, LT;->after()V
    return-void
    :handler
    move-exception v2
    goto :cont
.end method

.method public static twoTries()V
    .registers 3
    new-instance v0, Ljava/lang/StringBuilder;
    const-string v1, "a"
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V
    :t1s
    invoke-static {v0}, LT;->use(Ljava/lang/Object;)V
    :t1e
    .catch Ljava/lang/Exception; {:t1s .. :t1e} :h1
    :c1
    new-instance v0, Ljava/lang/StringBuilder;
    const-string v1, "b"
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V
    :t2s
    invoke-static {v0}, LT;->use(Ljava/lang/Object;)V
    :t2e
    .catch Ljava/lang/Exception; {:t2s .. :t2e} :h2
    :c2
    invoke-static {}, LT;->after()V
    return-void
    :h1
    move-exception v2
    goto :c1
    :h2
    move-exception v2
    goto :c2
.end method

.method public static twoTriesConst()V
    .registers 3
    const-string v0, "a"
    :t1s
    invoke-static {v0}, LT;->use(Ljava/lang/Object;)V
    :t1e
    .catch Ljava/lang/Exception; {:t1s .. :t1e} :h1
    :c1
    const-string v0, "b"
    :t2s
    invoke-static {v0}, LT;->use(Ljava/lang/Object;)V
    :t2e
    .catch Ljava/lang/Exception; {:t2s .. :t2e} :h2
    :c2
    invoke-static {}, LT;->after()V
    return-void
    :h1
    move-exception v2
    goto :c1
    :h2
    move-exception v2
    goto :c2
.end method

.method public static twoTriesNoPrefix()V
    .registers 3
    :t1s
    invoke-static {}, LT;->after()V
    :t1e
    .catch Ljava/lang/Exception; {:t1s .. :t1e} :h1
    :c1
    :t2s
    invoke-static {}, LT;->after()V
    :t2e
    .catch Ljava/lang/Exception; {:t2s .. :t2e} :h2
    :c2
    invoke-static {}, LT;->after()V
    return-void
    :h1
    move-exception v2
    goto :c1
    :h2
    move-exception v2
    goto :c2
.end method

# three tries in a row: each follow is wrapped by the next
.method public static threeTries()V
    .registers 3
    :t1s
    invoke-static {}, LT;->after()V
    :t1e
    .catch Ljava/lang/Exception; {:t1s .. :t1e} :h1
    :c1
    :t2s
    invoke-static {}, LT;->use2()V
    :t2e
    .catch Ljava/lang/Exception; {:t2s .. :t2e} :h2
    :c2
    :t3s
    invoke-static {}, LT;->use3()V
    :t3e
    .catch Ljava/lang/Exception; {:t3s .. :t3e} :h3
    :c3
    return-void
    :h1
    move-exception v2
    goto :c1
    :h2
    move-exception v2
    goto :c2
    :h3
    move-exception v2
    goto :c3
.end method

.method public static use2()V
    .registers 0
    return-void
.end method

.method public static use3()V
    .registers 0
    return-void
.end method

.method public static flag()Z
    .registers 1
    const/4 v0, 0x1
    return v0
.end method

# the first try ENDS IN AN IF: its follow comes from the if's merge, not from
# the block's single successor (a cond-type TryBlock)
.method public static condTry()V
    .registers 2
    :t1s
    invoke-static {}, LT;->flag()Z
    move-result v0
    if-eqz v0, :m
    invoke-static {}, LT;->use2()V
    :t1e
    .catch Ljava/lang/Exception; {:t1s .. :t1e} :h1
    :m
    :t2s
    invoke-static {}, LT;->use3()V
    :t2e
    .catch Ljava/lang/Exception; {:t2s .. :t2e} :h2
    :c2
    invoke-static {}, LT;->after()V
    return-void
    :h1
    move-exception v1
    goto :m
    :h2
    move-exception v1
    goto :c2
.end method

# NESTED, not back to back: the outer handler also covers the inner try's
# block (Java splits the outer region around the inner one), so the inner try
# must stay inside the outer
.method public static nestedTry()V
    .registers 2
    :r1s
    invoke-static {}, LT;->use2()V
    :r1e
    :r2s
    invoke-static {}, LT;->use3()V
    :r2e
    .catch Ljava/lang/Exception; {:r1s .. :r1e} :h1
    .catch Ljava/io/IOException; {:r2s .. :r2e} :h2
    .catch Ljava/lang/Exception; {:r2s .. :r2e} :h1
    :c2
    invoke-static {}, LT;->after()V
    return-void
    :h1
    move-exception v0
    return-void
    :h2
    move-exception v0
    goto :c2
.end method

# the first try is a do-while header: left as it was (the loop body is walked
# over the header's own edges, so a remapped follow would split the loop)
.method public static loopHeadTry(I)V
    .registers 3
    :head
    :t1s
    invoke-static {}, LT;->use2()V
    :t1e
    .catch Ljava/lang/Exception; {:t1s .. :t1e} :h1
    :c1
    :t2s
    invoke-static {}, LT;->use3()V
    :t2e
    .catch Ljava/lang/Exception; {:t2s .. :t2e} :h2
    :c2
    add-int/lit8 p0, p0, -1
    if-nez p0, :head
    return-void
    :h1
    move-exception v0
    goto :c1
    :h2
    move-exception v0
    goto :c2
.end method

.method public static get()Ljava/lang/Object;
    .registers 1
    const/4 v0, 0x0
    return-object v0
.end method

# defined in the try, read after it: declared before the try
.method public static hoistAfter()Ljava/lang/Object;
    .registers 2
    :ts
    invoke-static {}, LT;->get()Ljava/lang/Object;
    move-result-object v0
    :te
    .catch Ljava/lang/Exception; {:ts .. :te} :h
    :c
    invoke-static {v0}, LT;->use(Ljava/lang/Object;)V
    return-object v0
    :h
    move-exception v1
    const/4 v0, 0x0
    goto :c
.end method

# defined in the try, read in its catch
.method public static hoistIntoCatch()Ljava/lang/Object;
    .registers 2
    const/4 v0, 0x0
    :ts
    invoke-static {}, LT;->get()Ljava/lang/Object;
    move-result-object v0
    invoke-static {v0}, LT;->use(Ljava/lang/Object;)V
    :te
    .catch Ljava/lang/Exception; {:ts .. :te} :h
    return-object v0
    :h
    move-exception v1
    return-object v0
.end method

# the catch defines the value a shared return block returns: the catch's def
# and the normal path's def are one variable, so it is declared before the try
.method public static catchDefShared()Ljava/lang/Object;
    .registers 2
    :ts
    invoke-static {}, LT;->after()V
    :te
    .catch Ljava/lang/Exception; {:ts .. :te} :h
    invoke-static {}, LT;->get()Ljava/lang/Object;
    move-result-object v0
    :ret
    return-object v0
    :h
    move-exception v1
    const/4 v0, 0x0
    goto :ret
.end method

# the catch RETURNS, so the code after the try is reached only on the normal
# path -- and reads what the try body defined
.method public static hoistCatchReturns()Ljava/lang/Object;
    .registers 2
    :ts
    invoke-static {}, LT;->get()Ljava/lang/Object;
    move-result-object v0
    :te
    .catch Ljava/lang/Exception; {:ts .. :te} :h
    invoke-static {v0}, LT;->use(Ljava/lang/Object;)V
    return-object v0
    :h
    move-exception v1
    const/4 v0, 0x0
    return-object v0
.end method

.method public static ia()I
    .registers 1
    const/4 v0, 0x1
    return v0
.end method

.method public static ib()I
    .registers 1
    const/4 v0, 0x2
    return v0
.end method

.method public static use4(IIII)V
    .registers 4
    return-void
.end method

# four locals both arms of an if define inside one try, all read after it:
# the declarations come out in one fixed order (they once followed pointer
# hashing, and the text and the AST disagreed)
.method public static hoistMany(Z)V
    .registers 6
    :ts
    if-eqz p0, :else
    invoke-static {}, LT;->ia()I
    move-result v0
    invoke-static {}, LT;->ia()I
    move-result v1
    invoke-static {}, LT;->ia()I
    move-result v2
    invoke-static {}, LT;->ia()I
    move-result v3
    goto :join
    :else
    invoke-static {}, LT;->ib()I
    move-result v0
    invoke-static {}, LT;->ib()I
    move-result v1
    invoke-static {}, LT;->ib()I
    move-result v2
    invoke-static {}, LT;->ib()I
    move-result v3
    :join
    invoke-static {}, LT;->ia()I
    :te
    .catch Ljava/lang/Exception; {:ts .. :te} :h
    invoke-static {v0, v1, v2, v3}, LT;->use4(IIII)V
    :h
    return-void
.end method

# a catch variable written by a sibling handler: its declaration IS the
# catch clause itself, so it must never be hoisted (a hoist once wrote
# "Throwable v0;" beside "catch (Throwable v0)", a duplicate declaration)
.method public static catchVarShared()V
    .registers 3
    :ts
    invoke-static {}, LT;->after()V
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h1
    .catch Ljava/lang/Throwable; {:ts .. :te} :h2
    return-void
    :h1
    move-exception v0
    invoke-static {v0}, LT;->use(Ljava/lang/Object;)V
    goto :j
    :h2
    move-exception v1
    move-object v0, v1
    :j
    throw v0
.end method
