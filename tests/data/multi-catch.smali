.class public LM;
.super Ljava/lang/Object;
.field public static D:Z

.method public static get()Ljava/lang/Object;
    .registers 1
    const/4 v0, 0
    return-object v0
.end method

.method public static log(Ljava/lang/Throwable;)V
    .registers 1
    return-void
.end method

# one handler, three catch types, the variable read
.method public static three()V
    .registers 1
    :ts
    invoke-static {}, LM;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    .catch Ljava/lang/IllegalStateException; {:ts .. :te} :h
    .catch Ljava/lang/ClassNotFoundException; {:ts .. :te} :h
    return-void
    :h
    move-exception v0
    invoke-static {v0}, LM;->log(Ljava/lang/Throwable;)V
    return-void
.end method

# the same handler, the types in the other order: the clause follows the try table
.method public static reversed()V
    .registers 1
    :ts
    invoke-static {}, LM;->get()Ljava/lang/Object;
    :te
    .catch Ljava/lang/ClassNotFoundException; {:ts .. :te} :h
    .catch Ljava/io/IOException; {:ts .. :te} :h
    return-void
    :h
    move-exception v0
    invoke-static {v0}, LM;->log(Ljava/lang/Throwable;)V
    return-void
.end method

# a shared handler with no move-exception: the clause has no variable
.method public static noVariable()V
    .registers 1
    :ts
    invoke-static {}, LM;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    .catch Ljava/lang/IllegalStateException; {:ts .. :te} :h
    return-void
    :h
    invoke-static {}, LM;->get()Ljava/lang/Object;
    return-void
.end method

# a catch-all shares the handler: it catches everything
.method public static withCatchAll()V
    .registers 1
    :ts
    invoke-static {}, LM;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    .catchall {:ts .. :te} :h
    return-void
    :h
    move-exception v0
    invoke-static {v0}, LM;->log(Ljava/lang/Throwable;)V
    return-void
.end method

# control: one catch type
.method public static single()V
    .registers 1
    :ts
    invoke-static {}, LM;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    return-void
    :h
    move-exception v0
    invoke-static {v0}, LM;->log(Ljava/lang/Throwable;)V
    return-void
.end method

# control: two handlers, one type each, stay two clauses
.method public static twoHandlers()V
    .registers 1
    :ts
    invoke-static {}, LM;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h1
    .catch Ljava/lang/IllegalStateException; {:ts .. :te} :h2
    return-void
    :h1
    move-exception v0
    invoke-static {v0}, LM;->log(Ljava/lang/Throwable;)V
    return-void
    :h2
    move-exception v0
    invoke-static {v0}, LM;->log(Ljava/lang/Throwable;)V
    return-void
.end method

# the catch variable escapes the handler: it is passed where an Object is
# expected and returned, so its declared type is the join of the clause's types
.method public static escapes()Ljava/lang/Object;
    .registers 1
    :ts
    invoke-static {}, LM;->get()Ljava/lang/Object;
    move-result-object v0
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    .catch Ljava/lang/IllegalStateException; {:ts .. :te} :h
    return-object v0
    :h
    move-exception v0
    return-object v0
.end method

# two try ranges, each listing both types for the same handler: the clause
# names each type once
.method public static twoRanges()V
    .registers 1
    :ts1
    invoke-static {}, LM;->get()Ljava/lang/Object;
    :te1
    .catch Ljava/io/IOException; {:ts1 .. :te1} :h
    .catch Ljava/lang/IllegalStateException; {:ts1 .. :te1} :h
    invoke-static {}, LM;->get()Ljava/lang/Object;
    :ts2
    invoke-static {}, LM;->get()Ljava/lang/Object;
    :te2
    .catch Ljava/io/IOException; {:ts2 .. :te2} :h
    .catch Ljava/lang/IllegalStateException; {:ts2 .. :te2} :h
    return-void
    :h
    move-exception v0
    invoke-static {v0}, LM;->log(Ljava/lang/Throwable;)V
    return-void
.end method

# a null and one shared handler reach the same use: the variable is declared
# outside the clause, with the join of the handler's types
.method public static nullThenShared()V
    .registers 2
    const/4 v0, 0
    :ts
    invoke-static {}, LM;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    .catch Ljava/lang/IllegalStateException; {:ts .. :te} :h
    :tail
    if-eqz v0, :out
    invoke-static {v0}, LM;->log(Ljava/lang/Throwable;)V
    :out
    return-void
    :h
    move-exception v0
    goto :tail
.end method

# the handler opens with a test, so SplitIfNodes replaces it with a -pre and a
# -cond node (adversarial review): the type list must survive the split
.method public static splitIf()V
    .registers 2
    :ts
    invoke-static {}, LM;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    .catch Ljava/lang/IllegalStateException; {:ts .. :te} :h
    return-void
    :h
    move-exception v0
    sget-boolean v1, LM;->D:Z
    if-eqz v1, :x
    invoke-static {v0}, LM;->log(Ljava/lang/Throwable;)V
    :x
    return-void
.end method

# the handler is a bare goto, so Simplify removes it and re-points the catch
# edge at its successor (adversarial review): the list moves with it
.method public static gotoHandler()V
    .registers 1
    :ts
    invoke-static {}, LM;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    .catch Ljava/lang/IllegalStateException; {:ts .. :te} :h
    invoke-static {}, LM;->get()Ljava/lang/Object;
    return-void
    :h
    goto :t
    :t
    invoke-static {}, LM;->get()Ljava/lang/Object;
    return-void
.end method

# a bare-goto handler whose successor is ANOTHER handler's block: that block
# keeps its own type (the list is moved only onto a block no handler owns)
.method public static gotoIntoHandler()V
    .registers 1
    :ts
    invoke-static {}, LM;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h1
    .catch Ljava/lang/IllegalStateException; {:ts .. :te} :h1
    .catch Ljava/lang/ClassNotFoundException; {:ts .. :te} :h2
    return-void
    :h1
    goto :h2
    :h2
    invoke-static {}, LM;->get()Ljava/lang/Object;
    return-void
.end method

# the catch variable is written in the handler (the correctness review's
# shape): a multi-catch parameter cannot be assigned, so the clause names the
# join and keeps the types in a comment
.method public static reassigned()V
    .registers 2
    sget-boolean v1, LM;->D:Z
    :ts
    invoke-static {}, LM;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    .catch Ljava/lang/IllegalStateException; {:ts .. :te} :h
    return-void
    :h
    move-exception v0
    if-nez v1, :x
    const/4 v0, 0
    :x
    invoke-static {v0}, LM;->log(Ljava/lang/Throwable;)V
    return-void
.end method

# Throwable named among the types catches everything: `A | Throwable` is not Java
.method public static withThrowable()V
    .registers 1
    :ts
    invoke-static {}, LM;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    .catch Ljava/lang/Throwable; {:ts .. :te} :h
    return-void
    :h
    move-exception v0
    invoke-static {v0}, LM;->log(Ljava/lang/Throwable;)V
    return-void
.end method

# a type that is not a reference (crafted) is the dexllm#130 clamp's case
.method public static primType()V
    .registers 1
    :ts
    invoke-static {}, LM;->get()Ljava/lang/Object;
    :te
    .catch I {:ts .. :te} :h
    .catch Ljava/io/IOException; {:ts .. :te} :h
    return-void
    :h
    move-exception v0
    invoke-static {v0}, LM;->log(Ljava/lang/Throwable;)V
    return-void
.end method

.method public static num(I)V
    .registers 1
    return-void
.end method

# a bare-goto handler into a CATCH-ALL handler's block: that block stays a
# catch-all, it does not take the typed list
.method public static gotoIntoCatchAll()V
    .registers 1
    :ts
    invoke-static {}, LM;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h1
    .catch Ljava/lang/IllegalStateException; {:ts .. :te} :h1
    .catchall {:ts .. :te} :h2
    return-void
    :h1
    goto :h2
    :h2
    invoke-static {}, LM;->get()Ljava/lang/Object;
    return-void
.end method

# the register is an int first, so it splits; the catch version is then
# written in the handler (the split path of the reassignment rule)
.method public static reassignedSplit()V
    .registers 2
    const/4 v0, 5
    invoke-static {v0}, LM;->num(I)V
    sget-boolean v1, LM;->D:Z
    :ts
    invoke-static {}, LM;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    .catch Ljava/lang/IllegalStateException; {:ts .. :te} :h
    return-void
    :h
    move-exception v0
    if-nez v1, :x
    const/4 v0, 0
    :x
    invoke-static {v0}, LM;->log(Ljava/lang/Throwable;)V
    return-void
.end method

# two shared handlers, one register, merging at one use: each clause is its own
# parameter and neither is assigned, so both stay multi-catch
.method public static twoSharedMerge()V
    .registers 1
    :t1s
    invoke-static {}, LM;->get()Ljava/lang/Object;
    :t1e
    .catch Ljava/io/IOException; {:t1s .. :t1e} :h1
    .catch Ljava/lang/IllegalStateException; {:t1s .. :t1e} :h1
    :t2s
    invoke-static {}, LM;->get()Ljava/lang/Object;
    :t2e
    .catch Ljava/lang/ClassNotFoundException; {:t2s .. :t2e} :h2
    .catch Ljava/lang/InterruptedException; {:t2s .. :t2e} :h2
    return-void
    :h1
    move-exception v0
    goto :tail
    :h2
    move-exception v0
    :tail
    invoke-static {v0}, LM;->log(Ljava/lang/Throwable;)V
    return-void
.end method
