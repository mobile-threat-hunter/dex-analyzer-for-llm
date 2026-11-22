.class public LC;
.super Ljava/lang/Object;

.method public static get()Ljava/lang/Object;
    .registers 1
    const/4 v0, 0
    return-object v0
.end method

.method public static log(Ljava/lang/Throwable;)V
    .registers 1
    return-void
.end method

.method public static str(Ljava/lang/String;)V
    .registers 1
    return-void
.end method

.method public static obj(Ljava/lang/Object;)V
    .registers 1
    return-void
.end method

# the issue's shape: the exception is copied out and back, and the register it
# passes through is last written with a String on the path the handler joins
.method public static stale()V
    .registers 2
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    :tail
    invoke-static {}, LC;->get()Ljava/lang/Object;
    move-result-object v1
    check-cast v1, Ljava/lang/String;
    invoke-static {v1}, LC;->str(Ljava/lang/String;)V
    return-void
    :h
    move-exception v0
    move-object v1, v0
    move-object v0, v1
    invoke-static {v0}, LC;->log(Ljava/lang/Throwable;)V
    invoke-static {v0}, LC;->log(Ljava/lang/Throwable;)V
    goto :tail
.end method

# two handlers copy their exceptions into one register: the join, Throwable
.method public static twoHandlers()V
    .registers 2
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h1
    .catch Ljava/lang/IllegalStateException; {:ts .. :te} :h2
    const-string v1, "s"
    invoke-static {v1}, LC;->str(Ljava/lang/String;)V
    return-void
    :h1
    move-exception v0
    move-object v1, v0
    goto :j
    :h2
    move-exception v0
    move-object v1, v0
    :j
    invoke-static {v1}, LC;->log(Ljava/lang/Throwable;)V
    invoke-static {v1}, LC;->log(Ljava/lang/Throwable;)V
    const-string v1, "t"
    invoke-static {v1}, LC;->str(Ljava/lang/String;)V
    return-void
.end method

# a null on one path, the copy on the other
.method public static withNull()V
    .registers 2
    const/4 v1, 0
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    goto :j
    :h
    move-exception v0
    move-object v1, v0
    :j
    invoke-static {v1}, LC;->log(Ljava/lang/Throwable;)V
    invoke-static {v1}, LC;->log(Ljava/lang/Throwable;)V
    const-string v1, "t"
    invoke-static {v1}, LC;->str(Ljava/lang/String;)V
    return-void
.end method

# a copy that goes round a loop: the back edge carries nothing new
.method public static loop()V
    .registers 3
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    const-string v2, "s"
    invoke-static {v2}, LC;->str(Ljava/lang/String;)V
    return-void
    :h
    move-exception v0
    move-object v1, v0
    :l
    move-object v2, v1
    move-object v1, v2
    invoke-static {v2}, LC;->log(Ljava/lang/Throwable;)V
    invoke-static {v2}, LC;->log(Ljava/lang/Throwable;)V
    sget-boolean v0, LC;->D:Z
    if-nez v0, :l
    return-void
.end method

# REFUSED: a String constant reaches the same version on the other path
.method public static orString()V
    .registers 2
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    goto :s
    :h
    move-exception v0
    move-object v1, v0
    :j
    invoke-static {v1}, LC;->obj(Ljava/lang/Object;)V
    invoke-static {v1}, LC;->obj(Ljava/lang/Object;)V
    return-void
    :s
    const-string v1, "s"
    goto :j
.end method

# REFUSED: a call result reaches the same version on the other path
.method public static orCall()V
    .registers 2
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    invoke-static {}, LC;->get()Ljava/lang/Object;
    move-result-object v1
    check-cast v1, Ljava/lang/String;
    goto :j
    :h
    move-exception v0
    move-object v1, v0
    :j
    invoke-static {v1}, LC;->obj(Ljava/lang/Object;)V
    invoke-static {v1}, LC;->obj(Ljava/lang/Object;)V
    return-void
.end method

# REFUSED: a parameter reaches the same version on the other path
.method public static orParam(Ljava/lang/Throwable;)V
    .registers 3
    move-object v1, p0
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    goto :j
    :h
    move-exception v0
    move-object v1, v0
    :j
    invoke-static {v1}, LC;->log(Ljava/lang/Throwable;)V
    invoke-static {v1}, LC;->log(Ljava/lang/Throwable;)V
    const-string v1, "t"
    invoke-static {v1}, LC;->str(Ljava/lang/String;)V
    return-void
.end method

# the copy goes round a loop, and every register is last written with a String
# on the path the handler joins
.method public static loopStale()V
    .registers 3
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    :tail
    invoke-static {}, LC;->get()Ljava/lang/Object;
    move-result-object v2
    check-cast v2, Ljava/lang/String;
    move-object v0, v2
    move-object v1, v2
    invoke-static {v0}, LC;->str(Ljava/lang/String;)V
    invoke-static {v1}, LC;->str(Ljava/lang/String;)V
    return-void
    :h
    move-exception v2
    move-object v0, v2
    :l
    move-object v1, v0
    move-object v0, v1
    invoke-static {v1}, LC;->log(Ljava/lang/Throwable;)V
    invoke-static {v0}, LC;->log(Ljava/lang/Throwable;)V
    sget-boolean v2, LC;->D:Z
    if-nez v2, :l
    goto :tail
.end method

# NOT a catch copy: a copy of the null constant, merged with another null,
# carries no handler type
.method public static nullMerge()V
    .registers 2
    sget-boolean v0, LC;->D:Z
    if-eqz v0, :b
    const/4 v0, 0
    move-object v1, v0
    goto :j
    :b
    const/4 v1, 0
    :j
    invoke-static {v1}, LC;->obj(Ljava/lang/Object;)V
    invoke-static {v1}, LC;->obj(Ljava/lang/Object;)V
    invoke-static {}, LC;->get()Ljava/lang/Object;
    move-result-object v1
    check-cast v1, Ljava/lang/String;
    invoke-static {v1}, LC;->str(Ljava/lang/String;)V
    return-void
.end method

# the exception is copied into the PARAMETER register: a parameter keeps its
# declared type
.method public static toParam(Ljava/lang/Object;)V
    .registers 2
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    goto :j
    :h
    move-exception v0
    move-object p0, v0
    :j
    invoke-static {p0}, LC;->obj(Ljava/lang/Object;)V
    invoke-static {p0}, LC;->obj(Ljava/lang/Object;)V
    return-void
.end method

# CRAFTED (ART's runtime verifier rejects both): a PLAIN move of the exception,
# and a nonzero int merged with the copy. Neither is followed.
.method public static plainMove()V
    .registers 2
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    :tail
    invoke-static {}, LC;->get()Ljava/lang/Object;
    move-result-object v1
    check-cast v1, Ljava/lang/String;
    invoke-static {v1}, LC;->str(Ljava/lang/String;)V
    return-void
    :h
    move-exception v0
    move v1, v0
    move-object v0, v1
    invoke-static {v0}, LC;->log(Ljava/lang/Throwable;)V
    invoke-static {v0}, LC;->log(Ljava/lang/Throwable;)V
    goto :tail
.end method

.method public static orInt()V
    .registers 2
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    const/4 v1, 1
    goto :j
    :h
    move-exception v0
    move-object v1, v0
    :j
    invoke-static {v1}, LC;->obj(Ljava/lang/Object;)V
    invoke-static {v1}, LC;->obj(Ljava/lang/Object;)V
    return-void
.end method

# a null merged with the copy, where every register is last written with a
# String on the joined path
.method public static nullStale()V
    .registers 3
    const/4 v0, 0
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    :j
    invoke-static {v0}, LC;->log(Ljava/lang/Throwable;)V
    invoke-static {v0}, LC;->log(Ljava/lang/Throwable;)V
    invoke-static {}, LC;->get()Ljava/lang/Object;
    move-result-object v2
    check-cast v2, Ljava/lang/String;
    move-object v0, v2
    move-object v1, v2
    invoke-static {v2}, LC;->str(Ljava/lang/String;)V
    invoke-static {v0}, LC;->str(Ljava/lang/String;)V
    invoke-static {v1}, LC;->str(Ljava/lang/String;)V
    return-void
    :h
    move-exception v2
    move-object v0, v2
    goto :j
.end method

# REFUSED two hops deep: the copy's source is itself a merge of the exception
# and a parameter
.method public static deepParam(Ljava/lang/Throwable;)V
    .registers 4
    move-object v0, p0
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    :j
    move-object v1, v0
    invoke-static {v1}, LC;->log(Ljava/lang/Throwable;)V
    invoke-static {v1}, LC;->log(Ljava/lang/Throwable;)V
    invoke-static {}, LC;->get()Ljava/lang/Object;
    move-result-object v2
    check-cast v2, Ljava/lang/String;
    move-object v0, v2
    move-object v1, v2
    invoke-static {v2}, LC;->str(Ljava/lang/String;)V
    invoke-static {v0}, LC;->str(Ljava/lang/String;)V
    invoke-static {v1}, LC;->str(Ljava/lang/String;)V
    return-void
    :h
    move-exception v2
    move-object v0, v2
    goto :j
.end method

# a copy at a loop head whose catch source is defined LATER in the loop: the
# fixpoint has to revisit the head once the handler's copy is known
.method public static loopCarry()V
    .registers 3
    const/4 v1, 0
    :l
    move-object v2, v1
    invoke-static {v2}, LC;->log(Ljava/lang/Throwable;)V
    invoke-static {v2}, LC;->log(Ljava/lang/Throwable;)V
    sget-boolean v0, LC;->D:Z
    if-eqz v0, :out
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    goto :l
    :h
    move-exception v0
    move-object v1, v0
    goto :l
    :out
    invoke-static {}, LC;->get()Ljava/lang/Object;
    move-result-object v2
    check-cast v2, Ljava/lang/String;
    invoke-static {v2}, LC;->str(Ljava/lang/String;)V
    return-void
.end method

# REFUSED: a FileNotFoundException and an IOException copied into one register
# that is then passed as an IOException. Throwable is not their common
# supertype, and the class hierarchy is not known here, so the pass leaves it.
.method public static subtypes()V
    .registers 2
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/FileNotFoundException; {:ts .. :te} :h1
    .catch Ljava/io/IOException; {:ts .. :te} :h2
    const-string v1, "s"
    invoke-static {v1}, LC;->str(Ljava/lang/String;)V
    return-void
    :h1
    move-exception v0
    move-object v1, v0
    goto :j
    :h2
    move-exception v0
    move-object v1, v0
    :j
    invoke-static {v1}, LC;->logio(Ljava/io/IOException;)V
    invoke-static {v1}, LC;->logio(Ljava/io/IOException;)V
    const-string v1, "t"
    invoke-static {v1}, LC;->str(Ljava/lang/String;)V
    return-void
.end method

# a copy at a loop head whose source copy comes LATER (over the back edge):
# the fixpoint has to revisit the head once that copy is known
.method public static loopBack()V
    .registers 4
    const/4 v2, 0
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    const/4 v0, 0
    goto :L
    :h
    move-exception v0
    :L
    move-object v1, v2
    invoke-static {v1}, LC;->log(Ljava/lang/Throwable;)V
    invoke-static {v1}, LC;->log(Ljava/lang/Throwable;)V
    move-object v2, v0
    sget-boolean v3, LC;->D:Z
    if-nez v3, :L
    const-string v1, "a"
    invoke-static {v1}, LC;->str(Ljava/lang/String;)V
    const-string v2, "b"
    invoke-static {v2}, LC;->str(Ljava/lang/String;)V
    return-void
.end method

.method public static logio(Ljava/io/IOException;)V
    .registers 1
    return-void
.end method

.field public static D:Z
