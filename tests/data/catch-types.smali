.class public LC;
.super Ljava/lang/Object;

.method public static get()Ljava/lang/Object;
    .registers 1
    const/4 v0, 0
    return-object v0
.end method

.method public static use(Ljava/lang/Object;)V
    .registers 1
    return-void
.end method

.method public static log(Ljava/lang/Throwable;)V
    .registers 1
    return-void
.end method

# the catch variable is read, and the register's last write elsewhere is a
# Field (AppCompatTextViewAutoSizeHelper.getTextViewField, register for register)
.method public static field(Ljava/lang/String;)Ljava/lang/reflect/Field;
    .registers 4
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    move-result-object v0
    check-cast v0, Ljava/lang/reflect/Field;
    if-nez v0, :done
    const-class v1, Ljava/lang/String;
    invoke-virtual {v1, v3}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;
    move-result-object v1
    move-object v0, v1
    :te
    .catch Ljava/lang/NoSuchFieldException; {:ts .. :te} :h
    :done
    return-object v0
    :h
    move-exception v0
    invoke-static {v0}, LC;->log(Ljava/lang/Throwable;)V
    const/4 v1, 0
    return-object v1
.end method

# the catch variable is never read
.method public static unusedCatch()Ljava/lang/Object;
    .registers 2
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    const-class v0, Ljava/lang/String;
    return-object v0
    :h
    move-exception v0
    const/4 v1, 0
    return-object v1
.end method

# the catch variable is never read and the register's last write is a String
# (ActivityChooserModel.readHistoricalDataImpl's `move-exception v15`)
.method public static deadCatch()Ljava/lang/String;
    .registers 2
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    move-result-object v1
    if-eqz v1, :c
    const/4 v1, 0
    return-object v1
    :c
    const-string v0, "y"
    return-object v0
    :h
    move-exception v0
    const/4 v1, 0
    return-object v1
.end method

# a catch-all
.method public static catchAll()Ljava/lang/Object;
    .registers 2
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :te
    .catchall {:ts .. :te} :h
    const-class v0, Ljava/lang/String;
    return-object v0
    :h
    move-exception v0
    invoke-static {v0}, LC;->log(Ljava/lang/Throwable;)V
    const/4 v1, 0
    return-object v1
.end method

# the only writes of the register are two handlers that merge
.method public static mergedHandlers()V
    .registers 2
    :t1s
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :t1e
    .catch Ljava/io/IOException; {:t1s .. :t1e} :h1
    :t2s
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :t2e
    .catch Ljava/lang/IllegalStateException; {:t2s .. :t2e} :h2
    return-void
    :h1
    move-exception v0
    goto :tail
    :h2
    move-exception v0
    :tail
    invoke-static {v0}, LC;->log(Ljava/lang/Throwable;)V
    return-void
.end method

# null before two tries, each handler stores its exception: the version the
# merge reads is null-or-IOException-or-IllegalStateException
.method public static nullThenTwoHandlers()V
    .registers 2
    const/4 v0, 0
    :t1s
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :t1e
    .catch Ljava/io/IOException; {:t1s .. :t1e} :h1
    :t2s
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :t2e
    .catch Ljava/lang/IllegalStateException; {:t2s .. :t2e} :h2
    :tail
    if-eqz v0, :out
    invoke-static {v0}, LC;->log(Ljava/lang/Throwable;)V
    :out
    return-void
    :h1
    move-exception v0
    goto :tail
    :h2
    move-exception v0
    goto :tail
.end method

.method public static num()I
    .registers 1
    const/4 v0, 3
    return v0
.end method

# the register's last write is an int: the Java text always clamped this, the
# AST did not (it rendered `catch (int v0)`)
.method public static primCatch()I
    .registers 2
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    move-result-object v1
    if-eqz v1, :c
    const/4 v1, 0
    return v1
    :c
    invoke-static {}, LC;->num()I
    move-result v0
    return v0
    :h
    move-exception v0
    const/4 v1, 0
    return v1
.end method

# nullThenTwoHandlers again, with an unrelated first version of the register so
# that it splits: the handler types are joined on the split path
.method public static nullThenTwoHandlersSplit()V
    .registers 2
    const-string v0, "a"
    invoke-static {v0}, LC;->use(Ljava/lang/Object;)V
    const/4 v0, 0
    :t1s
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :t1e
    .catch Ljava/io/IOException; {:t1s .. :t1e} :h1
    :t2s
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :t2e
    .catch Ljava/lang/IllegalStateException; {:t2s .. :t2e} :h2
    :tail
    if-eqz v0, :out
    invoke-static {v0}, LC;->log(Ljava/lang/Throwable;)V
    :out
    return-void
    :h1
    move-exception v0
    goto :tail
    :h2
    move-exception v0
    goto :tail
.end method

.method public static useI(I)V
    .registers 1
    return-void
.end method

# a String def and a handler merge in one split version: the String is a real
# def of another type, so the version keeps it (the handler type does not win)
.method public static stringAndCatch()V
    .registers 2
    invoke-static {}, LC;->num()I
    move-result v0
    invoke-static {v0}, LC;->useI(I)V
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    const-string v0, "s"
    :tail
    invoke-static {v0}, LC;->use(Ljava/lang/Object;)V
    return-void
    :h
    move-exception v0
    goto :tail
.end method

# the same with a nonzero int (ART rejects the merge; it loads leniently)
.method public static intAndCatch()V
    .registers 2
    invoke-static {}, LC;->get()Ljava/lang/Object;
    move-result-object v0
    invoke-static {v0}, LC;->use(Ljava/lang/Object;)V
    :ts
    invoke-static {}, LC;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    const/4 v0, 7
    :tail
    invoke-static {v0}, LC;->use(Ljava/lang/Object;)V
    return-void
    :h
    move-exception v0
    goto :tail
.end method

