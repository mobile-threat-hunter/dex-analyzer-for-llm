.class public LC;
.super Ljava/lang/Object;

.method public static get()Ljava/lang/Object;
    .registers 1
    const/4 v0, 0
    return-object v0
.end method

.method public static a()V
    .registers 0
    return-void
.end method

.method public static b()V
    .registers 0
    return-void
.end method

.method public static log(Ljava/lang/Throwable;)V
    .registers 1
    return-void
.end method

.method public static str(Ljava/lang/String;)V
    .registers 1
    return-void
.end method

# javac's `synchronized (p0) { try { get(); } catch (IOException e) { log(e); } }`:
# the inner handler h1 is covered by the monitor's catch-all, which also covers
# the code h1 catches for -- a NESTED handler, which must be rendered
.method public static syncInner(Ljava/lang/Object;)V
    .registers 3
    monitor-enter p0
    :t1s
    invoke-static {}, LC;->get()Ljava/lang/Object;
    monitor-exit p0
    :t1e
    return-void
    :h1
    :t2s
    move-exception v0
    invoke-static {v0}, LC;->log(Ljava/lang/Throwable;)V
    monitor-exit p0
    :t2e
    return-void
    :ca
    move-exception v1
    :t3s
    monitor-exit p0
    :t3e
    throw v1
    .catch Ljava/io/IOException; {:t1s .. :t1e} :h1
    .catchall {:t1s .. :t1e} :ca
    .catchall {:t2s .. :t2e} :ca
    .catchall {:t3s .. :t3e} :ca
.end method

# `try { try { a(); } catch (IOException e) { log(e); } b(); }
#  catch (IllegalStateException x) { log(x); }` -- the inner handler is nested
.method public static innerCatch()V
    .registers 2
    :t1s
    invoke-static {}, LC;->a()V
    :t1e
    :after
    :t3s
    invoke-static {}, LC;->b()V
    :t3e
    return-void
    :h1
    :t2s
    move-exception v0
    invoke-static {v0}, LC;->log(Ljava/lang/Throwable;)V
    :t2e
    goto :after
    :h2
    move-exception v1
    invoke-static {v1}, LC;->log(Ljava/lang/Throwable;)V
    return-void
    .catch Ljava/io/IOException; {:t1s .. :t1e} :h1
    .catch Ljava/lang/IllegalStateException; {:t1s .. :t1e} :h2
    .catch Ljava/lang/IllegalStateException; {:t2s .. :t2e} :h2
    .catch Ljava/lang/IllegalStateException; {:t3s .. :t3e} :h2
.end method

# a nested handler with no move-exception (d8 drops an unused one): its clause
# must name its own type, not the Throwable of the try covering it
.method public static unboundNested()V
    .registers 2
    :t1s
    invoke-static {}, LC;->a()V
    :t1e
    :after
    :t3s
    invoke-static {}, LC;->b()V
    :t3e
    return-void
    :h1
    :t2s
    const-string v0, "io"
    invoke-static {v0}, LC;->str(Ljava/lang/String;)V
    :t2e
    goto :after
    :h2
    move-exception v1
    invoke-static {v1}, LC;->log(Ljava/lang/Throwable;)V
    return-void
    .catch Ljava/io/IOException; {:t1s .. :t1e} :h1
    .catchall {:t1s .. :t1e} :h2
    .catchall {:t2s .. :t2e} :h2
    .catchall {:t3s .. :t3e} :h2
.end method

# two handlers of one try, neither with a move-exception, the first opening
# with an `if`: SplitIfNodes re-adds the catch edges into its head through
# DAD's add_catch_edge, which copies the thrower's type -- the LAST handler's
# -- onto it, so on the pre-fix build both clauses named IllegalStateException
.method public static twoUnbound()V
    .registers 1
    :t1s
    invoke-static {}, LC;->a()V
    :t1e
    return-void
    :h1
    invoke-static {}, LC;->b()V
    invoke-static {}, LC;->get()Ljava/lang/Object;
    move-result-object v0
    if-eqz v0, :none
    const-string v0, "io"
    invoke-static {v0}, LC;->str(Ljava/lang/String;)V
    :none
    return-void
    :h2
    const-string v0, "ise"
    invoke-static {v0}, LC;->str(Ljava/lang/String;)V
    return-void
    .catch Ljava/io/IOException; {:t1s .. :t1e} :h1
    .catch Ljava/lang/IllegalStateException; {:t1s .. :t1e} :h2
.end method

# CONTROL, the $SwitchMap <clinit> d8 emits: each try's handler is the next
# try's first block. Not nested -- the next try's handler does not cover the
# first try -- so the handler stays skipped, as in DAD
.method public static switchMap()V
    .registers 0
    :t1s
    invoke-static {}, LC;->a()V
    :t1e
    :t2s
    invoke-static {}, LC;->b()V
    :t2e
    :done
    return-void
    .catch Ljava/lang/NoSuchFieldError; {:t1s .. :t1e} :t2s
    .catch Ljava/lang/NoSuchFieldError; {:t2s .. :t2e} :done
.end method

# CONTROL: a catch-all that covers itself (a synchronized block's monitor-exit +
# rethrow) stays skipped
.method public static selfCatchAll(Ljava/lang/Object;)V
    .registers 2
    monitor-enter p0
    :t1s
    invoke-static {}, LC;->a()V
    monitor-exit p0
    :t1e
    return-void
    :ca
    move-exception v0
    monitor-exit p0
    :t2e
    throw v0
    .catchall {:t1s .. :t1e} :ca
    .catchall {:ca .. :t2e} :ca
.end method

# two tries share one handler and only the second is inside an enclosing try:
# the handler is covered by the enclosing catch-all, and so is one of the two
# blocks that throw into it -- which is enough: requiring every thrower to be
# covered drops this handler's code
.method public static partlyNested()V
    .registers 2
    :t1s
    invoke-static {}, LC;->a()V
    :t1e
    :t2s
    invoke-static {}, LC;->b()V
    :t2e
    return-void
    :h1
    :t3s
    move-exception v0
    invoke-static {v0}, LC;->log(Ljava/lang/Throwable;)V
    :t3e
    return-void
    :h2
    move-exception v1
    invoke-static {v1}, LC;->log(Ljava/lang/Throwable;)V
    return-void
    .catch Ljava/io/IOException; {:t1s .. :t1e} :h1
    .catch Ljava/io/IOException; {:t2s .. :t2e} :h1
    .catchall {:t2s .. :t2e} :h2
    .catchall {:t3s .. :t3e} :h2
.end method
