# dexllm#126 — a call runs where it is written: an unconditional call is not
# moved into a block that some path from it skips.
# Authored for this project; assembled with the smali assembler (see README).
.class public LB;
.super Ljava/lang/Object;

.method public static next()I
    .registers 1
    const/4 v0, 0x1
    return v0
.end method

.method public static useI(I)V
    .registers 1
    return-void
.end method

.method public static useII(II)V
    .registers 2
    return-void
.end method

# int x = next(); if (c != 0) useI(x);
.method public static intoIf(I)V
    .registers 2
    invoke-static {}, LB;->next()I
    move-result v0
    if-eqz p0, :end
    invoke-static {v0}, LB;->useI(I)V
    :end
    return-void
.end method

# int x = next(); if (c == 0) throw new RuntimeException(); useI(x);
.method public static pastThrowGuard(I)V
    .registers 3
    invoke-static {}, LB;->next()I
    move-result v0
    if-nez p0, :ok
    new-instance v1, Ljava/lang/RuntimeException;
    invoke-direct {v1}, Ljava/lang/RuntimeException;-><init>()V
    throw v1
    :ok
    invoke-static {v0}, LB;->useI(I)V
    return-void
.end method

# int x = next(); if (c != 0) return; useI(x);
.method public static pastEarlyReturn(I)V
    .registers 2
    invoke-static {}, LB;->next()I
    move-result v0
    if-eqz p0, :go
    return-void
    :go
    invoke-static {v0}, LB;->useI(I)V
    return-void
.end method

# control: int x = next(); int y = c != 0 ? 1 : 2; useII(x, y);  -- the use
# runs on every path, so next() still folds into it
.method public static acrossDiamond(I)V
    .registers 3
    invoke-static {}, LB;->next()I
    move-result v0
    if-eqz p0, :two
    const/4 v1, 0x1
    goto :join
    :two
    const/4 v1, 0x2
    :join
    invoke-static {v0, v1}, LB;->useII(II)V
    return-void
.end method

# control: the use is the branch's own condition
.method public static intoCondition()V
    .registers 1
    invoke-static {}, LB;->next()I
    move-result v0
    if-eqz v0, :end
    invoke-static {v0}, LB;->useI(I)V
    :end
    return-void
.end method

.method public static spin()V
    .registers 0
    return-void
.end method

# int x = next(); if (c != 0) { useI(x); return; } for (;;) spin();
# the path that skips the use never ends, so it is not a post-dominating use
.method public static pastInfiniteLoop(I)V
    .registers 2
    invoke-static {}, LB;->next()I
    move-result v0
    if-eqz p0, :loop
    invoke-static {v0}, LB;->useI(I)V
    return-void
    :loop
    invoke-static {}, LB;->spin()V
    goto :loop
.end method

# int n = q.size(); if (c != 0) { Integer.valueOf(n); return; } for (;;) q.take();
# the loop is left only by an exception, which has no normal edge
.method public static pastWorkerLoop(Ljava/util/concurrent/BlockingQueue;I)V
    .registers 3
    invoke-interface {p0}, Ljava/util/concurrent/BlockingQueue;->size()I
    move-result v0
    if-eqz p1, :loop
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;
    return-void
    :loop
    invoke-interface {p0}, Ljava/util/concurrent/BlockingQueue;->take()Ljava/lang/Object;
    goto :loop
.end method

# control: int x = next(); while (c-- != 0) spin(); useI(x);  -- a loop with an
# exit edge is taken to terminate, so the use post-dominates the call
.method public static pastTerminatingLoop(I)V
    .registers 2
    invoke-static {}, LB;->next()I
    move-result v0
    :loop
    if-eqz p0, :done
    add-int/lit8 p0, p0, -0x1
    goto :loop
    :done
    invoke-static {v0}, LB;->useI(I)V
    return-void
.end method
