.class public LH;
.super Ljava/lang/Object;

.field public static D:Z

.method public static get()Ljava/lang/Object;
    .registers 1
    const/4 v0, 0
    return-object v0
.end method

.method public static a()Z
    .registers 1
    const/4 v0, 0
    return v0
.end method

.method public static b()Z
    .registers 1
    const/4 v0, 0
    return v0
.end method

.method public static log(Ljava/lang/Throwable;)V
    .registers 1
    return-void
.end method

.method public static x()V
    .registers 0
    return-void
.end method

.method public static y()V
    .registers 0
    return-void
.end method

.field public static E:Z

# dexllm#134: a loop entered only from a catch handler. Its header has no
# predecessor that preds() counts (both are in_catch), so WhileBlockStruct never
# re-pointed the handler's edge into the loop and the loop vanished.
#   try { get(); } catch (IOException e) { do { log(e); } while (D); }
.method public static loopInHandler()V
    .registers 2
    :ts
    invoke-static {}, LH;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    return-void
    :h
    move-exception v0
    :l
    invoke-static {v0}, LH;->log(Ljava/lang/Throwable;)V
    sget-boolean v1, LH;->D:Z
    if-nez v1, :l
    return-void
.end method

# CONTROL: a handler that runs into an `a && b` test it shares with the normal
# path. The join keeps DAD's preds(), so it stays outside the catch
#   boolean p = a(), q = b(); try { get(); } catch (IOException e) { log(e); }
#   if (p && q) x();
.method public static shortCircuitAfterHandler()V
    .registers 3
    invoke-static {}, LH;->a()Z
    move-result v1
    invoke-static {}, LH;->b()Z
    move-result v2
    :ts
    invoke-static {}, LH;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    goto :c1
    :h
    move-exception v0
    invoke-static {v0}, LH;->log(Ljava/lang/Throwable;)V
    :c1
    if-eqz v1, :out
    if-eqz v2, :out
    invoke-static {}, LH;->x()V
    :out
    return-void
.end method

# kotlin.concurrent.LocksKt.write: the finally path re-acquires in a pretest
# loop, then rethrows
#   try { a(); } catch (Throwable t) { while (p0 > 0) { x(); p0--; } throw t; }
.method public static finallyLoop(I)V
    .registers 3
    :ts
    invoke-static {}, LH;->a()Z
    :te
    .catchall {:ts .. :te} :h
    return-void
    :h
    move-exception v0
    :l
    if-lez p0, :rethrow
    invoke-static {}, LH;->x()V
    add-int/lit8 p0, p0, -1
    goto :l
    :rethrow
    throw v0
.end method

# CONTROL: an `&&` test only the handler reaches. ShortCircuitStruct does not
# merge it (its second test's lone predecessor is in_catch), so it was never
# lost; pinned so a future merge of it is noticed
#   try { get(); } catch (IOException e) { boolean p = a(), q = b();
#                                           if (p && q) x(); }
.method public static shortCircuitInHandler()V
    .registers 3
    :ts
    invoke-static {}, LH;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    return-void
    :h
    move-exception v0
    invoke-static {}, LH;->a()Z
    move-result v1
    invoke-static {}, LH;->b()Z
    move-result v2
    goto :c1
    :c1
    if-eqz v1, :out
    if-eqz v2, :out
    invoke-static {}, LH;->x()V
    :out
    return-void
.end method

# review: a loop wholly inside a handler, with a second back edge. Its latch is
# in_catch, and #138's ClosesDoWhile left every in_catch latch to DAD, so it
# was a do-while that left when E was false
#   catch (IOException e) { while (true) { log(e); if (!E) continue; y(); if (!D) break; } }
.method public static twoBackInHandler()V
    .registers 2
    :ts
    invoke-static {}, LH;->get()Ljava/lang/Object;
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    return-void
    :h
    move-exception v0
    :l
    invoke-static {v0}, LH;->log(Ljava/lang/Throwable;)V
    sget-boolean v1, LH;->E:Z
    if-eqz v1, :l
    invoke-static {}, LH;->y()V
    sget-boolean v1, LH;->D:Z
    if-nez v1, :l
    return-void
.end method

# a catch at the end of a loop body returns to the header: its edge into the
# header is in_catch, and dropping it lost the catch's `continue` (it fell into
# the code after the try instead)
#   while (p0 > 0) { try { a(); } catch (RuntimeException e) { p0 -= 2; continue; }
#                    if (E) y(); p0--; }
.method public static catchContinue(I)V
    .registers 2
    :l
    if-lez p0, :exit
    :ts
    invoke-static {}, LH;->a()Z
    :te
    .catch Ljava/lang/RuntimeException; {:ts .. :te} :h
    sget-boolean v0, LH;->E:Z
    if-eqz v0, :skip
    invoke-static {}, LH;->y()V
    :skip
    add-int/lit8 p0, p0, -1
    goto :l
    :h
    move-exception v0
    add-int/lit8 p0, p0, -2
    goto :l
    :exit
    return-void
.end method

# delta review: a loop AFTER the try, whose header joins the normal paths and
# the handler's fall-through. That in_catch edge is a forward edge and stays
# dropped (as DAD): re-pointing it let the catch claim the loop, and the
# normal path after the try never ran it
#   try { get(); if (E) return; } catch (IOException e) { log(e); } while (D) x();
.method public static loopAfterTry()V
    .registers 1
    :ts
    invoke-static {}, LH;->get()Ljava/lang/Object;
    sget-boolean v0, LH;->E:Z
    if-eqz v0, :head
    return-void
    :te
    .catch Ljava/io/IOException; {:ts .. :te} :h
    :h
    move-exception v0
    invoke-static {v0}, LH;->log(Ljava/lang/Throwable;)V
    :head
    sget-boolean v0, LH;->D:Z
    if-eqz v0, :exit
    invoke-static {}, LH;->x()V
    goto :head
    :exit
    return-void
.end method
