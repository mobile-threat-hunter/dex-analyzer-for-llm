.class public LL;
.super Ljava/lang/Object;

.method public static n()I
    .registers 1
    const/4 v0, 0
    return v0
.end method

.method public static t(I)Z
    .registers 2
    const/4 v0, 0
    return v0
.end method

.method public static t2(I)Z
    .registers 2
    const/4 v0, 0
    return v0
.end method

.method public static a()V
    .registers 0
    return-void
.end method

.method public static b()V
    .registers 0
    return-void
.end method

.method public static c()V
    .registers 0
    return-void
.end method

.method public static add(I)V
    .registers 1
    return-void
.end method

# ShortcutXmlParser.parseShortcutIds: several back edges, the last a test whose
# branches both stay in the loop. DAD made it a do-while on that test, read the
# header as the loop's follow and turned the first `continue` into `break`.
#   while (true) { v0 = n(); if (v0 == 0) break;
#                  if (t(v0) && t2(v0)) add(v0); }  return 1;
.method public static multiLatch()I
    .registers 2
    :head
    invoke-static {}, LL;->n()I
    move-result v0
    if-eqz v0, :exit
    invoke-static {v0}, LL;->t(I)Z
    move-result v1
    if-eqz v1, :c1
    invoke-static {v0}, LL;->t2(I)Z
    move-result v1
    if-nez v1, :keep
    :c2
    goto :head
    :keep
    invoke-static {v0}, LL;->add(I)V
    :c1
    goto :head
    :exit
    const/4 v1, 1
    return v1
.end method

# SelectBuilderImpl.trySelectOther: a back edge from inside an if whose join
# code is real. With no `continue` the edge fell through into b().
#   while (true) { v0 = n(); if (v0 == 0) break;
#                  if (t(v0)) { if (!t2(v0)) continue; a(); } b(); }
.method public static continueJoin()V
    .registers 2
    :head
    invoke-static {}, LL;->n()I
    move-result v0
    if-eqz v0, :exit
    invoke-static {v0}, LL;->t(I)Z
    move-result v1
    if-eqz v1, :join
    invoke-static {v0}, LL;->t2(I)Z
    move-result v1
    if-eqz v1, :head
    invoke-static {}, LL;->a()V
    :join
    invoke-static {}, LL;->b()V
    goto :head
    :exit
    return-void
.end method

# the same with a header that is the loop's own test: a pretest loop, where
# `continue` re-evaluates it
#   while (p0 > 0) { p0--; if (t(p0)) { if (!t2(p0)) continue; a(); } b(); }
.method public static pretestJoin(I)V
    .registers 2
    :head
    if-lez p0, :exit
    add-int/lit8 p0, p0, -1
    invoke-static {p0}, LL;->t(I)Z
    move-result v0
    if-eqz v0, :join
    invoke-static {p0}, LL;->t2(I)Z
    move-result v0
    if-eqz v0, :head
    invoke-static {}, LL;->a()V
    :join
    invoke-static {}, LL;->b()V
    goto :head
    :exit
    return-void
.end method

# a switch at the end of the body: every case returns to the header, and a
# case's `break` already does that -- no `continue` is written
.method public static switchTail()V
    .registers 1
    :head
    invoke-static {}, LL;->n()I
    move-result v0
    if-eqz v0, :exit
    packed-switch v0, :sw
    invoke-static {}, LL;->b()V
    goto :head
    :k1
    invoke-static {}, LL;->a()V
    goto :head
    :k2
    invoke-static {v0}, LL;->add(I)V
    goto :head
    :exit
    return-void
    :sw
    .packed-switch 0x1
        :k1
        :k2
    .end packed-switch
.end method

# BidiFormatter.skipTagBackward: an inner do-while whose test leaves it for the
# OUTER header -- the two loops share one back-edge source. The inner loop
# writes it as its test; the outer one must not write it again.
#   while (true) { v0 = n(); if (v0 == 0) break; if (!t(v0)) continue;
#                  do { v1 = n(); } while (v1 != v0); }
.method public static sharedLatch()V
    .registers 2
    :outer
    invoke-static {}, LL;->n()I
    move-result v0
    if-eqz v0, :exit
    invoke-static {v0}, LL;->t(I)Z
    move-result v1
    if-eqz v1, :outer
    :inner
    invoke-static {}, LL;->n()I
    move-result v1
    if-eq v1, v0, :outer
    goto :inner
    :exit
    return-void
.end method

# CONTROL: a real do-while -- one back edge, its test -- stays one
#   do { a(); v0 = n(); } while (v0 != 0);
.method public static doWhile()V
    .registers 1
    :head
    invoke-static {}, LL;->a()V
    invoke-static {}, LL;->n()I
    move-result v0
    if-nez v0, :head
    return-void
.end method

# a try at the end of the body: falling off it returns to the header, so no
# `continue` is written
#   while (true) { v0 = n(); if (v0 == 0) break;
#                  try { a(); } catch (RuntimeException e) { b(); } }
.method public static tryTail()V
    .registers 2
    :head
    invoke-static {}, LL;->n()I
    move-result v0
    if-eqz v0, :exit
    :ts
    invoke-static {}, LL;->a()V
    :te
    goto :head
    :h
    move-exception v1
    invoke-static {}, LL;->b()V
    goto :head
    :exit
    return-void
    .catch Ljava/lang/RuntimeException; {:ts .. :te} :h
.end method

# a back edge out of a try body whose follow is real join code: `continue`
#   while (true) { v0 = n(); if (v0 == 0) break;
#                  try { if (!t(v0)) continue; a(); } catch (RuntimeException e) { }
#                  b(); }
.method public static tryJoin()V
    .registers 2
    :head
    invoke-static {}, LL;->n()I
    move-result v0
    if-eqz v0, :exit
    :ts
    invoke-static {v0}, LL;->t(I)Z
    move-result v1
    if-eqz v1, :head
    invoke-static {}, LL;->a()V
    :te
    :join
    invoke-static {}, LL;->b()V
    goto :head
    :h
    move-exception v1
    goto :join
    :exit
    return-void
    .catch Ljava/lang/RuntimeException; {:ts .. :te} :h
.end method

# review finding: a `continue` in one arm of an if inside a switch case. DAD's
# need_break_ was the LAST jump written, so the case lost its `break;` and fell
# into the next one although the other arm leaves the case normally.
#   switch (v0) { case 1: if (!t(v0)) continue; a(); break; case 2: add(v0); }
.method public static swCont()V
    .registers 2
    :head
    invoke-static {}, LL;->n()I
    move-result v0
    if-eqz v0, :exit
    packed-switch v0, :sw
    goto :after
    :k1
    invoke-static {v0}, LL;->t(I)Z
    move-result v1
    if-eqz v1, :head
    invoke-static {}, LL;->a()V
    goto :after
    :k2
    invoke-static {v0}, LL;->add(I)V
    :after
    invoke-static {}, LL;->b()V
    goto :head
    :exit
    return-void
    :sw
    .packed-switch 0x1
        :k1
        :k2
    .end packed-switch
.end method

# review finding: a `continue` written BEFORE a switch leaked into the switch's
# first case, which then lost its `break;`
#   if (t(v0)) { if (n() == 0) continue; a(); } switch (v0) { case 1: c(); break; ... }
.method public static contBeforeSwitch()V
    .registers 2
    :head
    invoke-static {}, LL;->n()I
    move-result v0
    if-eqz v0, :exit
    invoke-static {v0}, LL;->t(I)Z
    move-result v1
    if-eqz v1, :sw0
    invoke-static {}, LL;->n()I
    move-result v1
    if-eqz v1, :head
    invoke-static {}, LL;->a()V
    :sw0
    packed-switch v0, :sw
    goto :after
    :k1
    invoke-static {}, LL;->c()V
    goto :after
    :k2
    invoke-static {v0}, LL;->add(I)V
    :after
    invoke-static {}, LL;->b()V
    goto :head
    :exit
    return-void
    :sw
    .packed-switch 0x1
        :k1
        :k2
    .end packed-switch
.end method

# a latch test whose branches both return to the header: the loop has no exit
# and is not a do-while
.method public static noExit()V
    .registers 1
    :head
    invoke-static {}, LL;->a()V
    invoke-static {}, LL;->n()I
    move-result v0
    if-eqz v0, :head
    goto :head
.end method

# a back edge through a catch handler (the dexllm#134 family): left to DAD,
# whose do-while is wrong here, and a `continue` must not appear inside it
.method public static handlerLatch()Z
    .registers 2
    :head
    invoke-static {}, LL;->n()I
    move-result v0
    if-nez v0, :one
    :ts
    invoke-static {}, LL;->a()V
    :te
    goto :head
    :h
    move-exception v1
    invoke-static {v0}, LL;->t(I)Z
    move-result v1
    if-nez v1, :head
    const/4 v0, 0
    return v0
    :one
    const/4 v0, 1
    return v0
    .catch Ljava/lang/RuntimeException; {:ts .. :te} :h
.end method

# a case that ends in `continue` takes no `break` after it
.method public static caseContinue()V
    .registers 1
    :head
    invoke-static {}, LL;->n()I
    move-result v0
    if-eqz v0, :exit
    packed-switch v0, :sw
    goto :after
    :k1
    invoke-static {}, LL;->a()V
    goto :head
    :k2
    invoke-static {v0}, LL;->add(I)V
    :after
    invoke-static {}, LL;->b()V
    goto :head
    :exit
    return-void
    :sw
    .packed-switch 0x1
        :k1
        :k2
    .end packed-switch
.end method

# an inner do-while whose test leaves for the outer header, inside an endless
# outer loop: the shared latch is written once, as the inner loop's test
.method public static sharedLatchDo()V
    .registers 2
    :outer
    invoke-static {}, LL;->n()I
    move-result v0
    if-eqz v0, :exit
    invoke-static {v0}, LL;->t(I)Z
    move-result v1
    if-eqz v1, :outer
    :inner
    invoke-static {}, LL;->a()V
    invoke-static {}, LL;->n()I
    move-result v1
    if-eq v1, v0, :outer
    goto :inner
    :exit
    return-void
.end method

# a throw ends a case: no `break` after it
.method public static caseThrow(I)V
    .registers 2
    packed-switch p0, :sw
    :after
    invoke-static {}, LL;->b()V
    return-void
    :k1
    new-instance v0, Ljava/lang/IllegalStateException;
    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V
    throw v0
    :k2
    invoke-static {}, LL;->a()V
    goto :after
    :sw
    .packed-switch 0x1
        :k1
        :k2
    .end packed-switch
.end method

# a try in a case completes normally when its body does, whatever the catch
# ends in
.method public static tryInCase(I)V
    .registers 2
    packed-switch p0, :sw
    :after
    invoke-static {}, LL;->b()V
    return-void
    :k1
    :ts
    invoke-static {}, LL;->a()V
    :te
    goto :after
    :h
    move-exception v0
    return-void
    :k2
    invoke-static {p0}, LL;->add(I)V
    goto :after
    :sw
    .packed-switch 0x1
        :k1
        :k2
    .end packed-switch
    .catch Ljava/lang/RuntimeException; {:ts .. :te} :h
.end method

# a loop in a case completes normally whatever its body ends in
.method public static loopInCase(I)V
    .registers 3
    packed-switch p0, :sw
    :after
    invoke-static {}, LL;->b()V
    return-void
    :k1
    :lh
    invoke-static {}, LL;->n()I
    move-result v0
    if-eqz v0, :after
    invoke-static {v0}, LL;->t(I)Z
    move-result v1
    if-eqz v1, :r
    invoke-static {}, LL;->a()V
    goto :lh
    :r
    return-void
    :k2
    invoke-static {p0}, LL;->add(I)V
    goto :after
    :sw
    .packed-switch 0x1
        :k1
        :k2
    .end packed-switch
.end method

# an if in a case with one returning arm: the case still takes its `break`
.method public static ifInCase(I)V
    .registers 2
    packed-switch p0, :sw
    :after
    invoke-static {}, LL;->b()V
    return-void
    :k1
    invoke-static {p0}, LL;->t(I)Z
    move-result v0
    if-eqz v0, :k1a
    return-void
    :k1a
    invoke-static {}, LL;->a()V
    goto :after
    :k2
    invoke-static {p0}, LL;->add(I)V
    goto :after
    :sw
    .packed-switch 0x1
        :k1
        :k2
    .end packed-switch
.end method

# a case holding a loop with no exit: nothing follows the loop, so the case
# takes no (unreachable) `break`
.method public static exitlessInCase(I)V
    .registers 2
    packed-switch p0, :sw
    :after
    invoke-static {}, LL;->b()V
    return-void
    :k1
    invoke-static {}, LL;->a()V
    goto :k1
    :k2
    invoke-static {p0}, LL;->add(I)V
    goto :after
    :sw
    .packed-switch 0x1
        :k1
        :k2
    .end packed-switch
.end method

# a handler-latch loop (left to DAD as a do-while) with a second, mid-body
# back edge: inside a do-while that edge is not a `continue`, which would jump
# to the do-while's test instead of the header
.method public static handlerLatchMid()V
    .registers 2
    :head
    invoke-static {}, LL;->n()I
    move-result v0
    if-nez v0, :exit
    :ts
    invoke-static {v0}, LL;->t(I)Z
    move-result v1
    if-eqz v1, :join
    invoke-static {v0}, LL;->t2(I)Z
    move-result v1
    if-eqz v1, :head
    invoke-static {}, LL;->a()V
    :join
    invoke-static {}, LL;->b()V
    :te
    goto :head
    :h
    move-exception v1
    invoke-static {v0}, LL;->t2(I)Z
    move-result v1
    if-nez v1, :head
    :exit
    return-void
    .catch Ljava/lang/RuntimeException; {:ts .. :te} :h
.end method

# delta review: one arm of a case's if falls into the next case, the other
# completes. One `break` after the if would stop the falling arm too; the
# completing arm takes its own.
#   case 0: if (t(p0)) { a(); /* falls */ } else { b(); break; }  case 1: c();
.method public static fallTrue(I)V
    .registers 2
    packed-switch p0, :sw
    goto :end
    :c0
    invoke-static {p0}, LL;->t(I)Z
    move-result v0
    if-eqz v0, :el
    invoke-static {}, LL;->a()V
    goto :c1
    :el
    invoke-static {}, LL;->b()V
    goto :end
    :c1
    invoke-static {}, LL;->c()V
    goto :end
    :c2
    invoke-static {p0}, LL;->add(I)V
    :end
    return-void
    :sw
    .packed-switch 0x0
        :c0
        :c1
        :c2
    .end packed-switch
.end method

# the mirror: the true arm completes, the false arm falls
.method public static fallFalse(I)V
    .registers 2
    packed-switch p0, :sw
    goto :end
    :c0
    invoke-static {p0}, LL;->t(I)Z
    move-result v0
    if-eqz v0, :el
    invoke-static {}, LL;->a()V
    goto :end
    :el
    invoke-static {}, LL;->b()V
    goto :c1
    :c1
    invoke-static {}, LL;->c()V
    goto :end
    :c2
    invoke-static {p0}, LL;->add(I)V
    :end
    return-void
    :sw
    .packed-switch 0x0
        :c0
        :c1
        :c2
    .end packed-switch
.end method

# a loop inside a case whose body leaves straight into the next case: a
# `break` there would leave the loop, not the switch, so no arm is split
.method public static loopToNextCase(I)V
    .registers 3
    packed-switch p0, :sw
    goto :end
    :c0
    :lh
    invoke-static {p0}, LL;->t(I)Z
    move-result v0
    if-eqz v0, :lx
    invoke-static {p0}, LL;->t2(I)Z
    move-result v1
    if-eqz v1, :c1
    invoke-static {}, LL;->a()V
    goto :lh
    :lx
    invoke-static {}, LL;->b()V
    goto :end
    :c1
    invoke-static {}, LL;->c()V
    goto :end
    :c2
    invoke-static {p0}, LL;->add(I)V
    :end
    return-void
    :sw
    .packed-switch 0x0
        :c0
        :c1
        :c2
    .end packed-switch
.end method
