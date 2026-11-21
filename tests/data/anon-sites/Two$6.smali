# dexllm#129 fixture (anon-sites.dex): see tests/data/README.md.
# Two$6 names ITSELF as its enclosing class and constructs itself in run():
# it must not be written inside its own body.
.class final Lsm/Two$6;
.super Ljava/lang/Object;
.implements Ljava/lang/Runnable;

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lsm/Two$6;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x8
    name = null
.end annotation

.method constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public run()V
    .registers 2
    new-instance v0, Lsm/Two$6;
    invoke-direct {v0}, Lsm/Two$6;-><init>()V
    invoke-virtual {v0}, Lsm/Two$6;->run()V
    return-void
.end method
