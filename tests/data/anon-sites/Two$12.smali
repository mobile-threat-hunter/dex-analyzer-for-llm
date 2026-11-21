# dexllm#129 fixture (anon-sites.dex): see tests/data/README.md.
.class final Lsm/Two$12;
.super Ljava/lang/Object;
.implements Ljava/lang/Runnable;

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lsm/Two;
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
    new-instance v0, Lsm/Two$12$1;
    invoke-direct {v0}, Lsm/Two$12$1;-><init>()V
    invoke-interface {v0}, Ljava/lang/Runnable;->run()V
    return-void
.end method
