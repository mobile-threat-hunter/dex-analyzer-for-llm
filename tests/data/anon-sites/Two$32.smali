# dexllm#129 fixture (anon-sites.dex): see tests/data/README.md.
.class final Lsm/Two$32;
.super Lsm/Over;

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lsm/Two;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x8
    name = null
.end annotation

.method constructor <init>(Ljava/lang/Object;)V
    .registers 2
    invoke-direct {p0, p1}, Lsm/Over;-><init>(Ljava/lang/Object;)V
    return-void
.end method

.method public run()V
    .registers 1
    return-void
.end method
