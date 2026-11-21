# dexllm#129 fixture (anon-sites.dex): see tests/data/README.md.
.class final Lsm/Two$14;
.super Ljava/lang/Object;
.implements Ljava/lang/Runnable;

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lsm/Two;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x8
    name = null
.end annotation

.field final synthetic val$s:Ljava/lang/String;

.method constructor <init>(Ljava/lang/String;)V
    .registers 2
    iput-object p1, p0, Lsm/Two$14;->val$s:Ljava/lang/String;
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public other(Lsm/Two$14;)Ljava/lang/String;
    .registers 3
    iget-object v0, p1, Lsm/Two$14;->val$s:Ljava/lang/String;
    return-object v0
.end method

.method public run()V
    .registers 1
    return-void
.end method
