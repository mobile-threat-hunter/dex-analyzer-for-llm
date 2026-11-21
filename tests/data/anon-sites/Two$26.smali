# dexllm#129 fixture (anon-sites.dex): see tests/data/README.md.
.class final Lsm/Two$26;
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
    iput-object p1, p0, Lsm/Two$26;->val$s:Ljava/lang/String;
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public run()V
    .registers 2
    invoke-static {}, Lsm/Two;->get()Ljava/lang/String;
    move-result-object v0
    invoke-static {v0}, Lsm/Two;->use(Ljava/lang/Object;)V
    invoke-static {v0}, Lsm/Two;->use(Ljava/lang/Object;)V
    iget-object v1, p0, Lsm/Two$26;->val$s:Ljava/lang/String;
    invoke-static {v1}, Lsm/Two;->use(Ljava/lang/Object;)V
    return-void
.end method
