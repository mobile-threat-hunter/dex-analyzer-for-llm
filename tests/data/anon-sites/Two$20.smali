# dexllm#129 fixture (anon-sites.dex): see tests/data/README.md.
.class final Lsm/Two$20;
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
    iput-object p1, p0, Lsm/Two$20;->val$s:Ljava/lang/String;
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public run()V
    .registers 2
    :try_start
    invoke-static {}, Lsm/Two;->get()Ljava/lang/String;
    :try_end
    .catch Ljava/lang/Exception; {:try_start .. :try_end} :handler
    return-void
    :handler
    move-exception v0
    iget-object v1, p0, Lsm/Two$20;->val$s:Ljava/lang/String;
    invoke-static {v1}, Lsm/Two;->use(Ljava/lang/Object;)V
    return-void
.end method
