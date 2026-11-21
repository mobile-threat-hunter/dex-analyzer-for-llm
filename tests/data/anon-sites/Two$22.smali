# dexllm#129 fixture (anon-sites.dex): see tests/data/README.md.
.class final Lsm/Two$22;
.super Ljava/lang/Object;
.implements Ljava/lang/Runnable;

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lsm/Two;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x8
    name = null
.end annotation

.field synthetic val$s:Ljava/lang/String;

.method constructor <init>(Ljava/lang/String;)V
    .registers 2
    iput-object p1, p0, Lsm/Two$22;->val$s:Ljava/lang/String;
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public run()V
    .registers 3
    iget-object v0, p0, Lsm/Two$22;->val$s:Ljava/lang/String;
    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;
    invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V
    return-void
.end method
