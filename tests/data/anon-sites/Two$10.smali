# dexllm#129 fixture (anon-sites.dex): see tests/data/README.md.
.class final Lsm/Two$10;
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
    .registers 3
    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    sget-object v0, Ljava/lang/System;->out:Ljava/io/PrintStream;
    const-string v1, "init"
    invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V
    return-void
.end method

.method public run()V
    .registers 1
    return-void
.end method
