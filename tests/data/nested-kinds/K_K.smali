# dexllm#128 fixture (nested-kinds.dex): see tests/data/README.md.
.class public Lnk/K$K;
.super Ljava/lang/Object;

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lnk/K;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "K"
.end annotation

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
