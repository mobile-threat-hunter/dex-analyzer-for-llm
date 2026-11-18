# dexllm#128 fixture (nested-kinds.dex): see tests/data/README.md.
.class  Lnk/K$P$K;
.super Ljava/lang/Object;

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lnk/K$P;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x8
    name = "K"
.end annotation

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
