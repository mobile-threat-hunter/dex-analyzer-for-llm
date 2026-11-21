# dexllm#129 fixture (anon-sites.dex): see tests/data/README.md.
# A LOCAL class of h(): named, but only inside its method.
.class Lsm/Two$1Loc;
.super Ljava/lang/Object;

.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lsm/Two;->h()Ljava/lang/Object;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x0
    name = "Loc"
.end annotation

.method constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
