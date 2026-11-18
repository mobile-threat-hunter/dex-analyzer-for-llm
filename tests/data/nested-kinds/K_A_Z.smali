# dexllm#128 fixture (nested-kinds.dex): see tests/data/README.md.
# Two siblings (Q, A) each declare a member named Z: one must not hide the other.
.class public Lnk/K$A$Z;
.super Ljava/lang/Object;

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lnk/K$A;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Z"
.end annotation
