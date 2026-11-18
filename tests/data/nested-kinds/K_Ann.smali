# dexllm#128 fixture (nested-kinds.dex): see tests/data/README.md.
.class public interface abstract annotation Lnk/K$Ann;
.super Ljava/lang/Object;
.implements Ljava/lang/annotation/Annotation;

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lnk/K;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x2609
    name = "Ann"
.end annotation
