# companion of arg-order.smali: a class with a static final field and an initializer
.class public LV;
.super Ljava/lang/Object;

.field public static final X:I

.method static constructor <clinit>()V
    .registers 1
    invoke-static {}, LW;->next()I
    move-result v0
    sput v0, LV;->X:I
    return-void
.end method
