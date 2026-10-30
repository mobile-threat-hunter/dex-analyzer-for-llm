# dexllm#92 fixture -- a `long` (J) constant in every position a long literal
# is rendered, plus the int / double controls that must NOT gain an `L`.
# Hand-written smali so each const-wide stays a distinct, propagated literal.
.class public LLongLiterals;
.super Ljava/lang/Object;

# static initializers (DecodeEncodedValueText 0x06), one per width d8 picks
.field public static final SMALL:J = 0x5L
.field public static final NEG:J = -0x1L
.field public static final BIG:J = 0xdc6d62da00L
.field public static final EDGE:J = 0x80000000L
.field public static final MIN:J = -0x8000000000000000L
.field public static final MAX:J = 0x7fffffffffffffffL
# controls: an int initializer stays bare
.field public static final INT_F:I = 0x5

.field static sJ:J
.field iJ:J

.method static takeOv(I)V
    .registers 1
    return-void
.end method
.method static takeOv(J)V
    .registers 2
    return-void
.end method
.method static takeD(D)V
    .registers 2
    return-void
.end method

# a small long at an overloaded (J) parameter: bare `220` would bind takeOv(I)
.method static argSmall()V
    .registers 2
    const-wide/16 v0, 0xdcL
    invoke-static {v0, v1}, LLongLiterals;->takeOv(J)V
    return-void
.end method

# control: an int at the (I) overload stays `220`
.method static argInt()V
    .registers 1
    const/16 v0, 0xdc
    invoke-static {v0}, LLongLiterals;->takeOv(I)V
    return-void
.end method

# out of the int range: the lexer needs the suffix
.method static argBig()V
    .registers 2
    const-wide v0, 0xdc6d62da00L
    invoke-static {v0, v1}, LLongLiterals;->takeOv(J)V
    return-void
.end method

# Long.MIN_VALUE: `-9223372036854775808L` is the one literal unary minus may apply to
.method static retMin()J
    .registers 2
    const-wide/high16 v0, -0x8000000000000000L
    return-wide v0
.end method

.method static retZero()J
    .registers 2
    const-wide/16 v0, 0x0L
    return-wide v0
.end method

.method static retNeg()J
    .registers 2
    const-wide/16 v0, -0x1L
    return-wide v0
.end method

.method static addOne(J)J
    .registers 4
    const-wide/16 v0, 0x1L
    add-long v0, p0, v0
    return-wide v0
.end method

.method static cmpHundred(J)Z
    .registers 4
    const-wide/16 v0, 0x64L
    cmp-long v0, p0, v0
    if-lez v0, :no
    const/4 v0, 0x1
    return v0
    :no
    const/4 v0, 0x0
    return v0
.end method

.method static storeStatic()V
    .registers 2
    const-wide/16 v0, 0x7L
    sput-wide v0, LLongLiterals;->sJ:J
    return-void
.end method

.method storeInstance()V
    .registers 3
    const-wide v0, 0x80000000L
    iput-wide v0, p0, LLongLiterals;->iJ:J
    return-void
.end method

# control: a const-wide at a DOUBLE position is reinterpreted as 1.0, never `...L`
.method static argDouble()V
    .registers 2
    const-wide/high16 v0, 0x3ff0000000000000L
    invoke-static {v0, v1}, LLongLiterals;->takeD(D)V
    return-void
.end method

# dexllm#92 review: a const-wide READ AS A DOUBLE by a conversion / a negation is
# the double 1.0, never the long `4607182418800017408L` (javac would accept that
# and compute 0 / -4.6e18). Controls: the same shapes reading a LONG keep `L`.
.method static castDoubleBits()I
    .registers 2
    const-wide/high16 v0, 0x3ff0000000000000L
    double-to-int v0, v0
    return v0
.end method

.method static negDoubleBits()D
    .registers 2
    const-wide/high16 v0, 0x3ff0000000000000L
    neg-double v0, v0
    return-wide v0
.end method

.method static castLong()I
    .registers 2
    const-wide v0, 0x100000000L
    long-to-int v0, v0
    return v0
.end method

.method static negLong()J
    .registers 2
    const-wide/16 v0, 0x5L
    neg-long v0, v0
    return-wide v0
.end method

# the same projection for a FLOAT operand (const/high16 holds float bits):
# before this fix the corpus rendered `(- 2139095039)` for -Float.MAX_VALUE
.method static negFloatBits()F
    .registers 1
    const/high16 v0, 0x3f800000
    neg-float v0, v0
    return v0
.end method
