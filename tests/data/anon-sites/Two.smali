# dexllm#129 fixture (anon-sites.dex): see tests/data/README.md.
.class public Lsm/Two;
.super Ljava/lang/Object;

# The enclosing class names Two$30 in a field: that class needs its name.
.field static keep:Lsm/Two$30;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

# Two methods construct Two$1: Java cannot write this, a shrinker can.
.method public static a()Ljava/lang/Runnable;
    .registers 1
    new-instance v0, Lsm/Two$1;
    invoke-direct {v0}, Lsm/Two$1;-><init>()V
    return-object v0
.end method

.method public static b()Ljava/lang/Runnable;
    .registers 1
    new-instance v0, Lsm/Two$1;
    invoke-direct {v0}, Lsm/Two$1;-><init>()V
    return-object v0
.end method

# One method constructs Two$2, so it is inlined: the control.
.method public static c()Ljava/lang/Runnable;
    .registers 1
    new-instance v0, Lsm/Two$2;
    invoke-direct {v0}, Lsm/Two$2;-><init>()V
    return-object v0
.end method

# Two$3 captures its argument as `val$s`, read as `p1` (the parameter of d),
# and declares a field named `p1` that an unqualified `p1` would find first.
.method public static d(Ljava/lang/String;)Ljava/lang/Runnable;
    .registers 2
    new-instance v0, Lsm/Two$3;
    invoke-direct {v0, p0}, Lsm/Two$3;-><init>(Ljava/lang/String;)V
    return-object v0
.end method

# Two$4 captures its argument, and its run() WRITES the captured field.
.method public static e(Ljava/lang/String;)Ljava/lang/Runnable;
    .registers 2
    new-instance v0, Lsm/Two$4;
    invoke-direct {v0, p0}, Lsm/Two$4;-><init>(Ljava/lang/String;)V
    return-object v0
.end method

# Two$5 captures its argument and only reads it: the control for d and e.
.method public static f(Ljava/lang/String;)Ljava/lang/Runnable;
    .registers 2
    new-instance v0, Lsm/Two$5;
    invoke-direct {v0, p0}, Lsm/Two$5;-><init>(Ljava/lang/String;)V
    return-object v0
.end method

# Two$7 is flagged ENUM but otherwise plain: an enum body is not inlined.
.method public static g()Ljava/lang/Runnable;
    .registers 1
    new-instance v0, Lsm/Two$7;
    invoke-direct {v0}, Lsm/Two$7;-><init>()V
    return-object v0
.end method

# Two$8 extends the LOCAL class Two$1Loc, which no source outside h() names.
.method public static h()Ljava/lang/Object;
    .registers 1
    new-instance v0, Lsm/Two$8;
    invoke-direct {v0}, Lsm/Two$8;-><init>()V
    return-object v0
.end method

# Two$9's constructor stores its value into ANOTHER instance's field.
.method public static i(Lsm/Two$9;Ljava/lang/String;)Ljava/lang/Runnable;
    .registers 3
    new-instance v0, Lsm/Two$9;
    invoke-direct {v0, p0, p1}, Lsm/Two$9;-><init>(Lsm/Two$9;Ljava/lang/String;)V
    return-object v0
.end method

# Two$10's constructor runs an instance initializer (prints) and stores nothing.
.method public static j()Ljava/lang/Runnable;
    .registers 1
    new-instance v0, Lsm/Two$10;
    invoke-direct {v0}, Lsm/Two$10;-><init>()V
    return-object v0
.end method

# Two$11's constructor calls the constructor of a class that is not its superclass.
.method public static k()Ljava/lang/Runnable;
    .registers 1
    new-instance v0, Lsm/Two$11;
    invoke-direct {v0}, Lsm/Two$11;-><init>()V
    return-object v0
.end method

# Two$12 constructs Two$12$1 in run(): an anonymous class inside an inlined
# one, with nothing captured, is inlined too (two levels).
.method public static l()Ljava/lang/Runnable;
    .registers 1
    new-instance v0, Lsm/Two$12;
    invoke-direct {v0}, Lsm/Two$12;-><init>()V
    return-object v0
.end method

# Two$13 stores ONE parameter into two fields.
.method public static m(Ljava/lang/String;)Ljava/lang/Runnable;
    .registers 2
    new-instance v0, Lsm/Two$13;
    invoke-direct {v0, p0}, Lsm/Two$13;-><init>(Ljava/lang/String;)V
    return-object v0
.end method

# Two$14 reads its captured field through ANOTHER instance (a parameter).
.method public static n(Ljava/lang/String;)Ljava/lang/Runnable;
    .registers 2
    new-instance v0, Lsm/Two$14;
    invoke-direct {v0, p0}, Lsm/Two$14;-><init>(Ljava/lang/String;)V
    return-object v0
.end method

# Two$15 says it is enclosed by a(), and only o() constructs it.
.method public static o()Ljava/lang/Runnable;
    .registers 1
    new-instance v0, Lsm/Two$15;
    invoke-direct {v0}, Lsm/Two$15;-><init>()V
    return-object v0
.end method

# Two$16's constructor calls its superclass constructor twice.
.method public static q()Ljava/lang/Runnable;
    .registers 1
    new-instance v0, Lsm/Two$16;
    invoke-direct {v0}, Lsm/Two$16;-><init>()V
    return-object v0
.end method

# Two$17's constructor calls the superclass constructor on ANOTHER object.
.method public static r(Lsm/Two$17;)Ljava/lang/Runnable;
    .registers 2
    new-instance v0, Lsm/Two$17;
    invoke-direct {v0, p0}, Lsm/Two$17;-><init>(Lsm/Two$17;)V
    return-object v0
.end method

# Two$18 passes its parameters to the superclass in REVERSE order.
.method public static t(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Object;
    .registers 3
    new-instance v0, Lsm/Two$18;
    invoke-direct {v0, p0, p1}, Lsm/Two$18;-><init>(Ljava/lang/String;Ljava/lang/String;)V
    return-object v0
.end method

# Two$19 has two constructors; t2() uses the one taking (and dropping) an int.
.method public static t2(I)Ljava/lang/Runnable;
    .registers 2
    new-instance v0, Lsm/Two$19;
    invoke-direct {v0, p0}, Lsm/Two$19;-><init>(I)V
    return-object v0
.end method

# Two$20's body catches into v0, the register the site's captured local is
# named after: the catch variable would shadow the capture.
.method public static u()Ljava/lang/Runnable;
    .registers 2
    invoke-static {}, Lsm/Two;->get()Ljava/lang/String;
    move-result-object v0
    invoke-static {v0}, Lsm/Two;->use(Ljava/lang/Object;)V
    new-instance v1, Lsm/Two$20;
    invoke-direct {v1, v0}, Lsm/Two$20;-><init>(Ljava/lang/String;)V
    return-object v1
.end method

.method public static get()Ljava/lang/String;
    .registers 1
    const-string v0, "g"
    return-object v0
.end method

.method public static use(Ljava/lang/Object;)V
    .registers 1
    return-void
.end method

# Two$21 captures p0 inside a loop that writes p0 again: one name for two
# values, so the body cannot read it as the captured one.
.method public static w(Ljava/lang/String;)Ljava/lang/Runnable;
    .registers 2
    :loop
    new-instance v0, Lsm/Two$21;
    invoke-direct {v0, p0}, Lsm/Two$21;-><init>(Ljava/lang/String;)V
    invoke-static {v0}, Lsm/Two;->use(Ljava/lang/Object;)V
    invoke-static {}, Lsm/Two;->get()Ljava/lang/String;
    move-result-object p0
    if-nez p0, :loop
    return-object v0
.end method

# Two$22's captured field is not final.
.method public static x(Ljava/lang/String;)Ljava/lang/Runnable;
    .registers 2
    new-instance v0, Lsm/Two$22;
    invoke-direct {v0, p0}, Lsm/Two$22;-><init>(Ljava/lang/String;)V
    return-object v0
.end method

# Two$23's constructor returns before calling its superclass constructor.
.method public static y()Ljava/lang/Runnable;
    .registers 1
    new-instance v0, Lsm/Two$23;
    invoke-direct {v0}, Lsm/Two$23;-><init>()V
    return-object v0
.end method

# Two$24 extends Base2, which declares a field `p1`: an unqualified `p1` in
# the body would read it, not the captured parameter.
.method public static z(Ljava/lang/String;)Ljava/lang/Object;
    .registers 2
    new-instance v0, Lsm/Two$24;
    invoke-direct {v0, p0}, Lsm/Two$24;-><init>(Ljava/lang/String;)V
    return-object v0
.end method

# Two$25's run() does not decompile.
.method public static zz()Ljava/lang/Runnable;
    .registers 1
    new-instance v0, Lsm/Two$25;
    invoke-direct {v0}, Lsm/Two$25;-><init>()V
    return-object v0
.end method

# Two$26's run() declares a local v0, the name the site gives the capture.
.method public static u2()Ljava/lang/Runnable;
    .registers 2
    invoke-static {}, Lsm/Two;->get()Ljava/lang/String;
    move-result-object v0
    invoke-static {v0}, Lsm/Two;->use(Ljava/lang/Object;)V
    new-instance v1, Lsm/Two$26;
    invoke-direct {v1, v0}, Lsm/Two$26;-><init>(Ljava/lang/String;)V
    return-object v1
.end method

# Two$27: the site reads a field only Two$27 declares, through the object.
.method public static k1()I
    .registers 2
    new-instance v0, Lsm/Two$27;
    invoke-direct {v0}, Lsm/Two$27;-><init>()V
    iget v1, v0, Lsm/Two$27;->label:I
    return v1
.end method

# Two$28: the site calls a method only Two$28 declares.
.method public static k2()V
    .registers 1
    new-instance v0, Lsm/Two$28;
    invoke-direct {v0}, Lsm/Two$28;-><init>()V
    invoke-virtual {v0}, Lsm/Two$28;->extra()V
    return-void
.end method

# Two$29: the site tests `instanceof Two$29`.
.method public static k3(Ljava/lang/Object;)Ljava/lang/Object;
    .registers 2
    instance-of v0, p0, Lsm/Two$29;
    if-eqz v0, :new
    return-object p0
    :new
    new-instance v0, Lsm/Two$29;
    invoke-direct {v0}, Lsm/Two$29;-><init>()V
    return-object v0
.end method

# Two$30 is the type of Two's field `keep`.
.method public static k4()Ljava/lang/Object;
    .registers 1
    new-instance v0, Lsm/Two$30;
    invoke-direct {v0}, Lsm/Two$30;-><init>()V
    return-object v0
.end method

# Two$31: the site calls an INHERITED method through Two$31: still inlined.
.method public static k5()Ljava/lang/String;
    .registers 1
    new-instance v0, Lsm/Two$31;
    invoke-direct {v0}, Lsm/Two$31;-><init>()V
    invoke-virtual {v0}, Lsm/Two$31;->toString()Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method

# Two$32 extends Over, which has Over(Object) and Over(String); the bytecode
# passes a String constant to Over(Object).
.method public static k6()Ljava/lang/Object;
    .registers 2
    new-instance v0, Lsm/Two$32;
    const-string v1, "s"
    invoke-direct {v0, v1}, Lsm/Two$32;-><init>(Ljava/lang/Object;)V
    return-object v0
.end method
