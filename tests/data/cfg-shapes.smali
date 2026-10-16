# dexllm#113 fixture: control-flow shapes on which the text Writer diverged
# from the AST (dast.cpp) and from androguard DAD's writer.py.
# Assemble: java -cp jadx-1.5.3-all.jar com.android.tools.smali.smali.Main \
#               a cfg-shapes.smali -o cfg-shapes.dex
.class public LCfgShapes;
.super Ljava/lang/Object;

# An if with NO follow whose false arm is a return block the true arm also
# reaches: tvleanback MediaSessionCompatApi21.hasCallback, register for
# register. The shared `return v2` is also the target of the catch tails,
# which is what leaves the if without a follow.
.method public static hasCallback(Ljava/lang/Object;)Z
    .registers 7
    const/4 v2, 0x1
    const/4 v3, 0x0
    const/4 v0, 0x0
    :try_start
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    move-result-object v4
    const-string v5, "mCallback"
    invoke-virtual {v4, v5}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;
    move-result-object v0
    :try_end
    .catch Ljava/lang/NoSuchFieldException; {:try_start .. :try_end} :handler
    if-eqz v0, :none
    const/4 v4, 0x1
    :try_start2
    invoke-virtual {v0, v4}, Ljava/lang/reflect/Field;->setAccessible(Z)V
    invoke-virtual {v0, p0}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;
    move-result-object v4
    :try_end2
    .catch Ljava/lang/IllegalAccessException; {:try_start2 .. :try_end2} :handler2
    if-eqz v4, :null_value
    :ret
    return v2
    :null_value
    move v2, v3
    goto :ret
    :handler
    move-exception v1
    const-string v2, "CfgShapes"
    const-string v4, "Failed to get mCallback object."
    invoke-static {v2, v4}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :none
    move v2, v3
    goto :ret
    :handler2
    move-exception v1
    goto :none
.end method

# A switch whose `default` IS one of its case blocks (case 3 -> :dflt, the
# switch's own fall-through).
.method public static sharedDefault(I)I
    .registers 2
    packed-switch p0, :tbl
    :dflt
    const/16 v0, 0x63
    return v0
    :c2
    const/16 v0, 0x14
    return v0
    :c4
    const/16 v0, 0x28
    return v0
    :tbl
    .packed-switch 0x2
        :c2
        :dflt
        :c4
    .end packed-switch
.end method

# A follow-less if inside a switch case whose false arm IS the switch follow
# (the `switch (s.hashCode()) { case H: if (s.equals("x")) v = 0; break; }`
# shape javac emits): VisitNode writes nothing for that arm, so the text must
# not open an empty `} else { }`.
.method public static caseIf(ILjava/lang/String;)I
    .registers 4
    const/4 v0, -0x1
    packed-switch p0, :tbl
    :after
    return v0
    :c0
    const-string v1, "tap"
    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v1
    if-nez v1, :s0
    goto :after
    :s0
    const/4 v0, 0x0
    goto :after
    :c1
    const-string v1, "focus"
    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v1
    if-nez v1, :s1
    goto :after
    :s1
    const/4 v0, 0x1
    goto :after
    :tbl
    .packed-switch 0x0
        :c0
        :c1
    .end packed-switch
.end method

# A default that IS case 3's block, which then FALLS THROUGH into case 4.
# Emitting the default separately at the end (the pre-#113 text) skipped the
# store on the default path: a semantic change, not only a duplicate.
.method public static fallDefault(I)I
    .registers 2
    const/4 v0, 0x0
    packed-switch p0, :tbl
    :dflt
    const/16 v0, 0x7
    :c4
    add-int/lit8 v0, v0, 0x1
    return v0
    :c2
    const/4 v0, 0x2
    return v0
    :tbl
    .packed-switch 0x2
        :c2
        :dflt
        :c4
    .end packed-switch
.end method
