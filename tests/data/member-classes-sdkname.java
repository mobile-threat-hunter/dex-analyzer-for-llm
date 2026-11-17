// dexllm#127 fixture, second source file: a class a loaded dex DECLARES
// under a name the SDK lists as a member class, but WITHOUT the
// InnerClass/EnclosingClass annotations (it is top-level here). The dex's copy
// is the one being read, so nothing proves a nesting and its `$` must stay.
package android.view;

public class View$OnClickListener {
    public static int z;
}
