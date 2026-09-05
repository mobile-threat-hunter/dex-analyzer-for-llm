// dexllm#83 - a fixture where ONE string value reaches BOTH literal renderers.
//
// Every field below is a compile-time constant, so javac stores it in a
// ConstantValue attribute (d8 -> the class's `static_values` encoded_array, the
// `0x17 STRING` arm of DecodeEncodedValueText) AND inlines each READ of it as a
// `const-string` (the method-body arm, EscapeJavaString). `all()` returns an
// array rather than a concatenation precisely so javac cannot fold the values
// into one literal: each element is inlined separately, so the class carries
// both renderings of every value and a test can compare them.
//
// ONE VALUE PER BRANCH of the escaper rule, because a fixture where the two
// escapers AGREE proves nothing - and an adversarial review showed the first cut
// of this file was still short. VT / FF / NUL are controls Java has no short
// escape for (the `\xNN` cases, which are not Java at all); TAB / CR / LF and the
// quote / apostrophe / backslash are the SHORT-escape arms, which must run before
// the backslash-u branch or the Java lexer unterminates the literal (JLS 3.3); NEL,
// DEL and C1 and the two separators are what one escaper rendered raw and the
// other escaped, and DEL and C1 occur ZERO times in the whole corpus, so nothing
// but a fixture can reach them; CJK is the readable-BMP case and the emoji is the
// surrogate-pair case; and EMPTY exists because the change DELETES an empty-value
// special case, and a guard that only checks the declarations that are PRESENT
// cannot see one that stops being emitted at all.
//
// Written with octal / backslash-u escapes rather than raw characters so the
// source stays ASCII. javac translates a backslash-u escape before lexing (which
// is also why this sentence spells it out - it is translated inside a COMMENT
// too), and none of these is a Java LineTerminator (LF / CR only), so each ends
// up inside the literal exactly as written.
public class LiteralEscapes {
    public static final String VT = "\013";
    public static final String FF = "\f";
    public static final String NUL = "\0";
    public static final String TAB = "a\tb";
    public static final String NEL = "\u0085";
    public static final String DEL = "a\u007fb";
    public static final String C1 = "a\u009bb";
    public static final String LSEP = "\u2028";
    public static final String PSEP = "\u2029";
    public static final String QUOTE = "a\"b";
    public static final String APOS = "a\'b";
    public static final String BACKSLASH = "a\\b";
    public static final String CJK = "\uc5f0\uacb0";
    public static final String ASTRAL = "\ud83d\ude00";
    public static final String EMPTY = "";
    public static final String MIXED = "\n\013\f\r\u0085\u2028\u2029";

    public static String[] all() {
        return new String[] {
            VT, FF, NUL, TAB, NEL, DEL, C1, LSEP, PSEP, QUOTE, APOS, BACKSLASH,
            CJK, ASTRAL, EMPTY, MIXED
        };
    }
}
