// dexllm#91 fixture: one static initializer per branch of the integer-family
// encoded_value rule. SHORT / INT / LONG are SIGN-extended from value_arg+1
// bytes; CHAR is the one ZERO-extended member. d8 encodes each value in the
// fewest bytes that hold it SIGNED, so the byte count is part of the shape:
// a one-byte 0xff is -1 for an int but 255 for nothing, while a positive 128
// needs two bytes (80 00) and is the control that must stay positive.
public class NegativeStatics {
    public static final short SHORT_MINUS_ONE = -1;          // ff          (1 byte)
    public static final short SHORT_MIN = Short.MIN_VALUE;   // 00 80       (2 bytes)
    public static final int INT_MINUS_ONE = -1;              // ff          (1 byte)
    public static final int INT_MINUS_128 = -128;            // 80          (1 byte)
    public static final int INT_PLUS_128 = 128;              // 80 00       (2 bytes, control)
    public static final int INT_ALPHA_MASK = 0xff000000;     // 00 00 00 ff (4 bytes)
    public static final int INT_MIN = Integer.MIN_VALUE;     // 00 00 00 80
    public static final int INT_MAX = Integer.MAX_VALUE;     // ff ff ff 7f (control)
    public static final long LONG_MINUS_ONE = -1L;           // ff          (1 byte)
    public static final long LONG_MIN = Long.MIN_VALUE;      // 8 bytes, top 0x80
    public static final long LONG_MINUS_2_32 = -(1L << 32);  // 00 00 00 00 ff (5 bytes)
    public static final long LONG_PLUS_255 = 255L;           // ff 00       (2 bytes, control)
    public static final char CHAR_0X80 = '\u0080';           // 80          (1 byte, must stay 128)
    public static final char CHAR_MAX = '￿';            // ff ff       (must stay 65535)
    public static final byte BYTE_MINUS_ONE = -1;            // the BYTE arm, untouched

    // Every READ of a compile-time constant is inlined by javac as a `const*`
    // instruction, so each value also reaches the Java view through the
    // METHOD BODY's reader - a second, independent reader of the same fact.
    // An array, not a concatenation, so javac cannot fold the values together.
    public static Object[] all() {
        return new Object[] {
            SHORT_MINUS_ONE, SHORT_MIN, INT_MINUS_ONE, INT_MINUS_128, INT_PLUS_128,
            INT_ALPHA_MASK, INT_MIN, INT_MAX, LONG_MINUS_ONE, LONG_MIN,
            LONG_MINUS_2_32, LONG_PLUS_255, CHAR_0X80, CHAR_MAX, BYTE_MINUS_ONE,
        };
    }
}
