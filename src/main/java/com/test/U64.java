package com.test;

public final class U64 {
    short w3; // highest 16 bits
    short w2;
    short w1;
    short w0; // lowest 16 bits

    U64() {}

    U64(short w3, short w2, short w1, short w0) {
        this.w3 = w3;
        this.w2 = w2;
        this.w1 = w1;
        this.w0 = w0;
    }

    static void set(U64 x, short w3, short w2, short w1, short w0)
    {
        x.w3 = w3;
        x.w2 = w2;
        x.w1 = w1;
        x.w0 = w0;
    }

    static void getU64(short[] hiHi, short[] hiLo, short[] loHi, short[] loLo, short i, U64 out)
    {
        out.w3 = hiHi[i];
        out.w2 = hiLo[i];
        out.w1 = loHi[i];
        out.w0 = loLo[i];
    }

    static void copy(U64 src, U64 dst)
    {
        dst.w3 = src.w3;
        dst.w2 = src.w2;
        dst.w1 = src.w1;
        dst.w0 = src.w0;
    }

    static void xor(U64 a, U64 b, U64 out)
    {
        out.w3 = (short)(a.w3 ^ b.w3);
        out.w2 = (short)(a.w2 ^ b.w2);
        out.w1 = (short)(a.w1 ^ b.w1);
        out.w0 = (short)(a.w0 ^ b.w0);
    }

    static void and(U64 a, U64 b, U64 out)
    {
        out.w3 = (short)(a.w3 & b.w3);
        out.w2 = (short)(a.w2 & b.w2);
        out.w1 = (short)(a.w1 & b.w1);
        out.w0 = (short)(a.w0 & b.w0);
    }

    static void or(U64 a, U64 b, U64 out)
    {
        out.w3 = (short)(a.w3 | b.w3);
        out.w2 = (short)(a.w2 | b.w2);
        out.w1 = (short)(a.w1 | b.w1);
        out.w0 = (short)(a.w0 | b.w0);
    }

    public static void not(U64 src, U64 dst)
    {
        dst.w0 = (short)~src.w0;
        dst.w1 = (short)~src.w1;
        dst.w2 = (short)~src.w2;
        dst.w3 = (short)~src.w3;
    }

    public static void rol1(U64 src, U64 dst)
    {
        short c0 = (short)((src.w0 < 0) ? 1 : 0);
        short c1 = (short)((src.w1 < 0) ? 1 : 0);
        short c2 = (short)((src.w2 < 0) ? 1 : 0);
        short c3 = (short)((src.w3 < 0) ? 1 : 0);

        dst.w0 = (short)(src.w0 << 1);
        dst.w1 = (short)(src.w1 << 1);
        dst.w2 = (short)(src.w2 << 1);
        dst.w3 = (short)(src.w3 << 1);

        dst.w1 |= c0;
        dst.w2 |= c1;
        dst.w3 |= c2;
        dst.w0 |= c3;
    }

    public static void rol(U64 src, short count, U64 dst)
    {
        count &= 63;
        if (count == 0) {
            copy(src, dst);
            return;
        }

        U64 tmpA = new U64();
        U64 tmpB = new U64();
        copy(src, tmpA);

        while (count-- > 0) {
            rol1(tmpA, tmpB);
            copy(tmpB, tmpA);
        }

        copy(tmpA, dst);
    }

    static short msb(U64 a) {
        return (short)((a.w3 >>> 15) & 1);
    }

    static void clearMsb(U64 a) {
        a.w3 = (short)(a.w3 & 0x7FFF);
    }

    static void select(U64 x, U64 y, short mask, U64 out)
    {
        out.w3 = (short)(x.w3 ^ (mask & (x.w3 ^ y.w3)));
        out.w2 = (short)(x.w2 ^ (mask & (x.w2 ^ y.w2)));
        out.w1 = (short)(x.w1  ^ (mask & (x.w1 ^ y.w1)));
        out.w0 = (short)(x.w0 ^ (mask & (x.w0 ^ y.w0)));
    }

    private static short uLessThan16(short a, short b)
    {
        return (short)(((a ^ (short)0x8000) < (b ^ (short)0x8000)) ? 1 : 0);
    }

    static short ult(U64 a, U64 b)
    {
        if (a.w3 != b.w3) {
            return uLessThan16(a.w3, b.w3);
        }

        if (a.w2 != b.w2) {
            return uLessThan16(a.w2, b.w2);
        }

        if (a.w1 != b.w1) {
            return uLessThan16(a.w1, b.w1);
        }

        return uLessThan16(a.w0, b.w0);
    }
}