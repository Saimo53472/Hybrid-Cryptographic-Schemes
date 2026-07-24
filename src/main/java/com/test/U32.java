package com.test;

final class U32 {
    short hi;
    short lo;

    U32() {}

    U32(short hi, short lo) {
        this.hi = hi;
        this.lo = lo;
    }

    static void set(U32 x, short hi, short lo) {
        x.hi = hi;
        x.lo = lo;
    }

    static void copy(U32 dst, U32 src) {
        dst.hi = src.hi;
        dst.lo = src.lo;
    }

    static void xor(U32 a, U32 b, U32 out) {
        out.hi = (short)(a.hi ^ b.hi);
        out.lo = (short)(a.lo ^ b.lo);
    }

    static void and(U32 a, U32 b, U32 out) {
        out.hi = (short)(a.hi & b.hi);
        out.lo = (short)(a.lo & b.lo);
    }

    static void or(U32 a, U32 b, U32 out) {
        out.hi = (short)(a.hi | b.hi);
        out.lo = (short)(a.lo | b.lo);
    }

    static final short MASK1 = (short)0x1111;
    static final short MASK2 = (short)0x2222;
    static final short MASK4 = (short)0x4444;
    static final short MASK8 = (short)0x8888;

    static void andMask(U32 a, short mask, U32 out) {
        out.hi = (short)(a.hi & mask);
        out.lo = (short)(a.lo & mask);
    }

    static short high(U32 x) {
        return x.hi;
    }

    static short low(U32 x) {
        return x.lo;
    }

    static boolean isZero(U32 x) {
        return x.hi == 0 && x.lo == 0;
    }

    static short xorReduce(U32 x)
    {
        return (short)(x.hi ^ x.lo);
    }

    private static short uLessThan(
        short aHi, short aLo,
        short bHi, short bLo)
    {
        if (aHi != bHi) {
            return (short)(((aHi ^ (short)0x8000)
                    < (bHi ^ (short)0x8000)) ? 1 : 0);
        }

        return (short)(((aLo ^ (short)0x8000)
                < (bLo ^ (short)0x8000)) ? 1 : 0);
    }

    static short ult(U32 a, U32 b)
    {
        return uLessThan(
            a.hi, a.lo,
            b.hi, b.lo);
    }

    static short msb(U32 a)
    {
        return (short)((a.hi >>> 15) & 1);
    }

    static void clearMsb(U32 a)
    {
        a.hi = (short)(a.hi & 0x7FFF);
    }

    static void select(
        U32 x,
        U32 y,
        short mask,
        U32 out)
    {
        out.hi =
            (short)(x.hi
            ^ (mask & (x.hi ^ y.hi)));

        out.lo =
            (short)(x.lo
            ^ (mask & (x.lo ^ y.lo)));
    }

    static void mul16(short a, short b, U32 out)
    {
        short al = (short)(a & 0x00FF);
        // short ah = (short)(a >>> 8);
        short ah = (short)((a >>> 8) & 0x00FF);

        short bl = (short)(b & 0x00FF);
        // short bh = (short)(b >>> 8);
        short bh = (short)((a >>> 8) & 0x00FF);

        short p0 = (short)(al * bl);
        short p1 = (short)(al * bh);
        short p2 = (short)(ah * bl);
        short p3 = (short)(ah * bh);

        short m0 = (short)((p0 >>> 8)
                + (p1 & 0x00FF)
                + (p2 & 0x00FF));

        out.lo = (short)(
                (p0 & 0x00FF)
                | (m0 << 8));

        out.hi = (short)(
                p3
                + (p1 >>> 8)
                + (p2 >>> 8)
                + (m0 >>> 8));
    }

    static void mul32x32(
    short aHi, short aLo,
    short bHi, short bLo,
    U64 out)
    {
        U32 p00 = new U32();
        U32 p01 = new U32();
        U32 p10 = new U32();
        U32 p11 = new U32();

        U32.mul16(aLo, bLo, p00);
        U32.mul16(aLo, bHi, p01);
        U32.mul16(aHi, bLo, p10);
        U32.mul16(aHi, bHi, p11);

        /*
        * Result words:
        *
        * w0 = p00.lo
        * w1 = p00.hi + p01.lo + p10.lo
        * w2 = p01.hi + p10.hi + p11.lo + carry1
        * w3 = p11.hi + carry2
        */

        out.w0 = p00.lo;

        short s1a = (short)(p00.hi + p01.lo);
        short c1a = (short)((s1a < p00.hi) ? 1 : 0);

        short s1 = (short)(s1a + p10.lo);
        short c1b = (short)((s1 < s1a) ? 1 : 0);

        out.w1 = s1;

        short carry1 = (short)(c1a + c1b);

        short s2a = (short)(p01.hi + p10.hi);
        short c2a = (short)((s2a < p01.hi) ? 1 : 0);

        short s2b = (short)(s2a + p11.lo);
        short c2b = (short)((s2b < s2a) ? 1 : 0);

        short s2 = (short)(s2b + carry1);
        short c2c = (short)((s2 < s2b) ? 1 : 0);

        out.w2 = s2;

        short carry2 = (short)(c2a + c2b + c2c);

        out.w3 = (short)(p11.hi + carry2);
    }

    // static boolean ult(short a, short b)
    // {
    //     return (short)(a ^ (short)0x8000)
    //         < (short)(b ^ (short)0x8000);
    // }
}