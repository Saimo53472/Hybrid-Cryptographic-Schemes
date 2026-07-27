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
}