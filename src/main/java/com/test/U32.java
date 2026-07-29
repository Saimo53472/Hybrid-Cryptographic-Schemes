package com.test;

public final class U32 {
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
        short al = (short)(a & 0xFF);
        short ah = (short) ((short)(a >>> 8) & 0xFF);

        short bl = (short)(b & 0xFF);
        short bh = (short) ((short)(b >>> 8) & 0xFF);

        int p0 = al * bl;
        int p1 = al * bh;
        int p2 = ah * bl;
        int p3 = ah * bh;

        int middle = (p0 >>> 8) + (p1 & 0xFF) + (p2 & 0xFF);

        out.lo = (short)(
            (p0 & 0xFF)
            | ((middle & 0xFF) << 8));

        out.hi = (short)(
            p3
            + (p1 >>> 8)
            + (p2 >>> 8)
            + (middle >>> 8));
    }

    public static void mul64(
    short aHi, short aLo,
    short bHi, short bLo,
    short[] out, short off)
    {
        U32 p00 = new U32();
        U32 p01 = new U32();
        U32 p10 = new U32();
        U32 p11 = new U32();

        mul16(aLo, bLo, p00);
        mul16(aLo, bHi, p01);
        mul16(aHi, bLo, p10);
        mul16(aHi, bHi, p11);

        short r0 = p00.lo;

        short t1 = (short)(p00.hi + p01.lo);
        short carry1 = uLessThan(
            (short)0, t1,
            (short)0, p00.hi);

        short old = t1;
        t1 = (short)(t1 + p10.lo);

        if (uLessThan((short)0, t1, (short)0, old) != 0) {
            carry1++;
        }

        short r1 = t1;

        short t2 = (short)(p01.hi + p10.hi);
        short carry2 = uLessThan(
            (short)0, t2,
            (short)0, p01.hi);

        old = t2;
        t2 = (short)(t2 + p11.lo);

        if (uLessThan((short)0, t2, (short)0, old) != 0) {
            carry2++;
        }

        old = t2;
        t2 = (short)(t2 + carry1);

        if (uLessThan((short)0, t2, (short)0, old) != 0) {
            carry2++;
        }

        short r2 = t2;

        short r3 = (short)(p11.hi + carry2);

        out[off]               = r0;
        out[(short)(off + 1)] = r1;
        out[(short)(off + 2)] = r2;
        out[(short)(off + 3)] = r3;
    }
}