package com.test;

final class U64 {

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

    static void set(U64 x,
        short w3, short w2,
        short w1, short w0)
    {
        x.w3 = w3;
        x.w2 = w2;
        x.w1 = w1;
        x.w0 = w0;
    }

    static void copy(U64 dst, U64 src)
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

    static short msb(U64 a) {
        return (short)((a.w3 >>> 15) & 1);
    }

    static void clearMsb(U64 a) {
        a.w3 = (short)(a.w3 & 0x7FFF);
    }

    static void select(
    U64 x,
    U64 y,
    short mask,
    U64 out)
    {
        out.w3 =
            (short)(x.w3
            ^ (mask & (x.w3 ^ y.w3)));

        out.w2 =
            (short)(x.w2
            ^ (mask & (x.w2 ^ y.w2)));

        out.w1 =
            (short)(x.w1
            ^ (mask & (x.w1 ^ y.w1)));

        out.w0 =
            (short)(x.w0
            ^ (mask & (x.w0 ^ y.w0)));
    }

    private static short uLessThan16(short a, short b)
    {
        return (short)(((a ^ (short)0x8000)
            < (b ^ (short)0x8000)) ? 1 : 0);
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

    private static short subBorrow16(
    short a,
    short b,
    short borrowIn,
    short[] result,
    short resultOffset)
    {
        short bb = (short)(b + borrowIn);

        short borrowOut =
            uLessThan16(a, bb);

        result[resultOffset] =
            (short)(a - bb);

        return borrowOut;
    }

    static short sub(
    U64 a,
    U64 b,
    U64 out)
    {
        short borrow;

        short bb;

        bb = b.w0;
        borrow = uLessThan16(a.w0, bb);
        out.w0 = (short)(a.w0 - bb);

        bb = (short)(b.w1 + borrow);
        borrow = uLessThan16(a.w1, bb);
        out.w1 = (short)(a.w1 - bb);

        bb = (short)(b.w2 + borrow);
        borrow = uLessThan16(a.w2, bb);
        out.w2 = (short)(a.w2 - bb);

        bb = (short)(b.w3 + borrow);
        borrow = uLessThan16(a.w3, bb);
        out.w3 = (short)(a.w3 - bb);

        return borrow;
    }
}