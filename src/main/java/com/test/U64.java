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

    static void fromMulResult(
        U64 x,
        short[] mul,
        short off)
    {
        x.w3 = mul[1];
        x.w2 = mul[0];
        x.w1 = mul[3];
        x.w0 = mul[2];
    }

    static short addCarry(short a, short b)
    {
        short r = (short)(a + b);

        return (short)(((r ^ a) & (r ^ b)) >>> 15);
    }
}