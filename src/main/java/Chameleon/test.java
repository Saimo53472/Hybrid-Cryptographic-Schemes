package Chameleon;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

public class test {
    // Constants for sizes
    public static final int SIZE_64 = 64;
    public static final int SIZE_128 = 128;
    public static final int SIZE_256 = 256;
    public static final int SIZE_512 = 512;

    // Precomputed byte lengths
    private static final int BYTES_64 = SIZE_64 / 8;
    private static final int BYTES_128 = SIZE_128 / 8;

    private static void mul64(int a, int b, int[] out, int off) {
        int a0 = a & 0xFFFF;
        int a1 = a >>> 16;

        int b0 = b & 0xFFFF;
        int b1 = b >>> 16;

        int p00 = a0 * b0;
        int p01 = a0 * b1;
        int p10 = a1 * b0;
        int p11 = a1 * b1;

        int middle = (p00 >>> 16)
                + (p01 & 0xFFFF)
                + (p10 & 0xFFFF);

        int lo = (p00 & 0xFFFF)
                | ((middle & 0xFFFF) << 16);

        int hi = p11
                + (p01 >>> 16)
                + (p10 >>> 16)
                + (middle >>> 16);

        out[off] = hi;
        out[off + 1] = lo;
    }

    private static long mul64O(int a, int b) {
        // Convert to long to avoid sign extension issues, then multiply
        return (a & 0xFFFFFFFFL) * (b & 0xFFFFFFFFL);
    }

    // Encode 32-bit integer as little-endian bytes
    public static void enc32le(byte[] dst, int dstOffset, int x) {
        dst[dstOffset] = (byte) (x & 0xFF);
        dst[dstOffset + 1] = (byte) ((x >>> 8) & 0xFF);
        dst[dstOffset + 2] = (byte) ((x >>> 16) & 0xFF);
        dst[dstOffset + 3] = (byte) ((x >>> 24) & 0xFF);
    }

    private static int dec32le(byte[] src, int off) {
        return (src[off] & 0xFF)
                | ((src[off + 1] & 0xFF) << 8)
                | ((src[off + 2] & 0xFF) << 16)
                | ((src[off + 3] & 0xFF) << 24);
    }

    public static void bpXor64(byte[] d, int dOffset,
            byte[] a, int aOffset,
            byte[] b, int bOffset) {
        int lo = dec32le(a, aOffset)
                ^ dec32le(b, bOffset);

        int hi = dec32le(a, aOffset + 4)
                ^ dec32le(b, bOffset + 4);

        enc32le(d, dOffset, lo);
        enc32le(d, dOffset + 4, hi);
    }

    // Helper methods for long/byte conversion
    private static long bytesToLong(byte[] bytes, int offset)
    {
        long value = 0;
        for (int i = 0; i < 8; i++)
        {
            value |= ((long)(bytes[offset + i] & 0xFF)) << (i * 8);
        }
        return value;
    }

    private static void longToBytes(long value, byte[] bytes, int offset)
    {
        for (int i = 0; i < 8; i++)
        {
            bytes[offset + i] = (byte)((value >> (i * 8)) & 0xFF);
        }
    }

    // Fast XOR implementation using long operations
    public static void bpXor64O(byte[] d, int dOffset, byte[] a, int aOffset, byte[] b, int bOffset)
    {
        // Process 64 bits as a single long
        long aVal = bytesToLong(a, aOffset);
        long bVal = bytesToLong(b, bOffset);
        long result = aVal ^ bVal;
        longToBytes(result, d, dOffset);
    }

    public static void bpMul32(
            int x,
            int y,
            int[] out,
            int off) {
        int x0 = x & 0x11111111;
        int x1 = x & 0x22222222;
        int x2 = x & 0x44444444;
        int x3 = x & 0x88888888;

        int y0 = y & 0x11111111;
        int y1 = y & 0x22222222;
        int y2 = y & 0x44444444;
        int y3 = y & 0x88888888;

        int[] t = new int[2];

        int z0hi = 0;
        int z0lo = 0;

        mul64(x0, y0, t, 0);
        z0hi ^= t[0];
        z0lo ^= t[1];

        mul64(x1, y3, t, 0);
        z0hi ^= t[0];
        z0lo ^= t[1];

        mul64(x2, y2, t, 0);
        z0hi ^= t[0];
        z0lo ^= t[1];

        mul64(x3, y1, t, 0);
        z0hi ^= t[0];
        z0lo ^= t[1];

        int z1hi = 0;
        int z1lo = 0;

        mul64(x0, y1, t, 0);
        z1hi ^= t[0];
        z1lo ^= t[1];

        mul64(x1, y0, t, 0);
        z1hi ^= t[0];
        z1lo ^= t[1];

        mul64(x2, y3, t, 0);
        z1hi ^= t[0];
        z1lo ^= t[1];

        mul64(x3, y2, t, 0);
        z1hi ^= t[0];
        z1lo ^= t[1];

        int z2hi = 0;
        int z2lo = 0;

        mul64(x0, y2, t, 0);
        z2hi ^= t[0];
        z2lo ^= t[1];

        mul64(x1, y1, t, 0);
        z2hi ^= t[0];
        z2lo ^= t[1];

        mul64(x2, y0, t, 0);
        z2hi ^= t[0];
        z2lo ^= t[1];

        mul64(x3, y3, t, 0);
        z2hi ^= t[0];
        z2lo ^= t[1];

        int z3hi = 0;
        int z3lo = 0;

        mul64(x0, y3, t, 0);
        z3hi ^= t[0];
        z3lo ^= t[1];

        mul64(x1, y2, t, 0);
        z3hi ^= t[0];
        z3lo ^= t[1];

        mul64(x2, y1, t, 0);
        z3hi ^= t[0];
        z3lo ^= t[1];

        mul64(x3, y0, t, 0);
        z3hi ^= t[0];
        z3lo ^= t[1];

        z0hi &= 0x11111111;
        z0lo &= 0x11111111;

        z1hi &= 0x22222222;
        z1lo &= 0x22222222;

        z2hi &= 0x44444444;
        z2lo &= 0x44444444;

        z3hi &= 0x88888888;
        z3lo &= 0x88888888;

        out[off] = z0hi | z1hi | z2hi | z3hi;

        out[off + 1] = z0lo | z1lo | z2lo | z3lo;
    }

        /**
     * Optimized binary polynomial multiplication of two 32-bit values in GF(2)
     * Returns 64-bit product (carry-less multiplication)
     * <p>
     * This implements the same "classic technique" as the C code using
     * the 4-way decomposition with masks
     */
    public static long bpMul32O(int x, int y)
    {
        // Extract bits with specific masks to create "holes" for carries
        int x0 = x & 0x11111111;  // Every 4th bit, starting at bit 0
        int x1 = x & 0x22222222;  // Every 4th bit, starting at bit 1
        int x2 = x & 0x44444444;  // Every 4th bit, starting at bit 2
        int x3 = x & 0x88888888;  // Every 4th bit, starting at bit 3

        int y0 = y & 0x11111111;
        int y1 = y & 0x22222222;
        int y2 = y & 0x44444444;
        int y3 = y & 0x88888888;

        // Perform the 4x4 multiplication in GF(2) - equivalent to carry-less multiplication
        long z0 = mul64O(x0, y0) ^ mul64O(x1, y3) ^ mul64O(x2, y2) ^ mul64O(x3, y1);
        long z1 = mul64O(x0, y1) ^ mul64O(x1, y0) ^ mul64O(x2, y3) ^ mul64O(x3, y2);
        long z2 = mul64O(x0, y2) ^ mul64O(x1, y1) ^ mul64O(x2, y0) ^ mul64O(x3, y3);
        long z3 = mul64O(x0, y3) ^ mul64O(x1, y2) ^ mul64O(x2, y1) ^ mul64O(x3, y0);

        // Apply masks to isolate the bits in their proper positions
        z0 &= 0x1111111111111111L;
        z1 &= 0x2222222222222222L;
        z2 &= 0x4444444444444444L;
        z3 &= 0x8888888888888888L;

        // Combine all the partial results
        return z0 | z1 | z2 | z3;
    }

    public static void bpMuladd64(
            byte[] d, int dOffset,
            byte[] a, int aOffset,
            byte[] b, int bOffset,
            byte[] tmp, int tmpOffset) {
        int a0 = dec32le(a, aOffset);
        int a1 = dec32le(a, aOffset + 4);

        int b0 = dec32le(b, bOffset);
        int b1 = dec32le(b, bOffset + 4);

        int[] c = new int[6];

        bpMul32(a0, b0, c, 0);
        bpMul32(a1, b1, c, 2);
        bpMul32(a0 ^ a1, b0 ^ b1, c, 4);

        c[4] ^= c[0];
        c[5] ^= c[1];

        c[4] ^= c[2];
        c[5] ^= c[3];

        int d0lo = dec32le(d, dOffset);
        int d0hi = dec32le(d, dOffset + 4);

        int d1lo = dec32le(d, dOffset + 8);
        int d1hi = dec32le(d, dOffset + 12);

        d0hi ^= c[0] ^ c[5];
        d0lo ^= c[1];

        d1hi ^= c[2];
        d1lo ^= c[3] ^ c[4];

        enc32le(d, dOffset, d0lo);
        enc32le(d, dOffset + 4, d0hi);

        enc32le(d, dOffset + 8, d1lo);
        enc32le(d, dOffset + 12, d1hi);
    }

    /**
     * Encode 64-bit value as little-endian bytes
     * This is a direct translation of the C enc64le function
     */
    public static void enc64le(byte[] dst, int dstOffset, long x)
    {
        dst[dstOffset] = (byte)(x & 0xFF);
        dst[dstOffset + 1] = (byte)((x >>> 8) & 0xFF);
        dst[dstOffset + 2] = (byte)((x >>> 16) & 0xFF);
        dst[dstOffset + 3] = (byte)((x >>> 24) & 0xFF);
        dst[dstOffset + 4] = (byte)((x >>> 32) & 0xFF);
        dst[dstOffset + 5] = (byte)((x >>> 40) & 0xFF);
        dst[dstOffset + 6] = (byte)((x >>> 48) & 0xFF);
        dst[dstOffset + 7] = (byte)((x >>> 56) & 0xFF);
    }

    // Decode 64-bit little-endian bytes to long
    public static long dec64le(byte[] src, int srcOffset)
    {
        return ((long)(src[srcOffset] & 0xFF)) |
            ((long)(src[srcOffset + 1] & 0xFF) << 8) |
            ((long)(src[srcOffset + 2] & 0xFF) << 16) |
            ((long)(src[srcOffset + 3] & 0xFF) << 24) |
            ((long)(src[srcOffset + 4] & 0xFF) << 32) |
            ((long)(src[srcOffset + 5] & 0xFF) << 40) |
            ((long)(src[srcOffset + 6] & 0xFF) << 48) |
            ((long)(src[srcOffset + 7] & 0xFF) << 56);
    }

    /**
     * Binary polynomial multiplication and accumulation for 64-bit polynomials
     * d += a * b (polynomial multiplication in GF(2))
     * <p>
     * This is a direct translation of the C function that uses 32-bit halves
     * for efficient polynomial multiplication in GF(2)
     */
    public static void bpMuladd64O(byte[] d, int dOffset,
                                  byte[] a, int aOffset,
                                  byte[] b, int bOffset,
                                  byte[] tmp, int tmpOffset)
    {
        // tmp parameter is unused in this implementation, following the C code

        // Decode 32-bit halves from little-endian bytes
        int a0 = dec32le(a, aOffset);      // First 32 bits of a
        int a1 = dec32le(a, aOffset + 4);  // Second 32 bits of a
        int b0 = dec32le(b, bOffset);      // First 32 bits of b
        int b1 = dec32le(b, bOffset + 4);  // Second 32 bits of b

        // Compute the three 64-bit polynomial products using Karatsuba approach
        long c0 = bpMul32O(a0, b0);         // a0 * b0
        long c1 = bpMul32O(a1, b1);         // a1 * b1
        // (a0 + a1) * (b0 + b1) - c0 - c1 = a0*b1 + a1*b0
        long c2 = bpMul32O(a0 ^ a1, b0 ^ b1) ^ c0 ^ c1;

        // Combine results and accumulate into destination
        // Lower 64 bits: c0 ^ (c2 << 32)
        long lowerResult = dec64le(d, dOffset) ^ c0 ^ (c2 << 32);
        // Upper 64 bits: c1 ^ (c2 >>> 32)
        long upperResult = dec64le(d, dOffset + 8) ^ c1 ^ (c2 >>> 32);

        // Encode results back to little-endian bytes
        enc64le(d, dOffset, lowerResult);
        enc64le(d, dOffset + 8, upperResult);
    }


    private static void bpXor512(byte[] d, int dOffset, byte[] a, int aOffset, byte[] b, int bOffset) {
        for (int u = 0; u < 64; u++) {
            d[dOffset + u] = (byte) (a[aOffset + u] ^ b[bOffset + u]);
        }
    }

    public static void bpXor128(byte[] d, int dOffset, byte[] a, int aOffset, byte[] b, int bOffset) {
        // Process as two 64-bit chunks
        bpXor64(d, dOffset, a, aOffset, b, bOffset);
        bpXor64(d, dOffset + 8, a, aOffset + 8, b, bOffset + 8);
    }

    // Specialized implementations for better performance
    public static void bpMuladd128(byte[] d, int dOffset,
            byte[] a, int aOffset,
            byte[] b, int bOffset,
            byte[] tmp, int tmpOffset) {
        // Use optimized implementation for 128-bit polynomials
        int t1Offset = tmpOffset;
        int t2Offset = t1Offset + BYTES_128;

        // Karatsuba algorithm for 128-bit polynomials (split into 64-bit halves)
        bpXor64(tmp, t2Offset, a, aOffset, a, aOffset + BYTES_64); // a0 + a1
        bpXor64(tmp, t2Offset + BYTES_64, b, bOffset, b, bOffset + BYTES_64); // b0 + b1

        // t1 = (a0+a1)*(b0+b1) + d0 + d1
        bpXor128(tmp, t1Offset, d, dOffset, d, dOffset + BYTES_128);
        bpMuladd64(tmp, t1Offset, tmp, t2Offset, tmp, t2Offset + BYTES_64, tmp, t2Offset + BYTES_128);

        // d0 += a0*b0
        bpMuladd64(d, dOffset, a, aOffset, b, bOffset, tmp, t2Offset);

        // d1 += a1*b1
        bpMuladd64(d, dOffset + BYTES_128, a, aOffset + BYTES_64, b, bOffset + BYTES_64, tmp, t2Offset);

        // t1 = t1 + d0 + d1 = a0*b1 + a1*b0
        bpXor128(tmp, t1Offset, tmp, t1Offset, d, dOffset);
        bpXor128(tmp, t1Offset, tmp, t1Offset, d, dOffset + BYTES_128);

        // d += (x^64)*t1: d[8:24] ⊕= t1[0:16]
        bpXor128(d, dOffset + BYTES_64, d, dOffset + BYTES_64, tmp, t1Offset);
    }

    private static void bpXor256(byte[] d, int dOffset, byte[] a, int aOffset, byte[] b, int bOffset) {
        for (int u = 0; u < 32; u++) {
            d[dOffset + u] = (byte) (a[aOffset + u] ^ b[bOffset + u]);
        }
    }

    /**
     * Binary polynomial multiplication and accumulation for 256-bit polynomials
     * Uses Karatsuba algorithm with 128-bit halves
     */
    public static void bpMuladd256(byte[] d, int dOffset,
            byte[] a, int aOffset,
            byte[] b, int bOffset,
            byte[] tmp, int tmpOffset) {
        final int n = 256;
        final int hn = 128;
        final int byteLen = n / 8;
        final int halfByteLen = hn / 8;

        // Temporary buffers within the provided tmp array
        int t1Offset = tmpOffset;
        int t2Offset = t1Offset + byteLen;
        int t3Offset = t2Offset + byteLen;

        // t1 <- (a0 + a1)*(b0 + b1) + d0 + d1
        bpXor128(tmp, t2Offset, a, aOffset, a, aOffset + halfByteLen); // a0 + a1
        bpXor128(tmp, t2Offset + halfByteLen, b, bOffset, b, bOffset + halfByteLen); // b0 + b1
        bpXor256(tmp, t1Offset, d, dOffset, d, dOffset + byteLen); // d0 + d1
        bpMuladd128(tmp, t1Offset, tmp, t2Offset, tmp, t2Offset + halfByteLen, tmp, t3Offset);

        // d0 <- d0 + a0*b0
        bpMuladd128(d, dOffset, a, aOffset, b, bOffset, tmp, t3Offset);

        // d1 <- d1 + a1*b1
        bpMuladd128(d, dOffset + byteLen, a, aOffset + halfByteLen, b, bOffset + halfByteLen, tmp, t3Offset);

        // t1 <- t1 + d0 + d1 = a0*b1 + a1*b0
        bpXor256(tmp, t1Offset, tmp, t1Offset, d, dOffset);
        bpXor256(tmp, t1Offset, tmp, t1Offset, d, dOffset + byteLen);

        // d <- d + (x^{n/2})*t1: d[16:48] ⊕= t1[0:32]
        bpXor256(d, dOffset + halfByteLen, d, dOffset + halfByteLen, tmp, t1Offset);
    }

    // Generic XOR for any size
    private static void bpXor(int bitSize, byte[] d, int dOffset, byte[] a, int aOffset, byte[] b, int bOffset) {
        int byteSize = bitSize / 8;
        for (int u = 0; u < byteSize; u++) {
            d[dOffset + u] = (byte) (a[aOffset + u] ^ b[bOffset + u]);
        }
    }

    // Generic binary polynomial multiplication using Karatsuba algorithm
    private static void bpMulmod(int n, int hn, byte[] d, int dOffset,
            byte[] a, int aOffset, byte[] b, int bOffset,
            byte[] tmp, int tmpOffset) {
        int byteLen = n / 8;
        int halfByteLen = hn / 8;

        int t1Offset = tmpOffset;
        int t2Offset = t1Offset + byteLen;

        // t1 <- (a0 + a1)*(b0 + b1)
        bpXor(hn, d, dOffset, a, aOffset, a, aOffset + halfByteLen);
        bpXor(hn, d, dOffset + halfByteLen, b, bOffset, b, bOffset + halfByteLen);
        bpXor(n, tmp, t1Offset, d, dOffset, d, dOffset + halfByteLen);
        Arrays.fill(tmp, t1Offset, t1Offset + byteLen, (byte) 0);
        bpMuladd256(tmp, t1Offset, d, dOffset, d, dOffset + halfByteLen, tmp, t2Offset);

        // d <- a0*b0 + a1*b1
        Arrays.fill(d, dOffset, dOffset + byteLen, (byte) 0);
        bpMuladd256(d, dOffset, a, aOffset, b, bOffset, tmp, t2Offset);
        bpMuladd256(d, dOffset, a, aOffset + halfByteLen, b, bOffset + halfByteLen, tmp, t2Offset);

        // t1 <- t1 + d = a0*b1 + a1*b0
        bpXor(n, tmp, t1Offset, tmp, t1Offset, d, dOffset);

        // d <- d + rotate_{n/2}(t1)
        bpXor(hn, d, dOffset, d, dOffset, tmp, t1Offset + halfByteLen);
        bpXor(hn, d, dOffset + halfByteLen, d, dOffset + halfByteLen, tmp, t1Offset);
    }

    // Basis multiplication modulo 2
    public static void basisM2Mul(int logn, byte[] t0, int t0Offset, byte[] t1, int t1Offset,
            byte[] h0, int h0Offset, byte[] h1, int h1Offset,
            byte[] f2, int f2Offset, byte[] g2, int g2Offset,
            byte[] F2, int F2Offset, byte[] G2, int G2Offset,
            byte[] tmp, int tmpOffset) {

        int n = 1 << logn;
        int byteLen = n >> 3;

        int w1Offset = tmpOffset;
        int w2Offset = w1Offset + byteLen;

        bpMulmod(512, 256, t0, t0Offset, h0, h0Offset, f2, f2Offset, tmp, w2Offset); // still need to resolve
        bpMulmod(512, 256, tmp, w1Offset, h1, h1Offset, F2, F2Offset, tmp, w2Offset);
        bpXor512(t0, t0Offset, t0, t0Offset, tmp, w1Offset);
        bpMulmod(512, 256, t1, t1Offset, h0, h0Offset, g2, g2Offset, tmp, w2Offset);
        bpMulmod(512, 256, tmp, w1Offset, h1, h1Offset, G2, G2Offset, tmp, w2Offset);
        bpXor512(t1, t1Offset, t1, t1Offset, tmp, w1Offset);
    }
    
    public static void testMul64()
    {
        Random rnd = new Random(12345);

        int[] out = new int[2];

        for (int i = 0; i < 1_000_000; i++)
        {
            int a = rnd.nextInt();
            int b = rnd.nextInt();

            long expected = mul64O(a, b);

            mul64(a, b, out, 0);

            long actual =
                ((out[0] & 0xFFFFFFFFL) << 32)
                | (out[1] & 0xFFFFFFFFL);

            if (expected != actual)
            {
                System.out.println("Mismatch!");
                System.out.printf("a = %08X%n", a);
                System.out.printf("b = %08X%n", b);
                System.out.printf("expected = %016X%n", expected);
                System.out.printf("actual   = %016X%n", actual);
                return;
            }
        }

        System.out.println("All tests passed.");
    }

    static void testBpXor64()
    {
        Random rnd = new Random();

        for (int i = 0; i < 100000; i++)
        {
            byte[] a = new byte[8];
            byte[] b = new byte[8];

            rnd.nextBytes(a);
            rnd.nextBytes(b);

            byte[] d1 = new byte[8];
            byte[] d2 = new byte[8];

            bpXor64(d1, 0, a, 0, b, 0);
            bpXor64O(d2, 0, a, 0, b, 0);

            if (!Arrays.equals(d1, d2))
            {
                System.out.println("bpXor64 mismatch");
                System.out.println(Arrays.toString(a));
                System.out.println(Arrays.toString(b));
                return;
            }
        }

        System.out.println("bpXor64 OK");
    }

    static void testBpMul32()
    {
        Random rnd = new Random();

        int[] out = new int[2];

        for (int i = 0; i < 1000000; i++)
        {
            int x = rnd.nextInt();
            int y = rnd.nextInt();

            long expected = bpMul32O(x, y);

            bpMul32(x, y, out, 0);

            long actual =
                ((out[0] & 0xFFFFFFFFL) << 32)
                | (out[1] & 0xFFFFFFFFL);

            if (expected != actual)
            {
                System.out.println("bpMul32 mismatch");

                System.out.printf("x = %08X%n", x);
                System.out.printf("y = %08X%n", y);

                System.out.printf("expected = %016X%n", expected);
                System.out.printf("actual   = %016X%n", actual);

                return;
            }
        }

        System.out.println("bpMul32 OK");
    }

    static void testBpMuladd64()
    {
        Random rnd = new Random();

        for (int i = 0; i < 100000; i++)
        {
            byte[] d1 = new byte[16];
            byte[] d2 = new byte[16];

            byte[] a = new byte[8];
            byte[] b = new byte[8];

            rnd.nextBytes(d1);
            rnd.nextBytes(a);
            rnd.nextBytes(b);

            System.arraycopy(d1, 0, d2, 0, 16);

            byte[] tmp1 = new byte[128];
            byte[] tmp2 = new byte[128];

            bpMuladd64(
                d1, 0,
                a, 0,
                b, 0,
                tmp1, 0);

            bpMuladd64O(
                d2, 0,
                a, 0,
                b, 0,
                tmp2, 0);

            if (!Arrays.equals(d1, d2))
            {
                System.out.println("bpMuladd64 mismatch");

                System.out.println("a = " + Arrays.toString(a));
                System.out.println("b = " + Arrays.toString(b));

                return;
            }
        }

        System.out.println("bpMuladd64 OK");
    }

    public static void main(String[] args)
    {
        testMul64();
        testBpXor64();
        testBpMul32();
        testBpMuladd64();
    }
}