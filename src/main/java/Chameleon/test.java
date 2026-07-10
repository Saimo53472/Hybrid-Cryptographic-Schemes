package Chameleon;

import java.security.SecureRandom;
import java.util.Arrays;
import java.lang.reflect.Method;
import javacard.framework.Util;

public class test {
    static short tbmask(short x) {
        return (short)(x >> 15);
    }

    static int tbmaski(int x) {
        return x >> 15;
    }

    public static boolean encodeSig(int logn, byte[] sig, short sigOffset, short sigLen,byte[] salt, short saltOffset,
        short saltLen, short[] s1, short s1Offset) {
        short n = (short)(1 << logn);
        byte low = (byte)((logn == 10) ? 6 : 5);

        short bufOffset = sigOffset;
        short remainingLen = sigLen;

        short minSize = (short)(saltLen + (((short)(low + 2)) << (logn - 3)));

        if (remainingLen < minSize) {
            return false;
        }

        // 1. Copy salt
        Util.arrayCopyNonAtomic(salt, saltOffset, sig, bufOffset, saltLen);

        bufOffset += saltLen;
        remainingLen -= saltLen;

        // 2. Sign bits
        short u;
        short v;

        for (u = 0; u < n; u += 8) {

            byte x = 0;

            for (v = 0; v < 8; v++) {
                short coeff = s1[(short)(s1Offset + u + v)];
                byte signBit = (byte)((coeff >> 15) & 1);
                x |= (byte)(signBit << v);
            }

            sig[(short)(bufOffset + (u >> 3))] = x;
        }

        bufOffset += (short)(n >> 3);
        remainingLen -= (short)(n >> 3);

        // 3. Fixed-size low bits; reimplemented without long. - check if this is correct!!
        short lowMask = (short)((1 << low) - 1);

        int acc8 = 0;
        short accBits = 0;

        for (u = 0; u < n; u++) {

            short w = s1[(short)(s1Offset + u)];
            short mask = tbmask(w);

            w ^= mask;                 // abs(w)

            acc8 |= (w & lowMask) << accBits;
            accBits += low;

            while (accBits >= 8) {

                if (remainingLen <= 0) {
                    return false;
                }

                sig[bufOffset++] = (byte)(acc8 & 0xFF);

                acc8 >>>= 8;
                accBits -= 8;
                remainingLen--;
            }
        }
        // 4. Variable-size unary encoding
        int acc = 0;
        short accLen = 0;

        for (u = 0; u < n; u++) {

            short w = s1[(short)(s1Offset + u)];
            short mask = tbmask(w);

            w ^= mask;

            short k = (short)((w & 0xFFFF) >>> low);

            acc |= (1 << (accLen + k));
            accLen += (short)(1 + k);

            while (accLen >= 8) {

                if (remainingLen <= 0) {
                    return false;
                }

                sig[bufOffset++] = (byte)acc;
                remainingLen--;

                acc >>>= 8;
                accLen -= 8;
            }
        }

        /*
        * Flush remaining bits
        */
        if (accLen > 0) {

            if (remainingLen <= 0) {
                return false;
            }

            sig[bufOffset++] = (byte)acc;
            remainingLen--;
        }

        // 5. Zero padding
        Util.arrayFillNonAtomic(sig, bufOffset, remainingLen, (byte)0);

        return true;
    }

        /**
     * Encode the signature, with output length exactly sigLen bytes.
     * Padding is applied if necessary. Returned value is 1 on success, 0
     * on error; an error is reported if the signature does not fit in the
     * provided buffer.
     */
    public static boolean encodeSigReference(int logn, byte[] sig, int sigOffset, int sigLen,
                                    byte[] salt, int saltOffset, int saltLen,
                                    short[] s1, int s1Offset)
    {
        int n = 1 << logn;
        int low = (logn == 10) ? 6 : 5;
        int bufOffset = sigOffset;
        int remainingLen = sigLen;

        // Check minimal size, including at least n bits for the variable part
        int minSize = saltLen + ((low + 2) << (logn - 3));
        if (remainingLen < minSize)
        {
            return false;
        }

        // 1. Copy salt
        System.arraycopy(salt, saltOffset, sig, bufOffset, saltLen);
        bufOffset += saltLen;
        remainingLen -= saltLen;

        // 2. Sign bits (1 bit per coefficient)
        for (int u = 0; u < n; u += 8)
        {
            int x = 0;
            for (int v = 0; v < 8; v++)
            {
                int signBit = (s1[s1Offset + u + v] >> 15) & 1;
                x |= signBit << v;
            }
            sig[bufOffset + (u >> 3)] = (byte)x;
        }
        bufOffset += (n >> 3);
        remainingLen -= (n >> 3);

        // 3. Fixed-size parts (low bits of absolute values)
        int lowMask = (1 << low) - 1;
        for (int u = 0; u < n; u += 8)
        {
            long x = 0;
            for (int v = 0, shift = 0; v < 8; v++, shift += low)
            {
                int w = s1[s1Offset + u + v];
                int mask = tbmaski(w);
                w ^= mask; // Absolute value
                x |= (long)(w & lowMask) << shift;
            }

            // Write bytes (little-endian)
            for (int i = 0; i < low; i++)
            {
                if (remainingLen <= 0)
                {
                    return false;
                }
                sig[bufOffset++] = (byte)(x & 0xFF);
                x >>>= 8;
            }
        }
        remainingLen -= low << (logn - 3);

        // 4. Variable-size parts (remaining bits using unary-like encoding)
        int acc = 0;
        int accLen = 0;

        for (int u = 0; u < n; u++)
        {
            int w = s1[s1Offset + u];
            int mask = tbmaski(w);
            w ^= mask; // Absolute value
            int k = w >>> low; // Remaining bits after low bits

            // Unary encoding: k zeros followed by a one
            acc |= 1 << (accLen + k);
            accLen += 1 + k;

            // Flush complete bytes
            while (accLen >= 8)
            {
                if (remainingLen <= 0)
                {
                    return false;
                }
                sig[bufOffset++] = (byte)(acc & 0xFF);
                remainingLen--;
                acc >>>= 8;
                accLen -= 8;
            }
        }

        // Flush remaining bits
        if (accLen > 0)
        {
            if (remainingLen <= 0)
            {
                return false;
            }
            sig[bufOffset++] = (byte)(acc & 0xFF);
            remainingLen--;
        }

        // 5. Padding with zeros
        for (int i = 0; i < remainingLen; i++)
        {
            sig[bufOffset + i] = 0;
        }

        return true;
    }    

    public static void testEncodeSig() {
        SecureRandom rnd = new SecureRandom();

        for (int t = 0; t < 10000; t++) {

            int logn = rnd.nextBoolean() ? 9 : 10;
            int n = 1 << logn;

            byte[] salt = new byte[40];
            rnd.nextBytes(salt);

            short[] s1 = new short[n];

            for (int i = 0; i < n; i++) {
                s1[i] = (short)(rnd.nextInt(2048) - 1024);
            }

            byte[] sigRef = new byte[4096];
            byte[] sigJC  = new byte[4096];

            boolean r1 = encodeSigReference(
                logn,
                sigRef, (short)0, (short)sigRef.length,
                salt, (short)0, (short)salt.length,
                s1, (short)0
            );

            boolean r2 = encodeSig(
                logn,
                sigJC, (short)0, (short)sigJC.length,
                salt, (short)0, (short)salt.length,
                s1, (short)0
            );

            if (r1 != r2) {
                throw new RuntimeException("Return mismatch");
            }

            if (!Arrays.equals(sigRef, sigJC)) {

                System.out.println("FAILED at test " + t);

                for (int i = 0; i < sigRef.length; i++) {

                    if (sigRef[i] != sigJC[i]) {

                        System.out.printf(
                            "Mismatch at %d: ref=%02X jc=%02X%n",
                            i,
                            sigRef[i] & 0xFF,
                            sigJC[i] & 0xFF
                        );

                        break;
                    }
                }

                return;
            }
        }

        System.out.println("All tests passed");
    }

    public static void main(String[] args){
        testEncodeSig();
    }
}
