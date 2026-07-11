package Chameleon;

import java.security.SecureRandom;
import java.util.Random;
import java.util.Arrays;

import org.bouncycastle.crypto.digests.SHAKEDigest;

import SHAKE.SHAKE256JC;

public class test {

    // Hawk-512 (logn = 9, n = 512)
    public static final short[] SIG_GAUSS_HI_HAWK_512 = {
        (short)0x580B, (short)0x35F9,
        (short)0x1D34, (short)0x0DD7,
        (short)0x05B7, (short)0x020C,
        (short)0x00A2, (short)0x002B,
        (short)0x000A, (short)0x0001
    };

    public static final int SG_MAX_HI_HAWK_512 = SIG_GAUSS_HI_HAWK_512.length;

    public static final long[] SIG_GAUSS_LO_HAWK_512 = {
        0x0C27920A04F8F267L, 0x3C689D9213449DC9L,
        0x1C4FF17C204AA058L, 0x7B908C81FCE3524FL,
        0x5E63263BE0098FFDL, 0x4EBEFD8FF4F07378L,
        0x56AEDFB0876A3BD8L, 0x4628BC6B23887196L,
        0x061E21D588CC61CCL, 0x7F769211F07B326FL,
        0x2BA568D92EEC18E7L, 0x0668F461693DFF8FL,
        0x00CF0F8687D3B009L, 0x001670DB65964485L,
        0x000216A0C344EB45L, 0x00002AB6E11C2552L,
        0x000002EDF0B98A84L, 0x0000002C253C7E81L,
        0x000000023AF3B2E7L, 0x0000000018C14ABFL,
        0x0000000000EBCC6AL, 0x000000000007876EL,
        0x00000000000034CFL, 0x000000000000013DL,
        0x0000000000000006L, 0x0000000000000000L
    };

    public static final int[] SIG_GAUSS_LO_HI_HAWK_512 = {
        0x0C27920A, 0x3C689D92,
        0x1C4FF17C, 0x7B908C81,
        0x5E63263B, 0x4EBEFD8F,
        0x56AEDFB0, 0x4628BC6B,
        0x061E21D5, 0x7F769211,
        0x2BA568D9, 0x0668F461,
        0x00CF0F86, 0x001670DB,
        0x000216A0, 0x00002AB6,
        0x000002ED, 0x0000002C,
        0x00000002, 0x00000000,
        0x00000000, 0x00000000,
        0x00000000, 0x00000000,
        0x00000000, 0x00000000 
    };

    public static final int[] SIG_GAUSS_LO_LO_HAWK_512 = {
        0x04F8F267, 0x13449DC9,
        0x204AA058, 0xFCE3524F,
        0xE0098FFD, 0xF4F07378,
        0x876A3BD8, 0x23887196,
        0x88CC61CC, 0xF07B326F,
        0x2EEC18E7, 0x693DFF8F,
        0x87D3B009, 0x65964485,
        0xC344EB45, 0xE11C2552,
        0xF0B98A84, 0x253C7E81,
        0x3AF3B2E7, 0x18C14ABF,
        0x00EBCC6A, 0x0007876E,
        0x000034CF, 0x0000013D,
        0x00000006, 0x00000000
    };

    public static final int SG_MAX_LO_HAWK_512 = SIG_GAUSS_LO_HAWK_512.length;

    private static int dec32le(byte[] src, int off)
    {
        return (src[off] & 0xFF)
            | ((src[off + 1] & 0xFF) << 8)
            | ((src[off + 2] & 0xFF) << 16)
            | ((src[off + 3] & 0xFF) << 24);
    }

    private static int dec16le(byte[] src, int off)
    {
        return (src[off] & 0xFF)
            | ((src[off + 1] & 0xFF) << 8);
    }

    /*
    * Returns 1 iff a < b when interpreted as unsigned ints.
    */
    private static int uLessThan(int a, int b)
    {
        return ((a ^ 0x80000000) < (b ^ 0x80000000)) ? 1 : 0;
    }

    public int sigGaussJC(
        int logn,
        SHAKE256JC shake,
        byte[] shakeBuf40,
        byte[] seed41,
        byte[] x,
        int xOffset,
        byte[] t,
        int tOffset)
    {
        int[] tabLoHi;
        int[] tabLoLo;
        short[] tabHi;

        int hiLen;
        int loLen;

        tabHi = SIG_GAUSS_HI_HAWK_512;
        tabLoHi = SIG_GAUSS_LO_HI_HAWK_512;
        tabLoLo = SIG_GAUSS_LO_LO_HAWK_512;
        hiLen = SG_MAX_HI_HAWK_512;
        loLen = SG_MAX_LO_HAWK_512;

        int n = 1 << logn;
        int sn = 0;

        for (int j = 0; j < 4; j++)
        {
            seed41[40] = (byte)j;

            shake.reset();
            shake.absorbXor(seed41, 0, 41);
            shake.finalizeSqueeze();

            for (int u = 0; u < (n << 1); u += 16)
            {
                shake.squeezeBytes(shakeBuf40, 0, 40);

                for (int k = 0; k < 4; k++)
                {
                    int v = u + (j << 2) + k;

                    int loLo = dec32le(shakeBuf40, k * 8);
                    int loHi = dec32le(shakeBuf40, k * 8 + 4);

                    int hi = dec16le(shakeBuf40, 32 + (k << 1));

                    /*
                    * Sign bit.
                    */
                    int neg = -(loHi >>> 31);

                    loHi &= 0x7FFFFFFF;
                    hi &= 0x7FFF;

                    int pbit =
                        (t[tOffset + (v >>> 3)] >>> (v & 7)) & 1;

                    int pOddw = -pbit;

                    int r = 0;

                    /*
                    * First loop.
                    */
                    for (int i = 0; i < hiLen; i += 2)
                    {
                        int mask = pOddw;

                        int thi =
                            (tabHi[i] & 0xFFFF)
                            ^ (mask
                            & ((tabHi[i] & 0xFFFF)
                            ^ (tabHi[i + 1] & 0xFFFF)));

                        int tloHi =
                            tabLoHi[i]
                            ^ (mask
                            & (tabLoHi[i]
                            ^ tabLoHi[i + 1]));

                        int tloLo =
                            tabLoLo[i]
                            ^ (mask
                            & (tabLoLo[i]
                            ^ tabLoLo[i + 1]));

                        int borrow = uLessThan(loLo, tloLo);

                        int diffHi = loHi - tloHi - borrow;

                        int cc = diffHi >>> 31;

                        int diffHi16 = hi - thi - cc;

                        r += diffHi16 >>> 31;
                    }

                    /*
                    * Second loop.
                    */
                    int hinz = (hi - 1) >>> 31;

                    for (int i = hiLen; i < loLen; i += 2)
                    {
                        int mask = pOddw;

                        int tloHi =
                            tabLoHi[i]
                            ^ (mask
                            & (tabLoHi[i]
                            ^ tabLoHi[i + 1]));

                        int tloLo =
                            tabLoLo[i]
                            ^ (mask
                            & (tabLoLo[i]
                            ^ tabLoLo[i + 1]));

                        int borrow = uLessThan(loLo, tloLo);

                        int diffHi = loHi - tloHi - borrow;

                        int cc = diffHi >>> 31;

                        r += hinz & cc;
                    }

                    r = (r << 1) - pOddw;

                    r = (r ^ neg) - neg;

                    x[xOffset + v] = (byte)r;

                    sn += r * r;
                }
            }
        }

        return sn;
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
     * Generate x with the right Gaussian, for the specified parity bits.
     * x is formally generated with center t/2 and standard deviation sigma_sign
     * (with sigma_sign = 1.010, 1.278 or 1.299, depending on degree); this
     * function generates 2*x.
     * <p>
     * Returned value is the squared norm of x.
     */
    public int sigGauss(int logn, byte[] seed, SHAKEDigest scExtra, byte[] x, int xOffset, byte[] t, int tOffset)
    {
        // Select tables based on security level
        short[] tabHi;
        long[] tabLo;
        int hiLen, loLen;

            tabHi = SIG_GAUSS_HI_HAWK_512;
            tabLo = SIG_GAUSS_LO_HAWK_512;
            hiLen = SG_MAX_HI_HAWK_512;
            loLen = SG_MAX_LO_HAWK_512;

        int n = 1 << logn;
        // byte[] seed = new byte[41];
        // byte[] tmp = new byte[40];
        // // Get 40 random bytes from RNG
        // random.nextBytes(tmp);
        // System.arraycopy(tmp, 0, seed, 0, tmp.length);

        int sn = 0; // squared norm

        for (int j = 0; j < 4; j++)
        {
            SHAKEDigest sc;
            if (scExtra != null)
            {
                sc = new SHAKEDigest(scExtra);
            }
            else
            {
                sc = new SHAKEDigest(256);
            }

            // Set instance identifier and inject seed
            seed[40] = (byte)j;
            sc.update(seed, 0, 41);

            // For SHAKEDigest, we don't need explicit flip - just start reading
            byte[] buffer = new byte[40];

            for (int u = 0; u < (n << 1); u += 16)
            {
                // Extract 40 bytes from SHAKE
                sc.doOutput(buffer, 0, 40);

                for (int k = 0; k < 4; k++)
                {
                    int v = u + (j << 2) + k;
                    long lo = dec64le(buffer, k * 8);
                    int hi = dec16le(buffer, 32 + k * 2);

                    // Extract sign bit
                    int neg = (int)(-(lo >>> 63));
                    lo &= 0x7FFFFFFFFFFFFFFFL;
                    hi &= 0x7FFF;

                    // Get parity bit from t
                    int tByteIndex = tOffset + (v >>> 3);
                    int tBitIndex = v & 7;
                    int pbit = (t[tByteIndex] >>> tBitIndex) & 1;
                    long pOdd = -pbit;
                    int pOddw = (int)pOdd;

                    int r = 0;

                    // Process high table
                    for (int i = 0; i < hiLen; i += 2)
                    {
                        long tlo0 = tabLo[i];
                        long tlo1 = tabLo[i + 1];
                        long tlo = tlo0 ^ (pOdd & (tlo0 ^ tlo1));

                        int thi0 = tabHi[i] & 0xFFFF;
                        int thi1 = tabHi[i + 1] & 0xFFFF;
                        int thi = thi0 ^ (pOddw & (thi0 ^ thi1));

                        // Calculate carry and update r
                        long diff = lo - tlo;
                        int cc = (int)(diff >>> 63); // Carry from low comparison
                        int diffHi = hi - thi - cc;
                        r += (diffHi >>> 31); // Add 1 if hi < (thi + cc)
                    }

                    // Process low table for remaining entries
                    int hinz = (hi - 1) >>> 31; // 0 if hi == 0, -1 if hi > 0
                    for (int i = hiLen; i < loLen; i += 2)
                    {
                        long tlo0 = tabLo[i];
                        long tlo1 = tabLo[i + 1];
                        long tlo = tlo0 ^ (pOdd & (tlo0 ^ tlo1));

                        long diff = lo - tlo;
                        int cc = (int)(diff >>> 63);
                        r += hinz & cc; // Only add if hi > 0
                    }

                    // Multiply by 2 and apply parity
                    r = (r << 1) - pOddw;

                    // Apply sign bit
                    r = (r ^ neg) - neg;
                    // Store as signed byte
                    x[xOffset + v] = (byte)r;
                    sn += r * r;
                }
            }
        }

        return sn;
    }

    public static void main(String[] args)
    {
        System.out.println("\n==== TEST 6: FULL SAMPLER ====");

        test T = new test();

        byte[] seed = new byte[41];
        byte[] parity = new byte[128];

        SecureRandom sr = new SecureRandom();

        for (int run = 0; run < 1000; run++)
        {
            sr.nextBytes(seed);
            sr.nextBytes(parity);

            byte[] x1 = new byte[1024];
            byte[] x2 = new byte[1024];

            int sn1 =
                T.sigGauss(
                    9,
                    seed.clone(),
                    null,
                    x1,
                    0,
                    parity,
                    0);


            byte[] state = new byte[200];
            int[] scratch = new int[120];
            SHAKE256JC shakeJC =
                new SHAKE256JC(state, scratch);

            byte[] shakeBuf40 =
                new byte[40];

            int sn2 =
                T.sigGaussJC(
                    9,
                    shakeJC,
                    shakeBuf40,
                    seed.clone(),
                    x2,
                    0,
                    parity,
                    0);

            if (!Arrays.equals(x1, x2))
            {
                System.out.println(
                    "Vector mismatch on run " + run);
                return;
            }

            if (sn1 != sn2)
            {
                System.out.println(
                    "Norm mismatch on run " + run);
                return;
            }
        }

        System.out.println("FULL SAMPLER PASS");


        System.out.println(
            "\nAll low-level tests passed.");
    }
}