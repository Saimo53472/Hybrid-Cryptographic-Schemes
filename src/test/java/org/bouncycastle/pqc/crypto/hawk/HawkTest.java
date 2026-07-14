package org.bouncycastle.pqc.crypto.hawk;

import java.util.Arrays;

public class HawkTest
{
    public static void main(String[] args)
    {
        int logn = 9;
        int n = 1 << logn;

        byte[] seed = new byte[24];
        for (int i = 0; i < seed.length; i++)
        {
            seed[i] = (byte)i;
        }

        byte[] f = new byte[n];
        byte[] g = new byte[n];

        HawkEngine.Hawk_regen_fg(logn, f, 0, g, 0, seed);

        System.out.println("f[0..15] = "
            + Arrays.toString(Arrays.copyOf(f, 16)));

        System.out.println("g[0..15] = "
            + Arrays.toString(Arrays.copyOf(g, 16)));
    }
}