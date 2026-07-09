package Chameleon;

import SHAKE.SHAKE256JC;
import java.security.SecureRandom;
import java.util.Arrays;
import java.lang.reflect.Method;

public class test {
        /**
     * Hamming weight of a byte (number of 1 bits)
     */
    private static byte popcount8(byte x)
    {
        short v = (short)(x & 0xFF);

        v = (short)((v & 0x55) + ((v >>> 1) & 0x55));
        v = (short)((v & 0x33) + ((v >>> 2) & 0x33));
        v = (short)((v & 0x0F) + ((v >>> 4) & 0x0F));

        return (byte)v;
    }

    /**
     * Regenerate f and g polynomials from seed using SHAKE256
     */
    public void regen_fg(byte[] f, short fOff, byte[] g, short gOff, byte[] seed) {
        for (byte j = 0; j < 4; j++)
        {
            byte[] state = new byte[200];
            int[] scratch = new int[120];

            SHAKE256JC shake = new SHAKE256JC(state, scratch);
            shake.absorbXor(seed, (short)0, (short)24);

            byte[] singleByte = new byte[1];
            singleByte[0] = j;
            shake.absorbXor(singleByte, (short)0, (short)1);

            shake.finalizeSqueeze();

            for (short u = 0; u < 1024; u += 32)
            {
                byte[] qb = new byte[8];
                shake.squeezeBytes(qb, (short)0, (short)8);

                for (short i = 0; i < 8; i++)
                {
                    byte coeff = (byte)(popcount8(qb[i]) - 4);

                    if (u < 512)
                    {
                        f[(short)(fOff + u + (j << 3) + i)] = coeff;
                    }
                    else
                    {
                        g[(short)(gOff + (u - 512) + (j << 3) + i)] = coeff;
                    }
                }
            }
        }
    }

    public static void testRegenFg()
    {
        try
        {
            int logn = 9;
            int n = 1 << logn;

            byte[] seed = new byte[24];
            new SecureRandom().nextBytes(seed);

            // Your implementation
            byte[] myF = new byte[n];
            byte[] myG = new byte[n];

            test impl = new test();
            impl.regen_fg(myF, (short)0, myG, (short)0, seed);

            // BC implementation through reflection
            byte[] bcF = new byte[n];
            byte[] bcG = new byte[n];

            Class<?> hawkClass = Class.forName("org.bouncycastle.pqc.crypto.hawk.HawkEngine");

            Method regen =
                hawkClass.getDeclaredMethod(
                    "hawkRegenFg",
                    int.class,
                    byte[].class,
                    byte[].class,
                    byte[].class);

            regen.setAccessible(true);

            regen.invoke(
                null,
                logn,
                bcF,
                bcG,
                seed);

            boolean fMatch = Arrays.equals(myF, bcF);
            boolean gMatch = Arrays.equals(myG, bcG);

            System.out.println("f match = " + fMatch);
            System.out.println("g match = " + gMatch);

            if (!fMatch)
            {
                for (int i = 0; i < n; i++)
                {
                    if (myF[i] != bcF[i])
                    {
                        System.out.printf(
                            "f mismatch @ %d ours=%d bc=%d%n",
                            i, myF[i], bcF[i]);
                        break;
                    }
                }
            }

            if (!gMatch)
            {
                for (int i = 0; i < n; i++)
                {
                    if (myG[i] != bcG[i])
                    {
                        System.out.printf(
                            "g mismatch @ %d ours=%d bc=%d%n",
                            i, myG[i], bcG[i]);
                        break;
                    }
                }
            }
        }
        catch (ClassNotFoundException e)
        {
            System.out.println("BouncyCastle not found.");
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        // try
        // {
        //     Class<?> c =
        //         Class.forName("org.bouncycastle.pqc.crypto.hawk.HawkEngine");

        //     System.out.println("Loaded.");

        //     Method[] ms = c.getDeclaredMethods();

        //     for(Method m : ms)
        //     {
        //         System.out.println(m);
        //     }
        // }
        catch(Throwable t)
        {
            t.printStackTrace();
        }
    }

    public static void main(String[] args){
        testRegenFg();
    }
}
