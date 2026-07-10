package Chameleon;

import java.security.SecureRandom;

public class test {

    static final long Q0I_LONG = 3955247103L;

    // Store only the lower 16 bits of Q0I
    static final int Q0I_LO = (int)(Q0I_LONG & 0xFFFF);
    static final int Q0I_HI = (int)((Q0I_LONG >>> 16) & 0xFFFF);
    private static final int Q = 18433;

    public static int mq18433MontyRed(int x)
    {
        int step1 = (int)((long)x * Q0I_LONG);
        int step2 = (step1 >>> 16) * Q;
        int result = (step2 >>> 16) + 1;
        int nonzero = -((x | -x) >>> 31);  // -1 if x != 0, 0 if x == 0
        return result & nonzero;
    }

    public static int mq18433MontyRedNew(int x)
    {
        int xLo = x & 0xFFFF;
        int xHi = x >>> 16;

        int pLL = xLo * 18431;
        int pLH = xLo * 60352;
        int pHL = xHi * 18431;

        int word16 = ((pLL >>> 16) + pLH + pHL) & 0xFFFF;

        int step2 = word16 * Q;
        int result = (step2 >>> 16) + 1;

        int nonzero = -((x | -x) >>> 31);
        return result & nonzero;
    }

    public static void main(String[] args) {

        SecureRandom rnd = new SecureRandom();

        for (int i = 0; i < 1000000; i++) {

            int x = rnd.nextInt();

            int a = mq18433MontyRed(x);
            int b = mq18433MontyRedNew(x);

            if (a != b) {
                System.out.println("Mismatch!");
                System.out.printf("x=%08X%n", x);
                System.out.printf("a=%08X%n", a);
                System.out.printf("b=%08X%n", b);
                return;
            }
        }

        System.out.println("All tests passed.");
    }
}