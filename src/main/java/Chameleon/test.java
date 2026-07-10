package Chameleon;

import java.security.SecureRandom;

public class test {

    static final long Q0I_LONG = 3955247103L;

    // Store only the lower 16 bits of Q0I
    private static final int Q0I_SHORT = 0x8F3F;  // Lower 16 bits of 3955247103
    private static final int Q = 18433;

    public static int mq18433MontyRed(int x)
    {
        int step1 = (int)((long)x * Q0I_LONG);
        int step2 = (step1 >>> 16) * Q;
        int result = (step2 >>> 16) + 1;
        int nonzero = -((x | -x) >>> 31);  // -1 if x != 0, 0 if x == 0
        return result & nonzero;
    }

    /**
     * Montgomery reduction - Pure 32-bit version (Java Card compatible).
     * No long type needed - handles 16-bit chunks manually.
     */
    public static int mq18433MontyRedNew(int x)
    {
        // Q0I split into 16-bit halves
        // Q0I = 0xEBFB8F3F: high=0xEBFB, low=0x8F3F
        int Q0I_lo = 0x8F3F;
        int Q0I_hi = 0xEBFB;
        
        int x_lo = x & 0xFFFF;
        int x_hi = (x >>> 16) & 0xFFFF;
        
        // Four partial products (16-bit * 16-bit = 32-bit)
        int p_ll = x_lo * Q0I_lo;        // x_lo * Q0I_lo [0:32]
        int p_lh = x_lo * Q0I_hi;        // x_lo * Q0I_hi [16:48]
        int p_hl = x_hi * Q0I_lo;        // x_hi * Q0I_lo [16:48]
        int p_hh = x_hi * Q0I_hi;        // x_hi * Q0I_hi [32:64]
        
        // Sum the contributions with proper shifts
        // We need: (p_ll) + (p_lh << 16) + (p_hl << 16) + (p_hh << 32)
        // Extract lower 32 bits only (for step1)
        
        int carry_lo = p_ll >>> 16;      // Carry from lowest product
        int mid = (p_lh & 0xFFFF) + (p_hl & 0xFFFF) + carry_lo;
        int carry_mid = mid >>> 16;
        
        int step1 = ((carry_mid + (p_lh >>> 16) + (p_hl >>> 16)) << 16) | (mid & 0xFFFF) | (p_ll & 0xFFFF);
        
        // Continue with original algorithm
        int step2 = (step1 >>> 16) * Q;
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