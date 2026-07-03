package SHAKE;

/**
 * Keccak-f[1600] permute with debug prints (hi/lo int scratch-based).
 * Prints limited lane snapshots for the first two rounds (first 5 lanes).
 *
 * Replace your KeccakF1600 temporarily with this file for debugging.
 * Remove the debug prints once you find & fix the issue.
 */
public final class KeccakF1600Debug
{
    private static final int[] RHO_OFFSETS = new int[] {
         0, 36,  3, 41, 18,
         1, 44, 10, 45,  2,
        62,  6, 43, 15, 61,
        28, 55, 25, 21,  8,
        27, 20, 39, 14, 32
    };

    private static final int[] RC_HI = new int[] {
        0x00000000, 0x00000000, 0x80000000, 0x80000000,
        0x00000000, 0x00000000, 0x80000000, 0x80000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x80000000, 0x80000000, 0x80000000,
        0x80000000, 0x80000000, 0x00000000, 0x80000000,
        0x80000000, 0x80000000, 0x00000000, 0x80000000
    };

    private static final int[] RC_LO = new int[] {
        0x00000001, 0x00008082, 0x0000808A, 0x80008000,
        0x0000808B, 0x80000001, 0x80008081, 0x00008009,
        0x0000008A, 0x00000088, 0x80008009, 0x8000000A,
        0x8000808B, 0x0000008B, 0x00008089, 0x00008003,
        0x00008002, 0x00000080, 0x0000800A, 0x8000000A,
        0x80008081, 0x00008080, 0x80000001, 0x80008008
    };

    // Debug helper: print up to maxLanes lanes from scratch as 64-bit hex
    private static void printLanesHiLoLimited(int[] scratch, int base_hi, int base_lo, String tag, int maxLanes) {
        System.out.println(tag);
        int m = Math.min(maxLanes, 25);
        for (int i = 0; i < m; i++) {
            long hi = ((long)scratch[base_hi + i]) & 0xFFFFFFFFL;
            long lo = ((long)scratch[base_lo + i]) & 0xFFFFFFFFL;
            long v = (hi << 32) | lo;
            System.out.printf("lane[%2d] = 0x%016X (hi=0x%08X lo=0x%08X)%n", i, v, scratch[base_hi + i], scratch[base_lo + i]);
        }
        System.out.println();
    }

    // Legacy convenience - for desktop when scratch not provided (keeps old API)
    public static void permute(byte[] state) {
        int[] scratch = new int[120];
        permute(state, scratch);
    }

    // Scratch-based permute with debug prints
    public static void permute(byte[] state, int[] scratch)
    {
        if (state == null || state.length != 200) throw new IllegalArgumentException("state must be 200 bytes");
        if (scratch == null || scratch.length < 120) throw new IllegalArgumentException("scratch must be int[120] or larger");

        final int base_hi   = 0;   // scratch[0..24]
        final int base_lo   = 25;  // scratch[25..49]
        final int base_C_hi = 50;  // scratch[50..54]
        final int base_C_lo = 55;  // scratch[55..59]
        final int base_D_hi = 60;  // scratch[60..64]
        final int base_D_lo = 65;  // scratch[65..69]
        final int base_B_hi = 70;  // scratch[70..94]
        final int base_B_lo = 95;  // scratch[95..119]

        // Convert bytes -> hi/lo in scratch (little-endian lanes)
        for (int i = 0; i < 25; i++)
        {
            int off = i * 8;
            int low = (state[off] & 0xFF) | ((state[off + 1] & 0xFF) << 8)
                    | ((state[off + 2] & 0xFF) << 16) | ((state[off + 3] & 0xFF) << 24);
            int high = (state[off + 4] & 0xFF) | ((state[off + 5] & 0xFF) << 8)
                     | ((state[off + 6] & 0xFF) << 16) | ((state[off + 7] & 0xFF) << 24);
            scratch[base_lo + i] = low;
            scratch[base_hi + i] = high;
        }

        // 24 rounds
        for (int round = 0; round < 24; round++)
        {
            // Theta: C[x] = A[x,0]^...^A[x,4]
            for (int x = 0; x < 5; x++)
            {
                int c_hi = scratch[base_hi + x] ^ scratch[base_hi + x + 5] ^ scratch[base_hi + x + 10]
                         ^ scratch[base_hi + x + 15] ^ scratch[base_hi + x + 20];
                int c_lo = scratch[base_lo + x] ^ scratch[base_lo + x + 5] ^ scratch[base_lo + x + 10]
                         ^ scratch[base_lo + x + 15] ^ scratch[base_lo + x + 20];
                scratch[base_C_hi + x] = c_hi;
                scratch[base_C_lo + x] = c_lo;
            }

            // D[x] = C[x-1] ^ ROTL64(C[x+1],1)
            for (int x = 0; x < 5; x++)
            {
                int next = (x + 1) % 5;
                int cnext_hi = scratch[base_C_hi + next];
                int cnext_lo = scratch[base_C_lo + next];

                // ROTL64 by 1 on (hi, lo)
                int rot_lo = (cnext_lo << 1) | (cnext_hi >>> 31);
                int rot_hi = (cnext_hi << 1) | (cnext_lo >>> 31);

                scratch[base_D_hi + x] = scratch[base_C_hi + ((x + 4) % 5)] ^ rot_hi;
                scratch[base_D_lo + x] = scratch[base_C_lo + ((x + 4) % 5)] ^ rot_lo;
            }

            // A[x,y] ^= D[x]
            for (int x = 0; x < 5; x++)
            {
                for (int y = 0; y < 5; y++)
                {
                    int idx = x + 5 * y;
                    scratch[base_hi + idx] ^= scratch[base_D_hi + x];
                    scratch[base_lo + idx] ^= scratch[base_D_lo + x];
                }
            }

            // Debug: print Theta result (A) for first two rounds
            if (round < 2) printLanesHiLoLimited(scratch, base_hi, base_lo, "HiLo: After Theta round " + round, 5);

            // Rho & Pi -> B
            for (int x = 0; x < 5; x++)
            {
                for (int y = 0; y < 5; y++)
                {
                    int idx = x + 5 * y;
                    int offset = RHO_OFFSETS[idx] & 0xFF;
                    int a_hi = scratch[base_hi + idx];
                    int a_lo = scratch[base_lo + idx];
                    int newHi, newLo;

                    if (offset == 0)
                    {
                        newHi = a_hi;
                        newLo = a_lo;
                    }
                    else if (offset < 32)
                    {
                        // rotate left by offset (1..31)
                        newLo = (a_lo << offset) | (a_hi >>> (32 - offset));
                        newHi = (a_hi << offset) | (a_lo >>> (32 - offset));
                    }
                    else if (offset == 32)
                    {
                        // rotate-left by 32 swaps hi and lo
                        newLo = a_hi;
                        newHi = a_lo;
                    }
                    else
                    {
                        int k = offset - 32;
                        newLo = (a_hi << k) | (a_lo >>> (32 - k));
                        newHi = (a_lo << k) | (a_hi >>> (32 - k));
                    }

                    int newX = (2 * x + 3 * y) % 5;
                    int dst = newX + 5 * y;
                    scratch[base_B_hi + dst] = newHi;
                    scratch[base_B_lo + dst] = newLo;
                }
            }

            // Debug: print B (Rho+Pi result) for first two rounds
            if (round < 2) printLanesHiLoLimited(scratch, base_B_hi, base_B_lo, "HiLo: After Rho+Pi (B) round " + round, 5);

            // Chi (B into A)
            for (int y = 0; y < 5; y++)
            {
                for (int x = 0; x < 5; x++)
                {
                    int idx = x + 5 * y;
                    int idx1 = ((x + 1) % 5) + 5 * y;
                    int idx2 = ((x + 2) % 5) + 5 * y;

                    int b_hi = scratch[base_B_hi + idx];
                    int b_lo = scratch[base_B_lo + idx];
                    int b1_hi = scratch[base_B_hi + idx1];
                    int b1_lo = scratch[base_B_lo + idx1];
                    int b2_hi = scratch[base_B_hi + idx2];
                    int b2_lo = scratch[base_B_lo + idx2];

                    int not_b1_hi = ~b1_hi;
                    int not_b1_lo = ~b1_lo;

                    scratch[base_hi + idx] = b_hi ^ (not_b1_hi & b2_hi);
                    scratch[base_lo + idx] = b_lo ^ (not_b1_lo & b2_lo);
                }
            }

            // Debug: print A after Chi for first two rounds
            if (round < 2) printLanesHiLoLimited(scratch, base_hi, base_lo, "HiLo: After Chi round " + round, 5);

            // Iota: XOR round constant
            scratch[base_hi + 0] ^= RC_HI[round];
            scratch[base_lo + 0] ^= RC_LO[round];

            // Debug: print A after Iota for first two rounds
            if (round < 2) printLanesHiLoLimited(scratch, base_hi, base_lo, "HiLo: After Iota round " + round, 5);
        }

        // write back hi/lo -> state bytes (little-endian)
        for (int i = 0; i < 25; i++)
        {
            int off = i * 8;
            int l = scratch[base_lo + i];
            int h = scratch[base_hi + i];
            state[off]     = (byte)(l & 0xFF);
            state[off + 1] = (byte)((l >>> 8) & 0xFF);
            state[off + 2] = (byte)((l >>> 16) & 0xFF);
            state[off + 3] = (byte)((l >>> 24) & 0xFF);
            state[off + 4] = (byte)(h & 0xFF);
            state[off + 5] = (byte)((h >>> 8) & 0xFF);
            state[off + 6] = (byte)((h >>> 16) & 0xFF);
            state[off + 7] = (byte)((h >>> 24) & 0xFF);
        }
    }
}