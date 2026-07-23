package SHAKE;

/**
 * Allocation-free Keccak-f[1600] permutation using 32-bit hi/lo lane pairs.
 */
public final class KeccakF1600
{
    private static final int[] RHO_OFFSETS = new int[] {
         0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14
    };

    // Round constants split into hi / lo 32-bit parts.
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

    public static void permute(byte[] state)
    {
        int[] scratch = new int[120];
        permute(state, scratch);
    }

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

        // bytes -> hi/lo ints (little-endian lane encoding)
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
            // Theta: C[x] = xor of column lanes
            for (int x = 0; x < 5; x++)
            {
                int c_hi = scratch[base_hi + x] ^ scratch[base_hi + x + 5] ^ scratch[base_hi + x + 10]
                         ^ scratch[base_hi + x + 15] ^ scratch[base_hi + x + 20];
                int c_lo = scratch[base_lo + x] ^ scratch[base_lo + x + 5] ^ scratch[base_lo + x + 10]
                         ^ scratch[base_lo + x + 15] ^ scratch[base_lo + x + 20];
                scratch[base_C_hi + x] = c_hi;
                scratch[base_C_lo + x] = c_lo;
            }

            // D[x] = C[x-1] ^ ROTL64(C[x+1], 1)
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
                        newLo = (a_lo << offset) | (a_hi >>> (32 - offset));
                        newHi = (a_hi << offset) | (a_lo >>> (32 - offset));
                    }
                    else
                    {
                        int k = offset - 32;
                        newLo = (a_hi << k) | (a_lo >>> (32 - k));
                        newHi = (a_lo << k) | (a_hi >>> (32 - k));
                    }

                    // int newX = (2 * x + 3 * y) % 5;
                    // int dst = newX + 5 * y;

                    int newX = y;
                    int newY = (2 * x + 3 * y) % 5;
                    int dst = newX + 5 * newY;

                    scratch[base_B_hi + dst] = newHi;
                    scratch[base_B_lo + dst] = newLo;
                }
            }

            // Chi: A[x,y] = B[x,y] ^ ((~B[x+1,y]) & B[x+2,y])
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

            // Iota: XOR round constant
            scratch[base_hi + 0] ^= RC_HI[round];
            scratch[base_lo + 0] ^= RC_LO[round];
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