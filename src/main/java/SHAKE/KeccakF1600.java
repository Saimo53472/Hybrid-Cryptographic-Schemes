package SHAKE;

/**
 * Keccak-f[1600] permutation implemented using 32-bit int hi/lo pairs for each 64-bit lane.
 * This implementation converts a 200-byte little-endian state buffer into 25 (hi,lo) pairs,
 * runs the 24-round permutation, then writes the lanes back to the byte buffer.
 *
 * The code is intentionally written without using 'long' to mirror a Java Card friendly representation.
 */
public final class KeccakF1600
{
    // rho offsets
    private static final int[] RHO_OFFSETS = new int[] {
         0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14
    };

    // round constants (64-bit) - will split into hi/lo when applying
    private static final long[] RC = new long[] {
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
        0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
        0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
        0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L,
        0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
        0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    // perform Keccak-f[1600] permutation on the 200-byte state (little-endian lanes)
    public static void permute(byte[] state)
    {
        if (state.length != 200)
        {
            throw new IllegalArgumentException("state must be 200 bytes");
        }

        // Convert to hi/lo lane representation
        int[] hi = new int[25];
        int[] lo = new int[25];

        for (int i = 0; i < 25; i++)
        {
            int off = i * 8;
            // little endian: byte 0 is least-significant byte of lane
            int low = (state[off] & 0xFF) | ((state[off + 1] & 0xFF) << 8) | ((state[off + 2] & 0xFF) << 16) | ((state[off + 3] & 0xFF) << 24);
            int high = (state[off + 4] & 0xFF) | ((state[off + 5] & 0xFF) << 8) | ((state[off + 6] & 0xFF) << 16) | ((state[off + 7] & 0xFF) << 24);
            lo[i] = low;
            hi[i] = high;
        }

        // Working arrays
        int[] C_hi = new int[5];
        int[] C_lo = new int[5];
        int[] D_hi = new int[5];
        int[] D_lo = new int[5];
        int[] B_hi = new int[25];
        int[] B_lo = new int[25];

        for (int round = 0; round < 24; round++)
        {
            // Theta
            for (int x = 0; x < 5; x++)
            {
                int c_hi = hi[x] ^ hi[x + 5] ^ hi[x + 10] ^ hi[x + 15] ^ hi[x + 20];
                int c_lo = lo[x] ^ lo[x + 5] ^ lo[x + 10] ^ lo[x + 15] ^ lo[x + 20];
                C_hi[x] = c_hi;
                C_lo[x] = c_lo;
            }

            for (int x = 0; x < 5; x++)
            {
                int next = (x + 1) % 5;
                int rot_hi, rot_lo;
                // ROTL64(C[next], 1)
                int[] rot = rotl64(C_hi[next], C_lo[next], 1);
                rot_hi = rot[0];
                rot_lo = rot[1];
                D_hi[x] = C_hi[(x + 4) % 5] ^ rot_hi;
                D_lo[x] = C_lo[(x + 4) % 5] ^ rot_lo;
            }

            for (int x = 0; x < 5; x++)
            {
                for (int y = 0; y < 5; y++)
                {
                    int idx = x + 5 * y;
                    hi[idx] ^= D_hi[x];
                    lo[idx] ^= D_lo[x];
                }
            }

            // Rho and Pi (into B)
            for (int x = 0; x < 5; x++)
            {
                for (int y = 0; y < 5; y++)
                {
                    int idx = x + 5 * y;
                    int offset = RHO_OFFSETS[idx];
                    int[] r = rotl64(hi[idx], lo[idx], offset);
                    // B[y][(2*x+3*y)%5] = ROTL(A[x][y], r)
                    int newX = (0 + 2 * x + 3 * y) % 5; // target x in B when flattening B[newX + 5*y]
                    int dst = newX + 5 * y;
                    B_hi[dst] = r[0];
                    B_lo[dst] = r[1];
                }
            }

            // Chi (on B into A)
            for (int x = 0; x < 5; x++)
            {
                for (int y = 0; y < 5; y++)
                {
                    int idx = x + 5 * y;
                    int idx1 = ((x + 1) % 5) + 5 * y;
                    int idx2 = ((x + 2) % 5) + 5 * y;
                    int b_hi = B_hi[idx];
                    int b_lo = B_lo[idx];
                    int b1_hi = B_hi[idx1];
                    int b1_lo = B_lo[idx1];
                    int b2_hi = B_hi[idx2];
                    int b2_lo = B_lo[idx2];

                    // A[x,y] = B[x,y] ^ ((~B[x+1,y]) & B[x+2,y])
                    int not_b1_hi = ~b1_hi;
                    int not_b1_lo = ~b1_lo;
                    hi[idx] = b_hi ^ (not_b1_hi & b2_hi);
                    lo[idx] = b_lo ^ (not_b1_lo & b2_lo);
                }
            }

            // Iota
            long rc = RC[round];
            int rc_lo = (int)rc;
            int rc_hi = (int)(rc >>> 32);
            hi[0] ^= rc_hi;
            lo[0] ^= rc_lo;
        }

        // Write back to state bytes little-endian
        for (int i = 0; i < 25; i++)
        {
            int off = i * 8;
            int l = lo[i];
            int h = hi[i];
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

    // rotate left a 64-bit value represented as (hi, lo) by r (0 <= r < 64).
    // returns new {hi, lo}
    private static int[] rotl64(int hi, int lo, int r)
    {
        if (r == 0)
        {
            return new int[] { hi, lo };
        }
        if (r < 32)
        {
            int newLo = (lo << r) | (hi >>> (32 - r));
            int newHi = (hi << r) | (lo >>> (32 - r));
            return new int[] { newHi, newLo };
        }
        else
        {
            int k = r - 32;
            int newLo = (hi << k) | (lo >>> (32 - k));
            int newHi = (lo << k) | (hi >>> (32 - k));
            return new int[] { newHi, newLo };
        }
    }
}