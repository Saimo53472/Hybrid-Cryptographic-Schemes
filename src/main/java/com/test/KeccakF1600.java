package com.test;

import javacard.framework.ISOException;

/**
 * Allocation-free Keccak-f[1600] permutation using 32-bit hi/lo lane pairs.
 */
public final class KeccakF1600
{
    private static final byte[] RHO_OFFSETS = new byte[] {
         0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14
    };

    private static final short[] RC_W3 = {
        (short)0x0000, (short)0x0000, (short)0x8000, (short)0x8000,
        (short)0x0000, (short)0x0000, (short)0x8000, (short)0x8000,
        (short)0x0000, (short)0x0000, (short)0x0000, (short)0x0000,
        (short)0x0000, (short)0x8000, (short)0x8000, (short)0x8000,
        (short)0x8000, (short)0x8000, (short)0x0000, (short)0x8000,
        (short)0x8000, (short)0x8000, (short)0x0000, (short)0x8000
    };

    private static final short[] RC_W2 = {
        (short)0x0000, (short)0x0000, (short)0x0000, (short)0x0000,
        (short)0x0000, (short)0x0000, (short)0x0000, (short)0x0000,
        (short)0x0000, (short)0x0000, (short)0x0000, (short)0x0000,
        (short)0x0000, (short)0x0000, (short)0x0000, (short)0x0000,
        (short)0x0000, (short)0x0000, (short)0x0000, (short)0x0000,
        (short)0x0000, (short)0x0000, (short)0x0000, (short)0x0000
    };

    private static final short[] RC_W1 = {
        (short)0x0000, (short)0x0000, (short)0x0000, (short)0x8000,
        (short)0x0000, (short)0x8000, (short)0x8000, (short)0x0000,
        (short)0x0000, (short)0x0000, (short)0x8000, (short)0x8000,
        (short)0x8000, (short)0x0000, (short)0x0000, (short)0x0000,
        (short)0x0000, (short)0x0000, (short)0x0000, (short)0x8000,
        (short)0x8000, (short)0x0000, (short)0x8000, (short)0x8000
    };

    private static final short[] RC_W0 = {
        (short)0x0001, (short)0x8082, (short)0x808A, (short)0x8000,
        (short)0x808B, (short)0x0001, (short)0x8081, (short)0x8009,
        (short)0x008A, (short)0x0088, (short)0x8009, (short)0x000A,
        (short)0x808B, (short)0x008B, (short)0x8089, (short)0x8003,
        (short)0x8002, (short)0x0080, (short)0x800A, (short)0x000A,
        (short)0x8081, (short)0x8080, (short)0x0001, (short)0x8008
    };

    private static short permCount = 0;

    public static void permute(byte[] state)
    {
        U64[] A = new U64[25];
        permute(state, A);
    }

    public static void permute(byte[] state, U64[] A)
    {
        permCount++;
        for (short i = 0; i < 25; i++) {
            A[i] = new U64();
        }

        for (short i = 0; i < 25; i++) {
            short off = (short)(i << 3);
            A[i].w0 = (short)((state[off] & 0xFF) | ((state[(short)(off + 1)] & 0xFF) << 8));
            A[i].w1 = (short)((state[(short)(off + 2)] & 0xFF) | ((state[(short)(off + 3)] & 0xFF) << 8));
            A[i].w2 = (short)((state[(short)(off + 4)] & 0xFF) | ((state[(short)(off + 5)] & 0xFF) << 8));
            A[i].w3 = (short)((state[(short)(off + 6)] & 0xFF) | ((state[(short)(off + 7)] & 0xFF) << 8));
        }

        // 24 rounds
        U64[] B = new U64[25];
        U64[] C = new U64[5];
        U64[] D = new U64[5];

        for (short i = 0; i < 25; i++) {
            B[i] = new U64();
        }

        for (short i = 0; i < 5; i++) {
            C[i] = new U64();
            D[i] = new U64();
        }

        U64 tmp    = new U64();
        U64 tmpNot = new U64();
        U64 tmpAnd = new U64();

        for (short round = 0; round < 24; round++)
        {
            // Theta: C[x] = xor of column lanes
            for (short x = 0; x < 5; x++) {
                U64.copy(A[x], C[x]);
                U64.xor(C[x], A[(short)(x + 5)],  C[x]);
                U64.xor(C[x], A[(short)(x + 10)], C[x]);
                U64.xor(C[x], A[(short)(x + 15)], C[x]);
                U64.xor(C[x], A[(short)(x + 20)], C[x]);
            }

            // D[x] = C[x-1] ^ ROTL64(C[x+1], 1)
            for (short x = 0; x < 5; x++)
            {
                short next = (short)(x + (short)1);
                short prev = (short)(x + (short)4);
                next = (short)(next % 5);
                prev = (short)(prev % 5);
                U64.rol1(C[next], tmp);
                U64.xor(C[prev], tmp, D[x]);
            }

            // A[x,y] ^= D[x]
            for (short x = 0; x < 5; x++)
            {
                for (short y = 0; y < 5; y++)
                {
                    short idx = (short) (x + 5 * y);
                    U64.xor(A[idx], D[x], A[idx]);
                }
            }

            // Rho & Pi -> B
            for (short x = 0; x < 5; x++)
            {
                for (short y = 0; y < 5; y++)
                {
                    short idx =
                        (short)(x + 5 * y);

                    short offset = (short)(RHO_OFFSETS[idx] & 0xFF);

                    short newX = y;
                    short newY = (short) ((short)(2*x) + (short)(3*y));
                    newY =(short)(newY % 5);

                    short dst =
                        (short)(newX + 5 * newY);

                    U64.rol(A[idx], offset, B[dst]);
                }
            }

            // Chi: A[x,y] = B[x,y] ^ ((~B[x+1,y]) & B[x+2,y])
            for (short y = 0; y < 5; y++) {
                for (short x = 0; x < 5; x++) {
                    short idx = (short)(x + 5 * y);

                    short idx1 =(short)((short) (x + 1) % 5);
                    idx1 = (short) (idx1 + 5 * y);
                    short idx2 =(short)((short) (x + 2) % 5);
                    idx2 = (short) (idx2 + 5 * y);

                    U64.not(B[idx1], tmpNot);
                    U64.and(tmpNot, B[idx2], tmpAnd);
                    U64.xor(B[idx], tmpAnd, A[idx]);
                }
            }

            // Iota: XOR round constant
            U64 rc = new U64();
            rc.w3 = RC_W3[round];
            rc.w2 = RC_W2[round];
            rc.w1 = RC_W1[round];
            rc.w0 = RC_W0[round];
            U64.xor(A[0], rc, A[0]);
        }

        // write back hi/lo -> state bytes (little-endian)
        for (short i = 0; i < 25; i++) {

//             short off = (short)(i << 3);

// if (permCount == 3 && i == 20) {
//     ISOException.throwIt((short)0x7F20);
// }

// state[off] = (byte)A[i].w0;

// if (permCount == 3 && i == 20) {
//     ISOException.throwIt((short)0x7F21);
// }

// state[(short)(off + 1)] = (byte)(A[i].w0 >>> 8);

// if (permCount == 3 && i == 20) {
//     ISOException.throwIt((short)0x7F22);
// }
            short off = (short)(i << 3);
            state[off] = (byte)A[i].w0;
            state[(short)(off + 1)] = (byte)(A[i].w0 >>> 8);
            state[(short)(off + 2)] = (byte)A[i].w1;
            state[(short)(off + 3)] = (byte)(A[i].w1 >>> 8);
            state[(short)(off + 4)] = (byte)A[i].w2;
            state[(short)(off + 5)] = (byte)(A[i].w2 >>> 8);
            state[(short)(off + 6)] = (byte)A[i].w3;
            state[(short)(off + 7)] = (byte)(A[i].w3 >>> 8);
        }
    }
}