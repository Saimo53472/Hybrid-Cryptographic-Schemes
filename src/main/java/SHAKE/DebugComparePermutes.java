package SHAKE;

import java.util.Arrays;

/**
 * Compare KeccakLongPermute.keccakF vs KeccakF1600.permute(state,scratch)
 * Prints first maxRounds rounds and first maxLanes lanes and highlights differences.
 */
public class DebugComparePermutes
{
    private static final int RATE_BYTES = 136;

    private static void printLane(long v) {
        System.out.printf("0x%016X", v);
    }

    private static long laneFromStateLong(byte[] state, int i) {
        int off = i * 8;
        long lo = ((long)state[off] & 0xFFL)
                | (((long)state[off + 1] & 0xFFL) << 8)
                | (((long)state[off + 2] & 0xFFL) << 16)
                | (((long)state[off + 3] & 0xFFL) << 24);
        long hi = ((long)state[off + 4] & 0xFFL)
                | (((long)state[off + 5] & 0xFFL) << 8)
                | (((long)state[off + 6] & 0xFFL) << 16)
                | (((long)state[off + 7] & 0xFFL) << 24);
        return (hi << 32) | (lo & 0xFFFFFFFFL);
    }

    private static long laneFromScratch(int[] scratch, int base_hi, int base_lo, int i) {
        long hi = ((long) scratch[base_hi + i]) & 0xFFFFFFFFL;
        long lo = ((long) scratch[base_lo + i]) & 0xFFFFFFFFL;
        return (hi << 32) | lo;
    }

    public static void main(String[] args) throws Exception
    {
        int maxRounds = 2; // print & compare first 2 rounds; increase if needed
        int maxLanes = 5;  // compare first 5 lanes

        // prepare padded state for empty input
        byte[] padded = new byte[200];
        Arrays.fill(padded, (byte)0);
        padded[0] ^= 0x1F;
        padded[RATE_BYTES - 1] ^= (byte)0x80;

        // We'll iterate round-by-round using copies and invoking only one round at a time.
        // For the long-based permute, we must run a full keccakF (24 rounds), so we will
        // compare snapshots by re-running and extracting lane snapshots after each round.
        // To simplify, use the existing KeccakLongPermute.keccakF and KeccakF1600.permute (they do all 24 rounds).
        // We'll capture the full states and then reconstruct intermediate round snapshots by instrumenting
        // the permute code. If that's not possible, we'll at least compare the post-24-round states here.

        // Quick check: compare post-full-permutation states first (should match)
        byte[] stLong = Arrays.copyOf(padded, padded.length);
        byte[] stScratch = Arrays.copyOf(padded, padded.length);

        // Apply full permutations
        KeccakF1600Debug.permute(stLong);

        int[] scratch = new int[120];
        KeccakF1600.permute(stScratch, scratch);

        System.out.println("Comparing full-permutation (post 24 rounds) lane values (first " + maxLanes + "):");
        boolean allMatch = true;
        for (int i = 0; i < maxLanes; i++) {
            long l1 = laneFromStateLong(stLong, i);
            long l2 = laneFromScratch(scratch, 0, 25, i); // base_hi=0, base_lo=25 as in KeccakF1600
            System.out.printf("lane[%2d] long=", i); printLane(l1);
            System.out.print(" scratch="); printLane(l2);
            if (l1 == l2) {
                System.out.println("  OK");
            } else {
                System.out.println("  DIFF");
                allMatch = false;
            }
        }

        if (allMatch) {
            System.out.println("\nPost-24-round states match for first " + maxLanes + " lanes.");
            System.out.println("Now do a higher-level SHAKE output check (32 bytes):");
            // SHAKE check
            byte[] outLong = new byte[32];
            byte[] outScratch = new byte[32];

            // produce via long-based reference
            byte[] tmpState = Arrays.copyOf(padded, padded.length);
            KeccakF1600Debug.permute(tmpState);
            System.arraycopy(tmpState, 0, outLong, 0, 32);

            // produce via scratch-based SHAKE256JC
            byte[] state = new byte[200];
            int[] scratch2 = new int[120];
            SHAKE256JC shake = new SHAKE256JC(state, scratch2);
            shake.reset();
            shake.absorbXor(new byte[0], 0, 0);
            shake.finalizeSqueeze();
            shake.squeezeBytes(outScratch, 0, 32);

            System.out.print("Long-based first 32 bytes: ");
            for (byte b : outLong) System.out.printf("%02X", b);
            System.out.println();

            System.out.print("Scratch-based first 32 bytes: ");
            for (byte b : outScratch) System.out.printf("%02X", b);
            System.out.println();

        } else {
            System.out.println("\nMismatch detected in full-permutation states. We'll need more detailed per-round prints.");
            System.out.println("If you want, I can produce instrumented permute() versions that print lane snapshots after each sub-step (Theta/Rho+Pi/Chi/Iota) for the first few rounds so we can locate the exact operation where they differ.");
        }
    }
}