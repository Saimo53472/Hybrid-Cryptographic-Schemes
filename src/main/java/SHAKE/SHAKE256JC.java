package SHAKE;

/**
 * Java Card–friendly SHAKE256 sponge that uses KeccakF1600.permute(state, scratch).
 * No internal allocations in absorb/finalize/squeeze.
 *
 * Caller must provide buffers (prefer transient on Java Card):
 *  - byte[] state (200 bytes)
 *  - int[] scratch (120 ints)
 *  - byte[] tmp8 (>=8) for word decoding
 *  - byte[] singleByte (>=1) for x4
 */
public final class SHAKE256JC
{
    public static final int RATE_BYTES = 136;
    public static final int STATE_SIZE = 200;

    private final byte[] state;   // 200 bytes
    private final int[] scratch;  // 120 ints for permutation
    private int ratePos;
    private boolean squeezing;

    public SHAKE256JC(byte[] state, int[] scratch)
    {
        if (state == null || state.length != STATE_SIZE) throw new IllegalArgumentException("state must be 200 bytes");
        if (scratch == null || scratch.length < 120) throw new IllegalArgumentException("scratch must be int[120] or larger");
        this.state = state;
        this.scratch = scratch;
        this.ratePos = 0;
        this.squeezing = false;
    }

    public void reset()
    {
        for (int i = 0; i < STATE_SIZE; i++) {
            state[i] = 0;
        }
        ratePos = 0;
        squeezing = false;
    }

    public void absorbXor(byte[] in, int inOff, int len)
    {
        if (squeezing) throw new IllegalStateException("already finalised for squeezing");
        int i = inOff;
        int remaining = len;
        while (remaining > 0)
        {
            int toXor = RATE_BYTES - ratePos;
            if (toXor > remaining) toXor = remaining;
            for (int k = 0; k < toXor; k++) state[ratePos + k] ^= in[i + k];
            ratePos += toXor;
            i += toXor;
            remaining -= toXor;
            if (ratePos == RATE_BYTES)
            {
                KeccakF1600.permute(state, scratch);
                ratePos = 0;
            }
        }
    }

    /**
     * Finalize absorb and prepare for squeeze. SHAKE uses the delimited suffix 0x1F.
     * This implements: absorbBits(0x1F, 5) then pad and permute.
     */
    public void finalizeSqueeze()
    {
        if (squeezing) return;
        state[ratePos] ^= 0x1F;                  // delimited suffix for SHAKE
        state[RATE_BYTES - 1] ^= (byte)0x80;     // final bit
        KeccakF1600.permute(state, scratch);
        ratePos = 0;
        squeezing = true;
    }

    public void squeezeBytes(byte[] out, int outOff, int outLen)
    {
        if (!squeezing) finalizeSqueeze();
        int o = outOff;
        int remaining = outLen;
        while (remaining > 0)
        {
            int available = RATE_BYTES - ratePos;
            int toCopy = (available < remaining) ? available : remaining;
            for (int k = 0; k < toCopy; k++) out[o + k] = state[ratePos + k];
            o += toCopy;
            ratePos += toCopy;
            remaining -= toCopy;
            if (ratePos == RATE_BYTES)
            {
                KeccakF1600.permute(state, scratch);
                ratePos = 0;
            }
        }
    }

    // Squeeze one 64-bit little-endian word and decode into hi/lo ints using tmp8[>=8].
    public void squeezeWordIntoIntPair(byte[] tmp8, int tmpOff, int[] hiOut, int hiIdx, int[] loOut, int loIdx)
    {
        if (tmp8 == null || tmp8.length - tmpOff < 8) throw new IllegalArgumentException("tmp8 >= 8 bytes required");
        if (!squeezing) finalizeSqueeze();
        for (int k = 0; k < 8; k++)
        {
            if (ratePos == RATE_BYTES)
            {
                KeccakF1600.permute(state, scratch);
                ratePos = 0;
            }
            tmp8[tmpOff + k] = state[ratePos++];
        }
        int lo = (tmp8[tmpOff] & 0xFF) | ((tmp8[tmpOff + 1] & 0xFF) << 8)
               | ((tmp8[tmpOff + 2] & 0xFF) << 16) | ((tmp8[tmpOff + 3] & 0xFF) << 24);
        int hi = (tmp8[tmpOff + 4] & 0xFF) | ((tmp8[tmpOff + 5] & 0xFF) << 8)
               | ((tmp8[tmpOff + 6] & 0xFF) << 16) | ((tmp8[tmpOff + 7] & 0xFF) << 24);
        hiOut[hiIdx] = hi;
        loOut[loIdx] = lo;
    }

    // Compute words and fill hiOut/loOut using tmp8 scratch (no internal allocations).
    public void shake256wIntoIntPairs(byte[] msg, int msgOff, int msgLen, int words, int[] hiOut, int[] loOut, byte[] tmp8)
    {
        if (hiOut == null || loOut == null || hiOut.length < words || loOut.length < words) throw new IllegalArgumentException("output arrays too small");
        if (tmp8 == null || tmp8.length < 8) throw new IllegalArgumentException("tmp8 >= 8 required");
        reset();
        absorbXor(msg, msgOff, msgLen);
        finalizeSqueeze();
        for (int i = 0; i < words; i++) squeezeWordIntoIntPair(tmp8, 0, hiOut, i, loOut, i);
    }

    // Sequential SHAKE256x4 interleaving (HAWK) — reuses instance to avoid parallel state allocations.
    public static void sequentialShake256x4Interleaved(
            SHAKE256JC shared,
            byte[] msg, int msgOff, int msgLen,
            int totalWords,
            int[] outHi, int[] outLo,
            byte[] tmp8, byte[] singleByte)
    {
        if (shared == null) throw new IllegalArgumentException("shared required");
        if (outHi == null || outLo == null || outHi.length < totalWords || outLo.length < totalWords) throw new IllegalArgumentException("output arrays too small");
        if (tmp8 == null || tmp8.length < 8) throw new IllegalArgumentException("tmp8 >= 8 required");
        if (singleByte == null || singleByte.length < 1) throw new IllegalArgumentException("singleByte >= 1 required");

        for (int j = 0; j < 4; j++)
        {
            int wordsNeeded = (totalWords + 3 - j) / 4; // ceil((totalWords - j)/4)
            if (wordsNeeded <= 0) continue;

            shared.reset();
            shared.absorbXor(msg, msgOff, msgLen);

            singleByte[0] = (byte) j;
            shared.absorbXor(singleByte, 0, 1);

            shared.finalizeSqueeze();

            for (int i = 0; i < wordsNeeded; i++)
            {
                int outIdx = 4 * i + j;
                if (outIdx >= totalWords) break;
                shared.squeezeWordIntoIntPair(tmp8, 0, outHi, outIdx, outLo, outIdx);
            }
        }
    }
}