package SHAKE;

/**
 * Java Card / HAWK-friendly SHAKE256 sponge built on KeccakF1600JC.permute.
 *
 * Purpose:
 *  - Provide SHAKE256 byte sponge with domain separation for SHAKE (0x0F suffix).
 *  - Provide SHAKE256w output as 64-bit little-endian words expressed as (hi:int, lo:int).
 *  - Provide RAM-efficient sequential SHAKE256x4 interleaving per HAWK:
 *      SHAKE256x4(m)[4*i + j] = SHAKE256w(m || EncodeInt(j,8))[i]
 *
 * Java Card specific design decisions:
 *  - No 'long' anywhere. Words returned as two ints (hi, lo).
 *  - No allocations inside absorb / finalize / squeeze: caller must supply working buffers.
 *  - KeccakF1600JC.permute(state, scratch) is used; scratch must be int[120] as required by permute.
 *  - Use small tmp8 (byte[8]) and singleByte (byte[1]) buffers supplied by caller; reuse them to avoid allocations.
 *
 * Usage (recommended on Java Card):
 *  - Allocate transient buffers at install/reset (if supported):
 *      byte[] state = JCSystem.makeTransientByteArray((short)200, JCSystem.CLEAR_ON_RESET);
 *      int[] scratch = JCSystem.makeTransientIntArray((short)120, JCSystem.CLEAR_ON_RESET);
 *      byte[] tmp8 = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_RESET);
 *      byte[] singleByte = JCSystem.makeTransientByteArray((short)1, JCSystem.CLEAR_ON_RESET);
 *  - Create instance: SHAKE256JC_HAWK shake = new SHAKE256JC_HAWK(state, scratch);
 *  - Use absorbXor(...) then finalizeSqueeze(), then squeezeBytes(...).
 *  - For SHAKE256w words, use shake256wIntoIntPairs(...).
 *  - For SHAKE256x4 (HAWK), use sequentialShake256x4Interleaved(...), passing singleByte for j.
 *
 * Note: on a JVM (for testing) you may allocate normal arrays and pass them in.
 */
public final class SHAKE256JC
{
    public static final int RATE_BYTES = 136;
    public static final int STATE_SIZE = 200; // 25 * 8

    private final byte[] state;    // 200 bytes, caller provided
    private final int[] scratch;   // int[120], caller provided
    private int ratePos;           // current position in rate area (0..RATE_BYTES-1)
    private boolean squeezing;

    /**
     * Construct with caller-provided buffers.
     *
     * Preconditions:
     *   state.length == 200
     *   scratch.length >= 120
     *
     * Buffers should be allocated once and reused. Prefer transient allocation on Java Card.
     */
    public SHAKE256JC(byte[] state, int[] scratch)
    {
        if (state == null || state.length != STATE_SIZE)
        {
            throw new IllegalArgumentException("state must be 200 bytes");
        }
        if (scratch == null || scratch.length < 120)
        {
            throw new IllegalArgumentException("scratch must be int[120] or larger");
        }
        this.state = state;
        this.scratch = scratch;
        this.ratePos = 0;
        this.squeezing = false;
    }

    /** Zero the state and reset counters. Avoids Arrays.fill so it's Java Card friendly. */
    public void reset()
    {
        for (int i = 0; i < STATE_SIZE; i++)
        {
            state[i] = 0;
        }
        ratePos = 0;
        squeezing = false;
    }

    /**
     * Absorb bytes by XORing them into the state at the current rate position.
     * No allocations; permutes when a full rate block is reached.
     *
     * @param in input buffer
     * @param inOff input offset
     * @param len number of bytes to absorb
     */
    public void absorbXor(byte[] in, int inOff, int len)
    {
        if (squeezing)
        {
            throw new IllegalStateException("already finalised for squeezing");
        }
        int i = inOff;
        int remaining = len;
        while (remaining > 0)
        {
            int toXor = RATE_BYTES - ratePos;
            if (toXor > remaining) toXor = remaining;

            // XOR incoming bytes into state
            for (int k = 0; k < toXor; k++)
            {
                state[ratePos + k] ^= in[i + k];
            }

            ratePos += toXor;
            i += toXor;
            remaining -= toXor;

            if (ratePos == RATE_BYTES)
            {
                // apply permutation and reset rate position
                Keccak.permute(state, scratch);
                ratePos = 0;
            }
        }
    }

    /**
     * Append SHAKE domain separation (0x0F, 4 bits), set final bit, permute and enter squeezing.
     *
     * This matches BouncyCastle's absorbBits(0x0F, 4) behavior for SHAKE.
     */
    public void finalizeSqueeze()
    {
        if (squeezing)
        {
            return;
        }

        // XOR low nibble 0x0F into the current rate byte position
        state[ratePos] ^= 0x0F;

        // XOR 0x80 into last byte of the rate block (padding)
        state[RATE_BYTES - 1] ^= (byte)0x80;

        // permute once to mix padding
        Keccak.permute(state, scratch);
        ratePos = 0;
        squeezing = true;
    }

    /**
     * Squeeze bytes into caller-provided output buffer.
     *
     * @param out output buffer
     * @param outOff offset in out buffer
     * @param outLen number of bytes to produce
     */
    public void squeezeBytes(byte[] out, int outOff, int outLen)
    {
        if (!squeezing)
        {
            finalizeSqueeze();
        }
        int o = outOff;
        int remaining = outLen;
        while (remaining > 0)
        {
            int available = RATE_BYTES - ratePos;
            int toCopy = (available < remaining) ? available : remaining;

            // copy bytes from state to out
            for (int k = 0; k < toCopy; k++)
            {
                out[o + k] = state[ratePos + k];
            }

            o += toCopy;
            ratePos += toCopy;
            remaining -= toCopy;

            if (ratePos == RATE_BYTES)
            {
                Keccak.permute(state, scratch);
                ratePos = 0;
            }
        }
    }

    /**
     * Squeeze exactly 8 bytes (one 64-bit little-endian word) into tmp8 starting at tmpOff,
     * then decode them to hi/lo ints and store in hiOut[hiIdx] and loOut[loIdx].
     *
     * tmp8 must be length >= tmpOff + 8.
     *
     * This method guarantees no allocations and uses only the instance state and scratch.
     */
    public void squeezeWordIntoIntPair(byte[] tmp8, int tmpOff, int[] hiOut, int hiIdx, int[] loOut, int loIdx)
    {
        if (tmp8 == null || tmp8.length - tmpOff < 8)
        {
            throw new IllegalArgumentException("tmp8 must be >= 8 bytes at tmpOff");
        }
        if (!squeezing)
        {
            finalizeSqueeze();
        }

        // Ensure 8 bytes available, permuting as needed
        for (int k = 0; k < 8; k++)
        {
            if (ratePos == RATE_BYTES)
            {
                Keccak.permute(state, scratch);
                ratePos = 0;
            }
            tmp8[tmpOff + k] = state[ratePos++];
        }

        // decode little-endian into lo and hi 32-bit ints
        int lo = (tmp8[tmpOff] & 0xFF) | ((tmp8[tmpOff + 1] & 0xFF) << 8)
               | ((tmp8[tmpOff + 2] & 0xFF) << 16) | ((tmp8[tmpOff + 3] & 0xFF) << 24);
        int hi = (tmp8[tmpOff + 4] & 0xFF) | ((tmp8[tmpOff + 5] & 0xFF) << 8)
               | ((tmp8[tmpOff + 6] & 0xFF) << 16) | ((tmp8[tmpOff + 7] & 0xFF) << 24);

        hiOut[hiIdx] = hi;
        loOut[loIdx] = lo;
    }

    /**
     * Compute SHAKE256w(m) and write 'words' 64-bit words into provided hiOut/loOut arrays.
     * All buffers must be supplied by caller to avoid allocations.
     *
     * @param msg input message
     * @param msgOff input offset
     * @param msgLen input length
     * @param words number of 64-bit words to produce
     * @param hiOut int[] destination for hi parts (length >= words)
     * @param loOut int[] destination for lo parts (length >= words)
     * @param tmp8 byte[8] temporary buffer (caller provided)
     */
    public void shake256wIntoIntPairs(byte[] msg, int msgOff, int msgLen,
                                      int words, int[] hiOut, int[] loOut, byte[] tmp8)
    {
        if (hiOut == null || loOut == null || hiOut.length < words || loOut.length < words)
        {
            throw new IllegalArgumentException("output arrays too small");
        }
        if (tmp8 == null || tmp8.length < 8)
        {
            throw new IllegalArgumentException("tmp8 must be >= 8 bytes");
        }

        reset();
        absorbXor(msg, msgOff, msgLen);
        finalizeSqueeze();
        for (int i = 0; i < words; i++)
        {
            squeezeWordIntoIntPair(tmp8, 0, hiOut, i, loOut, i);
        }
    }

    /**
     * RAM-efficient sequential SHAKE256x4 per HAWK:
     *
     * For j=0..3 run SHAKE256(m || j) sequentially, writing each produced 64-bit word to
     * out arrays at index 4*i + j. This uses only one shared sponge instance and avoids
     * storing 4 parallel states.
     *
     * All buffers (state, scratch, tmp8, singleByte) must be provided by caller and reused.
     *
     * @param msg input message m
     * @param msgOff input offset
     * @param msgLen input length
     * @param totalWords total number of 64-bit words desired in the interleaved output
     * @param outHi int[] destination for hi parts (length >= totalWords)
     * @param outLo int[] destination for lo parts (length >= totalWords)
     * @param tmp8 byte[8] temporary buffer for decoding one word at a time
     * @param singleByte byte[1] reusable buffer used to absorb the single 'j' byte (no allocation)
     */
    public static void sequentialShake256x4Interleaved(
            SHAKE256JC shared,
            byte[] msg, int msgOff, int msgLen,
            int totalWords,
            int[] outHi, int[] outLo,
            byte[] tmp8, byte[] singleByte)
    {
        if (shared == null)
        {
            throw new IllegalArgumentException("shared instance required");
        }
        if (outHi == null || outLo == null || outHi.length < totalWords || outLo.length < totalWords)
        {
            throw new IllegalArgumentException("output arrays too small");
        }
        if (tmp8 == null || tmp8.length < 8)
        {
            throw new IllegalArgumentException("tmp8 must be >= 8");
        }
        if (singleByte == null || singleByte.length < 1)
        {
            throw new IllegalArgumentException("singleByte must be 1 byte buffer");
        }

        // For each j = 0..3 run SHAKE256(m || j) sequentially
        for (int j = 0; j < 4; j++)
        {
            int wordsNeeded = (totalWords + 3 - j) / 4; // ceil((totalWords - j)/4)
            if (wordsNeeded <= 0) continue;

            shared.reset();
            shared.absorbXor(msg, msgOff, msgLen);

            // Absorb single byte j without allocating: reuse singleByte buffer
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