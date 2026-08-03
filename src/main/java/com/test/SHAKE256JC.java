package com.test;

/**
 * SHAKE256 sponge that uses KeccakF1600.permute(state, scratch).
 */
public final class SHAKE256JC
{
    public static final short RATE_BYTES = 136;
    public static final short STATE_SIZE = 200;

    private final byte[] state;   // 200 bytes
    private final U64[] scratch;  // 120 ints for permutation
    private short ratePos;
    private boolean squeezing;

    public SHAKE256JC()
    {
        this.state = new byte[200];
        this.scratch = new U64[25];
        this.ratePos = 0;
        this.squeezing = false;
    }

    public SHAKE256JC(SHAKE256JC shake256jc)
    {
        this.state = new byte[200];
        this.scratch = new U64[25];

        for(short i = 0; i < 200; i++) {
            this.state[i] = shake256jc.state[i];
        }
        this.ratePos = shake256jc.ratePos;
        this.squeezing = shake256jc.squeezing;
    }

    public void reset()
    {
        for (short i = 0; i < STATE_SIZE; i++) {
            state[i] = 0;
        }
        ratePos = 0;
        squeezing = false;
    }

    /**
     * Absorb input data into the SHAKE sponge.
     * Data is XORed into the rate portion of the state and a Keccak permutation is applied whenever the rate is full.
     */
    public void absorbXor(byte[] in, short inOff, short len)
    {
        short i = inOff;
        short remaining = len;
        while (remaining > 0)
        {
            int toXor = RATE_BYTES - ratePos;
            if (toXor > remaining) toXor = remaining;
            for (short k = 0; k < toXor; k++) state[(short) (ratePos + k)] ^= in[(short) (i + k)];
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

    /**
     * Extract output bytes from the sponge.
     * Additional Keccak permutations are applied as needed when more output is requested than fits in one rate block.
     */
    public void squeezeBytes(byte[] out, short outOff, short outLen)
    {
        if (!squeezing) finalizeSqueeze();
        int o = outOff;
        int remaining = outLen;
        while (remaining > 0)
        {
            int available = RATE_BYTES - ratePos;
            int toCopy = (available < remaining) ? available : remaining;
            for (short k = 0; k < toCopy; k++) out[(short) (o + k)] = state[(short) (ratePos + k)];
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

    /**
     * Convenience wrapper for absorbing input data.
     */
    public void update(byte[] in, short off, short len)
    {
        absorbXor(in, off, len);
    }

    /**
     * Generate the requested number of output bytes without
     * resetting the sponge state.
     */
    public short doOutput(byte[] out, short off, short len)
    {
        squeezeBytes(out, off, len);
        return len;
    }

    /**
     * Generate output bytes and then reset the sponge so it can be reused for a new SHAKE computation.
     */
    public short doFinal(byte[] out, short off, short len)
    {
        squeezeBytes(out, off, len);
        reset();
        return len;
    }
}