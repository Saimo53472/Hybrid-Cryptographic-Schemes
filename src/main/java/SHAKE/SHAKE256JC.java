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

    public SHAKE256JC()
    {
        this.state = new byte[200];
        this.scratch = new int[120];
        this.ratePos = 0;
        this.squeezing = false;
    }

    public SHAKE256JC(SHAKE256JC shake256jc)
    {
        this.state = new byte[200];
        this.scratch = new int[120];

        for(int i = 0; i < 200; i++) {
            this.state[i] = shake256jc.state[i];
        }
        this.ratePos = shake256jc.ratePos;
        this.squeezing = shake256jc.squeezing;
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

    public void update(byte[] in, int off, int len)
    {
        absorbXor(in, off, len);
    }

    public int doOutput(byte[] out, int off, int len)
    {
        squeezeBytes(out, off, len);
        return len;
    }

    public int doFinal(byte[] out, int off, int len)
    {
        squeezeBytes(out, off, len);
        reset();
        return len;
    }
}