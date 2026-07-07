package Chameleon;

import SHAKE.SHAKE256JC;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class Hawk {
    private static final byte INS_INIT = (byte) 0x10;
    private static final byte INS_GET_CERT = (byte) 0x20;
    private static final byte INS_SIGN_DELTA = (byte) 0x40;
    private static final byte INS_GET_SIG_DELTA = (byte) 0x60;
    private static final byte INS_LOAD_PRIVKEY_DELTA = (byte) 0x71;
    private static final byte INS_LOAD_CERT = (byte) 0x72;
    private static final byte INS_LOCK_CARD = (byte) 0x73;
    private static final byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;

    private byte[] dataToSign;
    private short dataToSignLen;

    private byte[] pqPrivateKey;
    private byte[] pqSignature;

    private byte[] certificate;
    private short certLen;

    private byte[] signatureBuffer;
    private short signatureLen;

    private boolean personalized;
    private RandomData random;

    private short pqKeyOffset = 0;
    private short pqKeyLen = 0;

    protected Hawk() {
      this.register();
   }

   public static void install(byte[] var0, short var1, byte var2) {
      new Hawk();
   }

    public void process(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        if ((apduBuffer[ISO7816.OFFSET_CLA] == 0) &&
            (apduBuffer[ISO7816.OFFSET_INS] == (byte)0xA4)) {
            return;
        }

        switch (apduBuffer[ISO7816.OFFSET_INS]) {

            case INS_INIT:
                initSession(apdu);
                return;

            case INS_GET_CERT:
                sendCertificate(apdu);
                return;

            case INS_SIGN_DELTA:
                createSignatureDelta(apdu);
                return;

            case INS_GET_SIG_DELTA:
                sendSignatureDelta(apdu);
                return;

            case INS_LOAD_PRIVKEY_DELTA:
                loadPrivateKeyDelta(apdu);
                return;

            case INS_LOAD_CERT:
                loadCertificate(apdu);
                return;

            case INS_LOCK_CARD:
                lockCard();
                return;

            case INS_INTERNAL_AUTHENTICATE:
                internalAuthenticate(apdu);
                return;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void loadPrivateKeyDelta(APDU apdu) {
        if (personalized)
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        if (buf[ISO7816.OFFSET_P1] == 0x00) {
            pqKeyOffset = 0;
        }

        Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, pqPrivateKey, pqKeyOffset, len);
        pqKeyOffset += len;
    }

    private short certOffset = 0;

    private void loadCertificate(APDU apdu) {
        if (personalized)
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        if (buf[ISO7816.OFFSET_P1] == 0x00) {
            certOffset = 0;
        }

        Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, certificate, certOffset, len);
        certOffset += len;
        certLen = certOffset;
    }

    private void sendCertificate(APDU apdu) {
        if (certLen == 0)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] buf = apdu.getBuffer();

        short offset = (short)(
            ((buf[ISO7816.OFFSET_P1] & 0xFF) << 8) |
             (buf[ISO7816.OFFSET_P2] & 0xFF)
        );

        if (offset >= certLen)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);

        short remaining = (short)(certLen - offset);
        short chunk = remaining > 200 ? 200 : remaining;

        apdu.setOutgoing();
        apdu.setOutgoingLength(chunk);
        apdu.sendBytesLong(certificate, offset, chunk);
    }

    private void lockCard() {
        personalized = true;
    }

    private void initSession(APDU apdu) {
        signatureLen = 0;
        dataToSignLen = 0;
    }

    private void internalAuthenticate(APDU apdu) {
        byte[] local = dataToSign;
        short pos = 0;

        local[pos++] = 0x05;
        local[pos++] = 0x01;
        local[pos++] = 0x08;

        byte[] dynamic = new byte[] {
            (byte)0x6c,(byte)0x55,(byte)0x44,(byte)0x79,
            (byte)0x7a,(byte)0x91,(byte)0x11,(byte)0x5d
        };

        Util.arrayCopy(dynamic, (short)0, local, pos, (short)8);
        pos += 8;

        short paddingLen = (short)(255 - pos - 4);
        for (short i = 0; i < paddingLen; i++) {
            local[pos++] = (byte)0xBB;
        }

        local[pos++] = 0x01;
        local[pos++] = 0x02;
        local[pos++] = 0x03;
        local[pos++] = 0x04;

        dataToSignLen = pos;
    }

    private void createSignatureDelta(APDU apdu) {
        MayoSigner signer = new MayoSigner();
        signatureLen = 0;
    }

    private void sendSignatureDelta(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength(signatureLen);
        apdu.sendBytesLong(signatureBuffer, (short)0, signatureLen);
    }
}

class HawkSigner{
    // Parameters
    private int q;
    private int logn;
    private int n;
    private int maxLogn;
    private int saltLen;
    private int maxXnorm;
    private RandomData random;

    // Constructor
    public HawkSigner() {
        q = 1;
        logn = 9;
        n = 1 << logn; // 2^logn = 512
        maxLogn = 9;
        saltLen = 24;
        maxXnorm = 8317;
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    }

    // Methods
    // Size calculations for private key and signature
    private static int HAWK_PRIVKEY_SIZE(int logn)
    {
        int n = 1 << logn;
        return 8 + (1 << (logn - 5)) + 2 * (n >> 3) + (n >> 4);
    }

    private static int HAWK_SIG_SIZE(int logn)
    {
        return 249 + 306 * (2 >> (10 - logn)) + 360 * (1 >> (10 - logn));
    }

    /**
     * Hamming weight of a byte (number of 1 bits)
     */
    private static byte popcount8(byte x)
    {
        short v = (short)(x & 0xFF);

        v = (short)((v & 0x55) + ((v >>> 1) & 0x55));
        v = (short)((v & 0x33) + ((v >>> 2) & 0x33));
        v = (short)((v & 0x0F) + ((v >>> 4) & 0x0F));

        return (byte)v;
    }

    /**
     * Regenerate f and g polynomials from seed using SHAKE256
     */
    public void regen_fg(byte[] f, short fOff, byte[] g, short gOff, byte[] seed) {
        byte[] qb = new byte[8];

        SHAKE256JC shake = new SHAKE256JC();

        for (byte j = 0; j < 4; j++)
        {
            shake.reset();
            shake.absorbXor(seed, (short)0, (short)24);

            byte[] singleByte = new byte[1];
            singleByte[0] = j;
            shake.absorbXor(singleByte, (short)0, (short)1);

            shake.finalizeSqueeze(); // check what update and doFinal are doing in the original code

            for (short u = 0; u < 1024; u += 32)
            {
                shake.squeezeBytes(qb, (short)0, (short)8);

                for (short i = 0; i < 8; i++)
                {
                    byte coeff = (byte)(popcount8(qb[i]) - 4);

                    if (u < 512)
                    {
                        f[(short)(fOff + u + (j << 3) + i)] = coeff;
                    }
                    else
                    {
                        g[(short)(gOff + (u - 512) + (j << 3) + i)] = coeff;
                    }
                }
            }
        }
    }

    // Sign method
    public int sign(int logn, int useShake, byte[] sig, SHAKE256JC shake256jc, byte[] priv, int privLen, byte[] tmp, int tmpLen) {
        // Ensure proper alignment for 64-bit access
        if (tmpLen < 7)
        {
            return 0;
        }
        if (logn < 8 || logn > 10)
        {
            return 0;
        }

        // Align temporary buffer for 64-bit access
        int utmp1 = 0;
        int utmp2 = (utmp1 + 7) & ~7;
        tmpLen -= (int)(utmp2 - utmp1);

        if (tmpLen < (6 << logn))
        {
            return 0;
        }

        int seedLen = 8 + (1 << (logn - 5));
        int hpubLen = 1 << (logn - 4);

        // Memory layout in tmp buffer
        int offset = 0;
        byte[] g = new byte[n];
        byte[] ww = new byte[2 * n];
        byte[] x0 = new byte[2 * n];
        byte[] x1 = new byte[n];
        byte[] f = new byte[n];

        // Re-expand the private key
        byte[] F2, G2;
        byte[] hpub;

        // Regenerate f and g from seed
        byte[] seed = new byte[seedLen];
        Util.arrayCopy(priv, 0, seed, 0, seedLen);
        regen_fg(f, 0, g, 0, seed);
        Util.arrayCopy(priv, seedLen, F2, 0, n >> 3);
        Util.arrayCopy(priv, seedLen + (n >> 3), G2, 0, n >> 3);
        Util.arrayCopy(priv, seedLen + 2 * (n >> 3), hpub, 0, hpubLen);

        // Compute hm = SHAKE256(message || hpub)
        byte[] hm = new byte[64];
        shake256jc.reset();
        shake256jc.absorbXor(hpub, 0, hpubLen);
        shake256jc.finalizeSqueeze();
        shake256jc.squeezeBytes(hm, 0, 64);

        // Main signing loop
        for (int attempt = 0; ; attempt += 2) {
            int t0Offset = 0;
            int t1Offset = t0Offset + (n >> 3);
            int h0Offset = t1Offset + (n >> 3);
            int h1Offset = h0Offset + (n >> 3);
            int f2Offset = h1Offset + (n >> 3);
            int g2Offset = f2Offset + (n >> 3);
            int xxOffset = g2Offset + (n >> 3);

            // Generate salt
            byte[] salt = new byte[saltLen];
            random.nextBytes(salt);

            if (useShake != 0) {
                byte[] tbuf = new byte[4];
                enc32le(tbuf, 0, attempt);

                shake256jc.reset();
                shake256jc.absorbXor(hm, 0, hm.length);
                shake256jc.absorbXor(priv, 0, seedLen);
                shake256jc.absorbXor(tbuf, 0, tbuf.length);
                shake256jc.absorbXor(salt, 0, saltLen);
                shake256jc.finalizeSqueeze();
                shake256jc.squeezeBytes(salt, 0, saltLen);
            }

            // Compute h = SHAKE256(hm || salt)
            shake256jc.reset();
            shake256jc.absorbXor(hm, 0, hm.length);
            shake256jc.absorbXor(salt, 0, saltLen);
            shake256jc.finalizeSqueeze();
            
            // Squeeze h0 and h1 (total n >> 2 bytes)
            shake256jc.squeezeBytes(ww, h0Offset, n >> 2);

            // Extract low bits and compute t = B*h (mod 2)
            byte[] f2 = new byte[n >> 3];
            byte[] g2 = new byte[n >> 3];
            extract_lowbit(logn, f2, f);
            extract_lowbit(logn, g2, g);

            basisM2Mul(logn,
                ww, t0Offset, ww, t1Offset,  // t0, t1
                ww, h0Offset, ww, h1Offset,  // h0, h1
                f2, 0, g2, 0,                // f2, g2
                F2, 0, G2, 0,                // F2, G2
                tmp, xxOffset);              // tmp space

            // Sample x using Gaussian distribution
            int xsn;
            if (useShake != 0) {
                byte[] tbuf = new byte[4];
                enc32le(tbuf, 0, attempt + 1);

                SHAKE256JC gaussShake = new SHAKE256JC();

                gaussShake.reset();
                gaussShake.absorbXor(hm, 0, hm.length);
                gaussShake.absorbXor(priv, 0, seedLen);
                gaussShake.absorbXor(tbuf, 0, tbuf.length);
                gaussShake.finalizeSqueeze();

                xsn = sigGauss(logn, gaussShake, x0, 0, ww, t0Offset, tmp8, singleByte);
            } else {
                xsn = sigGaussAlt(logn, x0, 0, ww, t0Offset);
            }

            // Reject if squared norm is too large
            if (xsn > maxXnorm) {
                continue;
            }

            // Compute s1 = f*x1 - g*x0 using NTT over Q=18433
            short[] w1 = new short[n];
            short[] w2 = new short[n];
            short[] w3 = new short[n];

            // w1 <- g*x0 in NTT domain
            mq18433PolySetSmall(logn, w1, 0, g, 0);
            mq18433PolySetSmall(logn, w2, 0, x0, 0);
            mq18433NTT(logn, w1, 0);
            mq18433NTT(logn, w2, 0);
            for (int u = 0; u < n; u++) {
                w1[u] = (short)mq18433MontyMul(w1[u] & 0xFFFF, w2[u] & 0xFFFF);
            }

            // w3 <- f*x1 - g*x0, then INTT to get polynomial
            mq18433PolySetSmall(logn, w2, 0, x0, n);  // x1 = x0[n..2n-1]
            mq18433PolySetSmall(logn, w3, 0, f, 0);
            mq18433NTT(logn, w2, 0);
            mq18433NTT(logn, w3, 0);
            for (int u = 0; u < n; u++) {
                w3[u] = (short)mq18433ToMonty(mq18433Sub(
                    mq18433MontyMul(w2[u] & 0xFFFF, w3[u] & 0xFFFF),
                    w1[u] & 0xFFFF));
            }
            mq18433INTT(logn, w3, 0);
            mq18433PolySnorm(logn, w3, 0);

            short[] s1 = w3;

            int ps = polySymBreak(logn, s1, 0);
            int lim = 1 << ((logn == 10) ? 10 : 9);
            int nm = ~tbmask(ps - 1); // ?

            byte[] h1buf = new byte[n >> 3];
            Util.arrayCopy(ww, h1Offset, h1buf, 0, n >> 3);

            // Per-coefficient bounds check
            int reject = 0;
            for (int u = 0; u < n; u++) {
                int z = s1[u];
                z = ((z ^ nm) - nm) + ((h1buf[u >> 3] >> (u & 7)) & 1);
                int y = z >> 1;

                // -1 if y < -lim or y >= lim, 0 otherwise
                int outOfRange = ((y + lim) >> 31) | ((lim - 1 - y) >> 31);
                reject |= outOfRange;
                s1[u] = (short)y;
            }

            if (reject != 0) {
                continue;
            }

            // Encode signature
            int sigLen = HAWK_SIG_SIZE(logn);
            if (encodeSig(logn, tmp, 0, sigLen, salt, 0, saltLen, s1, 0)) {
                if (sig != null) {
                    Util.arrayCopy(tmp, 0, sig, 0, sigLen);
                }
                return 1;
            }
        }
    }
}
