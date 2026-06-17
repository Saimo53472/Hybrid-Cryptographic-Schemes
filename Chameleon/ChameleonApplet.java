package Chameleon;

import javacard.framework.*; // Applet class
import javacard.security.*; // Cryptographic operations
import javacardx.crypto.*; // Extended cryptographic operations

public class ChameleonApplet extends Applet {

    // Commands that can be sent from the terminal to control the applet behavior
    private static final byte INS_INIT = (byte) 0x10; // Initializes/resets session state
    private static final byte INS_GET_CERT = (byte) 0x20; // Returns the stored Certificate
    private static final byte INS_SIGN_BASE = (byte) 0x30; // Creates the classical signature
    private static final byte INS_SIGN_DELTA = (byte) 0x40; // Creates the post-quantum signature
    private static final byte INS_GET_SIG_BASE = (byte) 0x50; // Returns the computed classical signature
    private static final byte INS_GET_SIG_DELTA = (byte) 0x60; // Returns the computed delta signature 

    private static final byte INS_LOAD_PRIVKEY_BASE = (byte) 0x70; 
    private static final byte INS_LOAD_PRIVKEY_DELTA = (byte) 0x71; 
    private static final byte INS_LOAD_CERT = (byte) 0x72;
    private static final byte INS_LOCK_CARD = (byte) 0x73;

    private static final byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;

    private static final byte INS_DEBUG_GET_ESK = (byte)0x92; // DEBUG
    private byte[] eskBuffer = new byte[4096];
    private short eskLen = 0;

    private byte[] dataToSign; // data to be signed
    private short dataToSignLen;
    private static final short TOTAL_LEN = 255; // total length of data to be signed (including padding)

    // Classical values 
    private ECPrivateKey classicalPrivateKey; // on card
    private Signature classicalSignature; 

    // Post-Quantum values
    private byte[] pqPrivateKey; // on card 
    private byte[] pqSignature; 

    // Certificate storage
    private byte[] certificate; // stored on card
    private short certLen;

    // Temporary APDU buffer - communication
    private byte[] buffer;

    private byte[] signatureBuffer;
    private short signatureLen;

    private boolean personalized;
    private RandomData random;
    private byte[] iccDynamicData = new byte[8];

    private short pqKeyOffset = 0;
    private short pqKeyLen = 0;

    // RAM usage estimation
    // dataToSign: 255 bytes
    // certificate: 2048 bytes
    // signatureBuffer: 128 bytes
    // pqPrivateKey: 2048 bytes
    // pqSignature: 512 bytes
    // TOTAL ≈ 4991 bytes (excluding temporary APDU buffers)

    protected ChameleonApplet() {
        dataToSign = new byte[255];
        certificate = new byte[2048];
        signatureBuffer = new byte[128];

        classicalPrivateKey = (ECPrivateKey) KeyBuilder.buildKey( KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        classicalSignature = Signature.getInstance( Signature.ALG_ECDSA_SHA_256, false);

        pqPrivateKey = new byte[2048];
        pqSignature = new byte[512];

        personalized = false;
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        register(); // makes the applet selectable 
    }

    // Called once during applet installation on the card
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ChameleonApplet();
    }

    // This is the main entry point for all communication with the card (every APDU command is routed through this method)
    public void process(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        if ((apduBuffer[ISO7816.OFFSET_CLA] == 0) && (apduBuffer[ISO7816.OFFSET_INS] == (byte) (0xA4)) ) // SELECT APDU command
            return;

        switch (apduBuffer[ISO7816.OFFSET_INS]) {

            case INS_INIT:
                initSession(apdu);
                return;

            case INS_GET_CERT:
                sendCertificate(apdu);
                return;
            
            case INS_SIGN_BASE:
                createSignatureBase(apdu);
                return;

            case INS_SIGN_DELTA:
                createSignatureDelta(apdu);
                return;

            case INS_GET_SIG_BASE:
                sendSignatureBase(apdu);
                return;

            case INS_GET_SIG_DELTA:
                sendSignatureDelta(apdu);
                return;

            case INS_LOAD_PRIVKEY_BASE:
                loadPrivateKeyBase(apdu);
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

            case INS_DEBUG_GET_ESK:
                sendESK(apdu);
                return;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void sendESK(APDU apdu) {
        MayoSigner signer = new MayoSigner();

        eskLen = signer.expandSK(pqPrivateKey, eskBuffer, (short)0);

        apdu.setOutgoing();
        apdu.setOutgoingLength(eskLen);
        apdu.sendBytesLong(eskBuffer, (short)0, eskLen);
    }

    private void loadPrivateKeyBase(APDU apdu) {

        if (personalized)
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        // Loads EC private scalar S
        classicalPrivateKey.setS(
            buf,
            (short) ISO7816.OFFSET_CDATA,
            len
        );
    }

    private void loadPrivateKeyDelta(APDU apdu) {

        if (personalized)
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        byte p1 = buf[ISO7816.OFFSET_P1];
        if (p1 == 0x00) {
            pqKeyOffset = 0;
        }

        // Load
        Util.arrayCopy(
                buf,
                ISO7816.OFFSET_CDATA,
                pqPrivateKey,
                pqKeyOffset,
                len
            );

        pqKeyOffset += len;
}

    private short certOffset = 0;

    private void loadCertificate(APDU apdu) {
        if (personalized)
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        short dataOffset = ISO7816.OFFSET_CDATA;

        byte p1 = buf[ISO7816.OFFSET_P1];

        if (p1 == 0x00) {
            certOffset = 0;
        }

        Util.arrayCopy(buf, dataOffset, certificate, certOffset, len);

        certOffset += len;
        certLen = certOffset;
    }

    private void lockCard() {
        personalized = true;
    }

    private void initSession(APDU apdu) {
        signatureLen = 0;
        dataToSignLen = 0;
    }

    private void internalAuthenticate(APDU apdu) {
        byte[] dataToSign = new byte[255];
        short pos = 0;

        dataToSign[pos++] = 0x05;
        dataToSign[pos++] = 0x01;
        dataToSign[pos++] = 0x08;

        // use the SAME random bytes you printed
        byte[] dynamic = new byte[] {
            (byte)0x6c,(byte)0x55,(byte)0x44,(byte)0x79,
            (byte)0x7a,(byte)0x91,(byte)0x11,(byte)0x5d
        };

        Util.arrayCopy(dynamic, (short) 0, dataToSign, pos, (short) 8);
        pos += 8;

        // padding
        short paddingLen = (short) (255 - pos - 4);
        for (short i = 0; i < paddingLen; i++) {
            dataToSign[pos++] = (byte)0xBB;
        }

        // challenge
        dataToSign[pos++] = 0x01;
        dataToSign[pos++] = 0x02;
        dataToSign[pos++] = 0x03;
        dataToSign[pos++] = 0x04;

        dataToSignLen = pos;
    }

    private void createSignatureBase(APDU apdu) {
        classicalSignature.init(classicalPrivateKey, Signature.MODE_SIGN);
        signatureLen = classicalSignature.sign(dataToSign, (short) 0, dataToSignLen, signatureBuffer, (short) 0);
    }

    private void createSignatureDelta(APDU apdu) {
        MayoSigner signer = new MayoSigner();

        // signatureLen = signer.sign(
        //     pqPrivateKey,
        //     pqKeyLen,
        //     dataToSign,
        //     dataToSignLen,
        //     pqSignature,
        //     (short) 0
        // );
    }

    private void sendCertificate(APDU apdu) {

        if (certLen == 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buf = apdu.getBuffer();

        short offset = (short) (
            ((buf[ISO7816.OFFSET_P1] & 0xFF) << 8) |
            (buf[ISO7816.OFFSET_P2] & 0xFF)
        );

        if (offset >= certLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short remaining = (short) (certLen - offset);
        short chunk = remaining > 200 ? 200 : remaining;

        apdu.setOutgoing();
        apdu.setOutgoingLength(chunk);
        apdu.sendBytesLong(certificate, offset, chunk);
    }

    private void sendSignatureBase(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength(signatureLen);
        apdu.sendBytesLong(signatureBuffer, (short) 0, signatureLen);
    }

    private void sendSignatureDelta(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength(signatureLen);
        apdu.sendBytesLong(signatureBuffer, (short) 0, signatureLen);
    }
}

class MayoSigner {

    private static final short Q = 16;

    private static final short M = 78;
    private static final short N = 86;
    private static final short O = 8;

    private static final short N_MINUS_O = (short)(N - O);
    private static final short O_DIM = O;

    private static final short K = 10;

    private static final short SALT_BYTES = 24;
    private static final short DIGEST_BYTES = 32;

    private static final short PK_SEED_BYTES = 16;
    private static final short SK_SEED_BYTES = 16;

    private static final short O_BYTES = (short)(N_MINUS_O * O);
    private static final short P1_BYTES = 512;
    private static final short P2_BYTES = 256;
    private static final short M_VEC_LIMBS = (short)((M + 15) / 16);
    private static final short MAYO_OK = 0;

    private Cipher aesCtr;

    private void decode(byte[] m, int offset, byte[] mdec, int mdecOffset, int mdeclen) {
        int i;
        int j = 0;

        for(i = 0; i < mdeclen / 2; i++) {
            mdec[mdecOffset + j++] = (byte)(m[offset + i] & 0x0F);
            mdec[mdecOffset + j++] = (byte)((m[offset + i] >> 4) & 0x0F);
        }

        if(mdeclen % 2 != 0) {
            mdec[mdecOffset + j] = (byte)(m[offset + i] & 0x0F);
        }
    }

    private void encode(byte[] m,byte[] menc, int mencOffset, int mlen) {
        int i;
        int j = 0;

        for(i = 0; i < mlen / 2; i++, j += 2) {
            menc[mencOffset + i] =
                (byte)((m[j] & 0x0F) |
                    ((m[j + 1] & 0x0F) << 4));
        }

        if(mlen % 2 != 0) {
            menc[mencOffset + i] = (byte)(m[j] & 0x0F);
        }
    }

    private int mul_table(byte b) {
        int x = (b & 0xFF) * 0x08040201;

        int high_nibble_mask = 0xF0F0F0F0;
        int high = x & high_nibble_mask;

        return x ^ (high >>> 4) ^ (high >>> 3);
    }

    private void m_vec_mul_add (int limbs, byte[] in, int in_offset, byte a, byte[] acc, int acc_offset) { // might be a problem?

        int tab = mul_table(a);   // must return int (32-bit)

        long lsb_mask = 0x1111111111111111L;

        for (int i = 0; i < limbs; i++) {

            int inPos = in_offset + i * 8;
            int accPos = acc_offset + i * 8;

            // reconstruct 64-bit value from 8 bytes - rebuild the 64-bit word so we can apply the same bit trick as C
            long inVal =
                    ((long)(in[inPos]   & 0xFF) << 56) |
                    ((long)(in[inPos+1] & 0xFF) << 48) |
                    ((long)(in[inPos+2] & 0xFF) << 40) |
                    ((long)(in[inPos+3] & 0xFF) << 32) |
                    ((long)(in[inPos+4] & 0xFF) << 24) |
                    ((long)(in[inPos+5] & 0xFF) << 16) |
                    ((long)(in[inPos+6] & 0xFF) << 8)  |
                    ((long)(in[inPos+7] & 0xFF));

            long accVal =
                    ((long)(acc[accPos]   & 0xFF) << 56) |
                    ((long)(acc[accPos+1] & 0xFF) << 48) |
                    ((long)(acc[accPos+2] & 0xFF) << 40) |
                    ((long)(acc[accPos+3] & 0xFF) << 32) |
                    ((long)(acc[accPos+4] & 0xFF) << 24) |
                    ((long)(acc[accPos+5] & 0xFF) << 16) |
                    ((long)(acc[accPos+6] & 0xFF) << 8)  |
                    ((long)(acc[accPos+7] & 0xFF));

            long result =
                    ((inVal       & lsb_mask) * (tab & 0xFFL)) ^
                    (((inVal >> 1) & lsb_mask) * ((tab >> 8)  & 0xFL)) ^
                    (((inVal >> 2) & lsb_mask) * ((tab >> 16) & 0xFL)) ^
                    (((inVal >> 3) & lsb_mask) * ((tab >> 24) & 0xFL));

            accVal ^= result;

            // store back into acc
            acc[accPos]   = (byte)(accVal >>> 56);
            acc[accPos+1] = (byte)(accVal >>> 48);
            acc[accPos+2] = (byte)(accVal >>> 40);
            acc[accPos+3] = (byte)(accVal >>> 32);
            acc[accPos+4] = (byte)(accVal >>> 24);
            acc[accPos+5] = (byte)(accVal >>> 16);
            acc[accPos+6] = (byte)(accVal >>> 8);
            acc[accPos+7] = (byte)(accVal);
        }
    }

    // private byte gf16_mul(byte x, byte y) {
    //     byte r = 0;

    //     for (int i = 0; i < 4; i++) {
    //         if (((y >> i) & 1) != 0) {
    //             r ^= x;
    //         }

    //         boolean carry = (x & 0x8) != 0;
    //         x <<= 1;

    //         if (carry) {
    //             x ^= 0x13; // GF(16) irreducible polynomial x^4 + x + 1
    //         }

    //         x &= 0xF; // keep 4 bits
    //     }

    //     return (byte)(r & 0xF);
    // }

    // private void m_vec_mul_add_simplified(byte[] in, int inOffset, byte a, byte[] acc, int accOffset, int vecLen) {

    //     for (int i = 0; i < vecLen; i++) {
    //         byte x = (byte)(in[inOffset + i] & 0x0F);
    //         byte prod = gf16_mul(x, a);

    //         acc[accOffset + i] ^= prod;
    //     }
    // }

    private void aes_ctr_prf(byte[] out, int outOffset, int outLen, byte[] keyBytes) {
        AESKey key = (AESKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_AES,
            KeyBuilder.LENGTH_AES_128,
            false
        );

        key.setKey(keyBytes, (short)0);

        Cipher aes = Cipher.getInstance(
            Cipher.ALG_AES_BLOCK_128_ECB_NOPAD,
            false
        );

        aes.init(key, Cipher.MODE_ENCRYPT);

        byte[] counter = new byte[16];
        byte[] block = new byte[16];

        short produced = 0;

        while (produced < outLen) {

            // encrypt counter
            aes.doFinal(counter, (short)0, (short)16, block, (short)0);

            short toCopy = (short)Math.min(16, outLen - produced);

            Util.arrayCopyNonAtomic(
                block, (short)0,
                out, (short)(outOffset + produced),
                toCopy
            );

            incrementCounter(counter);

            produced += toCopy;
        }
    }

    private void incrementCounter(byte[] counter) {
        for (short i = 15; i >= 0; i--) {
            counter[i]++;
            if (counter[i] != 0) {
                break; 
            }
        }
    }

    private void unpack_m_vecs(byte[] in, int inOffset, byte[] out, int outOffset, int vecs, int m) {
        int m_vec_limbs = (m + 15) / 16;
        byte[] tmp = new byte[m_vec_limbs * 8];

        for (int i = vecs - 1; i >= 0; i--) {

            Util.arrayFillNonAtomic(tmp, (short)0, (short)tmp.length, (byte)0);

            Util.arrayCopyNonAtomic(
                in, (short)(inOffset + i * m / 2),
                tmp, (short)0,
                (short)(m / 2)
            );

            Util.arrayCopyNonAtomic(
                tmp, (short)0,
                out, (short)(outOffset + i * m_vec_limbs * 8),
                (short)(m_vec_limbs * 8)
            );
        }
    }

    private void expand_P1_P2(byte[] esk, int P_offset, byte[] seed_pk) {
        aes_ctr_prf(esk, P_offset, P1_BYTES + P2_BYTES, seed_pk);

        int P1_limbs = P1_BYTES / 8;
        int P2_limbs = P2_BYTES / 8;
        int vecs = (P1_limbs + P2_limbs) / M_VEC_LIMBS;

        unpack_m_vecs(esk, P_offset, esk, P_offset, vecs, M);
    }

    private void P1P1t_times_O(byte[] P, int P1_offset, byte[] esk, int O_offset, int L_offset) {
        int bs_mat_entries_used = 0;

        for (short r = 0; r < N_MINUS_O; r++) {
            for (short c = r; c < N_MINUS_O; c++) {

                if (c == r) {
                    bs_mat_entries_used++;
                    continue;
                }

                for (short k = 0; k < O_DIM; k++) {

                    byte o_ck = esk[O_offset + (short)(c * O_DIM + k)];
                    byte o_rk = esk[O_offset + (short)(r * O_DIM + k)];

                    int P1_entry_offset = P1_offset + bs_mat_entries_used * M_VEC_LIMBS * 8;

                    int acc_r_offset = L_offset + (r * O_DIM + k) * M_VEC_LIMBS * 8;

                    int acc_c_offset = L_offset + (c * O_DIM + k) * M_VEC_LIMBS * 8;

                    m_vec_mul_add(M_VEC_LIMBS, P, P1_entry_offset, o_ck, P, acc_r_offset);

                    m_vec_mul_add(M_VEC_LIMBS, P, P1_entry_offset, o_rk, P, acc_c_offset);
                }

                bs_mat_entries_used++;
            }
        }
    }

    public short expandSK(byte[] csk, byte[] esk, short eskOff) {
        int ret = MAYO_OK;
        short checkpoint = 1;

        try {
            byte[] S = new byte[PK_SEED_BYTES + O_BYTES];
            byte[] seed_pk = S;

            // Layout inside esk:
            int P_offset = eskOff;
            int P1_offset = P_offset;
            int L_offset = P_offset + P1_BYTES;
            int O_offset = L_offset + P2_BYTES;

            // shake256 - temporarly replaced by AES-CTR PRF
            aes_ctr_prf(S, 0, PK_SEED_BYTES + O_BYTES, csk);
            checkpoint = 2;

            // decode directly into esk (O part)
            decode(S, PK_SEED_BYTES, esk, O_offset, N_MINUS_O * O_DIM);
            checkpoint = 3;

            // expand directly into esk (P1 + P2 area)
            expand_P1_P2(esk, P1_offset, seed_pk);
            checkpoint = 4;

            // compute L in-place (overwrites P2)
            P1P1t_times_O(esk, P1_offset, esk, O_offset, L_offset);
            checkpoint = 5;

            Util.arrayFillNonAtomic(S, (short)0,
                (short)(PK_SEED_BYTES + O_BYTES),
                (byte)0
            );

        } catch (Exception e) {
            ISOException.throwIt((short)(0x6F00 + checkpoint));
        }

        return (short)(P1_BYTES + P2_BYTES + O_BYTES);
    }
}