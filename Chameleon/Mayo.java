package Chameleon;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class Mayo extends Applet {

    private static final byte INS_INIT = (byte) 0x10;
    private static final byte INS_GET_CERT = (byte) 0x20;
    private static final byte INS_SIGN_DELTA = (byte) 0x40;
    private static final byte INS_GET_SIG_DELTA = (byte) 0x60;
    private static final byte INS_LOAD_PRIVKEY_DELTA = (byte) 0x71;
    private static final byte INS_LOAD_CERT = (byte) 0x72;
    private static final byte INS_LOCK_CARD = (byte) 0x73;
    private static final byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;
    private static final byte INS_DEBUG_GET_ESK = (byte)0x92;
    private static final byte INS_TEST_SAMPLE = (byte)0x93;

    private byte[] eskBuffer = new byte[4096];
    private short eskLen = 0;

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

    protected Mayo() {
        dataToSign = new byte[255];
        certificate = new byte[2048];
        signatureBuffer = new byte[128];

        pqPrivateKey = new byte[2048];
        pqSignature = new byte[512];

        personalized = false;
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Mayo();
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

            case INS_DEBUG_GET_ESK:
                sendESK(apdu);
                return;

            case INS_TEST_SAMPLE:
                testSampleSolution(apdu);
                return;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void testSampleSolution(APDU apdu) {
        MayoSigner signer = new MayoSigner();
        short k = 2;
        short o = 2;
        short m = 4;

        short ko = (short)(k * o);
        short cols = (short)(ko + 1);

        byte[] A = new byte[(short)(m * cols)];
        byte[] y = new byte[m];
        byte[] r = new byte[ko];
        byte[] x = new byte[ko];

        for (short i = 0; i < A.length; i++) {
            A[i] = (byte)((i + 1) & 0x0F);
        }

        for (short i = 0; i < m; i++) {
            y[i] = (byte)((i + 3) & 0x0F);
        }

        for (short i = 0; i < ko; i++) {
            r[i] = (byte)((i + 5) & 0x0F);
        }

        byte[] A_original = new byte[A.length];
        Util.arrayCopy(A, (short)0, A_original, (short)0, (short)A.length);

        short ok = signer.sampleSolution(A, y, r, x, k, o, m, cols);

        if (ok == 0) {
            ISOException.throwIt((short)0x6F01); // failed solving
        }

        byte[] check = new byte[m];
        signer.matMul(A_original, x, check, cols, m);

        for (short i = 0; i < m; i++) {
            if (check[i] != y[i]) {
                ISOException.throwIt((short)0x6F02); // wrong result
            }
        }

        short outLen = ko > 64 ? 64 : ko;

        apdu.setOutgoing();
        apdu.setOutgoingLength(outLen);
        apdu.sendBytesLong(x, (short)0, outLen);
    }

    private void sendESK(APDU apdu) {
        MayoSigner signer = new MayoSigner();

        short status = signer.expandSK(pqPrivateKey, eskBuffer, (short)0);

        if (status != 0) {
            ISOException.throwIt((short)(0x6F00 | (status & 0xFF)));
        }

        eskLen = signer.eskProducedLen;
        short outLen = eskLen > 200 ? 200 : eskLen;

        apdu.setOutgoing();
        apdu.setOutgoingLength(outLen);
        apdu.sendBytesLong(eskBuffer, (short)0, outLen);
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

class MayoSigner {

    private static final short M = 78;
    private static final short N = 86;
    private static final short O = 8;

    private static final short N_MINUS_O = (short)(N - O);
    private static final short O_DIM = O;

    private static final short PK_SEED_BYTES = 16;
    private static final short O_BYTES = (short)(N_MINUS_O * O);
    private static final short P1_BYTES = 512;
    private static final short P2_BYTES = 256;

    private static final short MAYO_OK = 0;

    public short eskProducedLen;

    private void decode(byte[] m, int offset, byte[] mdec, int mdecOffset, int mdeclen) {
        int j = 0;
        int i;
        for (i = 0; i < mdeclen / 2; i++) {
            mdec[mdecOffset + j++] = (byte)(m[offset + i] & 0x0F);
            mdec[mdecOffset + j++] = (byte)((m[offset + i] >> 4) & 0x0F);
        }
        if ((mdeclen % 2) != 0) {
            mdec[mdecOffset + j] = (byte)(m[offset + i] & 0x0F);
        }
    }

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
            aes.doFinal(counter, (short)0, (short)16, block, (short)0);

            short remaining = (short)(outLen - produced);
            short toCopy = (remaining < 16) ? remaining : 16;

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
            if (counter[i] != 0) break;
        }
    }

    private byte gf16_mul(byte x, byte y) {
        byte r = 0;

        for (short i = 0; i < 4; i++) {
            if (((y >> i) & 1) != 0) {
                r ^= x;
            }

            boolean carry = (x & 0x8) != 0;
            x <<= 1;

            if (carry) {
                x ^= 0x13;
            }

            x &= 0x0F;
        }

        return (byte)(r & 0x0F);
    }

    private byte gf16_sub(byte a, byte b) {
        return (byte) (a^b);
    }

    private byte gf16_inv(byte a) {
        for (byte i = 1; i < 16; i++) {
            if (gf16_mul(a, i) == 1) return i;
        }
        return 0; // should never happen
    }

    private void m_vec_mul_add(byte[] data, short dataOffset, byte scalar, short accOffset) {
        short bytesToProcess = (short)(M / 2);

        for (short i = 0; i < bytesToProcess; i++) {
            byte inByte = data[(short)(dataOffset + i)];

            byte x0 = (byte)(inByte & 0x0F);
            byte x1 = (byte)((inByte >> 4) & 0x0F);

            byte y0 = gf16_mul(x0, scalar);
            byte y1 = gf16_mul(x1, scalar);

            byte result = (byte)((y0 & 0x0F) | ((y1 & 0x0F) << 4));

            data[(short)(accOffset + i)] ^= result;
        }
    }

    public void matMul(byte[] A, byte[] x, byte[] result, short cols, short rows) {
        for (short i = 0; i < rows; i++) {
            byte acc = 0;

            for (short j = 0; j < (short)(cols - 1); j++) {
                byte a = A[(short)(i * cols + j)];
                byte prod = gf16_mul(a, x[j]);
                acc ^= prod;
            }

            result[i] = acc;
        }
    }

    private void expand_P1_P2(byte[] esk, int P_offset, byte[] seed_pk) {
        aes_ctr_prf(esk, P_offset, P1_BYTES + P2_BYTES, seed_pk);
    }

    private void P1P1t_times_O(byte[] esk, short P1_offset, short L_offset) {
        short O_offset = (short)(L_offset + P2_BYTES);
        short entries = (short)(P2_BYTES / (M / 2));

        for (short i = 0; i < P2_BYTES; i++) {
            esk[(short)(L_offset + i)] = 0;
        }

        short bs_mat_entries_used = 0;

        for (short r = 0; r < N_MINUS_O && r < entries; r++) {
            for (short c = r; c < N_MINUS_O && c < entries; c++) {

                if (c == r) {
                    bs_mat_entries_used++;
                    continue;
                }

                short P1_entry_offset = (short)(
                        P1_offset + bs_mat_entries_used * (M / 2)
                );

                for (short k = 0; k < O_DIM; k++) {

                    short idx_rk = (short)(r * O_DIM + k);
                    short idx_ck = (short)(c * O_DIM + k);

                    byte o_ck = esk[(short)(O_offset + idx_ck)];
                    byte o_rk = esk[(short)(O_offset + idx_rk)];

                    short acc_r_offset = (short)(
                            L_offset + idx_rk * (M / 2)
                    );

                    short acc_c_offset = (short)(
                            L_offset + idx_ck * (M / 2)
                    );

                    m_vec_mul_add(esk, P1_entry_offset, o_ck, acc_r_offset);
                    m_vec_mul_add(esk, P1_entry_offset, o_rk, acc_c_offset);
                }

                bs_mat_entries_used++;
            }
        }
    }

    public short expandSK(byte[] csk, byte[] esk, short eskOff) {
        byte[] S = new byte[PK_SEED_BYTES + O_BYTES];
        byte[] seed_pk = S;

        int P_offset = eskOff;
        int P1_offset = P_offset;
        int L_offset = P_offset + P1_BYTES;
        int O_offset = L_offset + P2_BYTES;

        aes_ctr_prf(S, 0, PK_SEED_BYTES + O_BYTES, csk);

        decode(S, PK_SEED_BYTES, esk, O_offset, N_MINUS_O * O_DIM);

        expand_P1_P2(esk, P1_offset, seed_pk);

        P1P1t_times_O(esk, (short)P1_offset, (short)L_offset);

        eskProducedLen = (short)(P1_BYTES + P2_BYTES + O_BYTES);

        return MAYO_OK;
    }

    private void gaussianElimination(byte[] A, short m, short cols) {
        short pivotRow = 0;

        for (short col = 0; col < (short)(cols - 1) && pivotRow < m; col++) {

            // find pivot
            short pivot = -1;
            for (short r = pivotRow; r < m; r++) {
                if (A[(short)(r * cols + col)] != 0) {
                    pivot = r;
                    break;
                }
            }

            if (pivot == -1) continue;

            // swap rows
            if (pivot != pivotRow) {
                for (short c = 0; c < cols; c++) {
                    byte tmp = A[(short)(pivotRow * cols + c)];
                    A[(short)(pivotRow * cols + c)] =
                        A[(short)(pivot * cols + c)];
                    A[(short)(pivot * cols + c)] = tmp;
                }
            }

            
            byte pivotVal = A[(short)(pivotRow * cols + col)];
            byte inv = gf16_inv(pivotVal);

            for (short c = col; c < cols; c++) {
                A[(short)(pivotRow * cols + c)] =
                    gf16_mul(A[(short)(pivotRow * cols + c)], inv);
            }

            // eliminate below
            for (short r = (short)(pivotRow + 1); r < m; r++) {
                byte factor = A[(short)(r * cols + col)];
                if (factor == 0) continue;

                for (short c = col; c < cols; c++) {
                    byte prod = gf16_mul(
                        factor,
                        A[(short)(pivotRow * cols + c)]
                    );
                    A[(short)(r * cols + c)] ^= prod;
                }
            }

            pivotRow++;
        }
    }

    public short sampleSolution (byte[] A, byte[] y, byte[] r, byte[] x, short k, short o, short m, short A_cols) {
        short ko = (short) (k * o); 
        
        // x <- r
        Util.arrayCopy(r, (short) 0, x, (short) 0, ko);

        // compute Ar 
        byte[] Ar = new byte[m];

        for (short i = 0; i < m; i++) {
            A[(short) (ko + i * A_cols)] = 0;
        }

        // todo
        matMul(A, r, Ar, A_cols, m);

        // last column = y - Ar
        for(short i = 0; i < m; i++) {
            A[(short)(ko + i * A_cols)] = (byte)(y[i] ^ Ar[i]);
        }

        gaussianElimination(A, m, A_cols);

        byte fullRank = 0;
        for(short i = 0; i < (short)(A_cols - 1); i++) {
            fullRank |= A[(short)((m-1) * A_cols + i)];
        }
        if(fullRank == 0) {
            return 0;
        }

        // back substitution
        for(short row = (short) (m-1); row >= 0; row--) {
            short pivotCol = -1;

            for(short col = row; col < ko; col++) {
                if(A[(short)(row * A_cols + col)] != 0) {
                    pivotCol = col;
                    break;
                }
            }
            if(pivotCol == -1) {
                return 0;
            }

            byte u = A[(short) (row*A_cols + (A_cols - 1))];

            x[pivotCol] ^= u;

            for(short i = 0; i < row; i++) {
                byte a = A[(short) (i*A_cols + pivotCol)];
                byte prod = gf16_mul(a, u);

                short idx = (short)(i*A_cols + (A_cols - 1));
                A[idx] ^= prod;
            }
        }
        return 1;
    }
}