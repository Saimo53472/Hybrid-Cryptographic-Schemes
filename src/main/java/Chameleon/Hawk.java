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
                (apduBuffer[ISO7816.OFFSET_INS] == (byte) 0xA4)) {
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

        short offset = (short) (((buf[ISO7816.OFFSET_P1] & 0xFF) << 8) |
                (buf[ISO7816.OFFSET_P2] & 0xFF));

        if (offset >= certLen)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);

        short remaining = (short) (certLen - offset);
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
                (byte) 0x6c, (byte) 0x55, (byte) 0x44, (byte) 0x79,
                (byte) 0x7a, (byte) 0x91, (byte) 0x11, (byte) 0x5d
        };

        Util.arrayCopy(dynamic, (short) 0, local, pos, (short) 8);
        pos += 8;

        short paddingLen = (short) (255 - pos - 4);
        for (short i = 0; i < paddingLen; i++) {
            local[pos++] = (byte) 0xBB;
        }

        local[pos++] = 0x01;
        local[pos++] = 0x02;
        local[pos++] = 0x03;
        local[pos++] = 0x04;

        dataToSignLen = pos;
    }

    private void createSignatureDelta(APDU apdu) {
        if (dataToSignLen == 0)
            ISOException.throwIt(
                    ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] state = new byte[200];
        int[] scratch = new int[120];

        SHAKE256JC shake = new SHAKE256JC(state, scratch);
        HawkSigner signer = new HawkSigner();

        byte[] tmp = new byte[6 * 1024]; // whatever size sign() requires

        int ret = signer.signMessage(9, signatureBuffer, dataToSign, dataToSignLen, pqPrivateKey, pqKeyLen, tmp,
                tmp.length);

        if (ret == 0) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        signatureLen = HawkSigner.HAWK_SIG_SIZE(9);
    }

    private void sendSignatureDelta(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength(signatureLen);
        apdu.sendBytesLong(signatureBuffer, (short) 0, signatureLen);
    }
}

class HawkSigner {
    // Parameters
    private int q;
    private int logn;
    private int n;
    private static final int Q;
    private static final int R2;
    private int maxLogn;
    private short saltLen;
    private int maxXnorm;
    private RandomData random;
    private static final short[] GM = new short[] {
            4564, 17110, 12162, 16208, 10701, 9705, 3451, 5078,
            12400, 10202, 8245, 13131, 4631, 3492, 17179, 5622,
            5537, 3399, 2485, 9938, 345, 14064, 10152, 789,
            5092, 15713, 12632, 6516, 16107, 2314, 15385, 17281,
            383, 5515, 5019, 13218, 3293, 4728, 9704, 14263,
            4417, 218, 16011, 2568, 5635, 8516, 18352, 12887,
            13102, 15257, 14316, 12813, 8886, 11051, 13356, 15353,
            12059, 6880, 17926, 11710, 8052, 1737, 16384, 18094,
            3410, 14787, 13788, 14210, 2656, 17550, 7950, 4311,
            18150, 4973, 11548, 7848, 15326, 15517, 97, 11648,
            17990, 17685, 10847, 14695, 282, 1558, 6535, 10743,
            2399, 181, 10165, 8051, 12204, 18401, 13377, 7233,
            10892, 15728, 15002, 11766, 8462, 15245, 12420, 8613,
            5053, 12360, 17415, 12678, 4606, 870, 8429, 9572,
            6542, 1892, 4008, 17045, 371, 10155, 819, 15114,
            1522, 13638, 16576, 17586, 16840, 7671, 13873, 12065,
            7433, 7599, 2497, 5298, 16406, 3443, 9437, 6905,
            14589, 17851, 209, 17496, 1698, 7028, 4444, 8211,
            9159, 16089, 16741, 9085, 2658, 4488, 8650, 3995,
            6532, 11903, 508, 192, 4039, 17347, 12742, 6993,
            14812, 17645, 4527, 695, 8380, 16230, 2153, 3136,
            2133, 4725, 9230, 13213, 6548, 18005, 6108, 16097,
            16952, 13519, 16207, 12802, 16047, 7081, 12818, 8328,
            17091, 8927, 9558, 9273, 9301, 10337, 11142, 5082,
            11846, 15508, 17108, 8498, 16135, 3776, 6752, 12857,
            3590, 486, 3056, 4203, 10364, 17125, 14532, 3025,
            18386, 12029, 1983, 7426, 13553, 623, 6269, 15287,
            16399, 12294, 6987, 8011, 1378, 14019, 3042, 3472,
            4734, 12820, 16363, 7781, 3644, 16472, 3523, 14104,
            11521, 18288, 13956, 4549, 6314, 16320, 16373, 16203,
            15299, 7524, 9080, 15914, 17765, 12520, 5829, 13379,
            9482, 7938, 760, 13350, 9526, 15502, 16160, 6398,
            7067, 1655, 3428, 7827, 10564, 1235, 10800, 8291,
            15614, 14755, 8732, 3010, 12821, 7168, 8131, 1912,
            8093, 10461, 12301, 11616, 13947, 8029, 15138, 8334,
            13345, 13462, 7201, 11285, 8232, 5869, 5652, 8087,
            9232, 151, 5425, 15984, 9061, 10972, 874, 6136,
            9299, 4966, 10442, 5398, 6605, 14398, 7625, 7091,
            10974, 14743, 6836, 17243, 504, 7883, 10503, 12533,
            3111, 13658, 1303, 6153, 12791, 335, 16064, 6652,
            14432, 10970, 558, 5436, 300, 13031, 12835, 7899,
            8435, 7252, 2970, 12879, 2786, 16438, 16584, 2204,
            5974, 6467, 7971, 14624, 9637, 9448, 18144, 7293,
            18121, 10042, 1398, 12430, 157, 6881, 18084, 12060,
            5783, 444, 14853, 7936, 13337, 10411, 4401, 12549,
            17699, 1174, 1162, 5374, 3796, 709, 1424, 8521,
            2238, 991, 9114, 15056, 4900, 16221, 731, 18419,
            14885, 1707, 11644, 7594, 14783, 4281, 12810, 5277,
            10528, 15155, 16633, 13979, 5573, 7912, 15085, 4250,
            13224, 11094, 1717, 11970, 4689, 11787, 613, 14891,
            6892, 1734, 15910, 17044, 1022, 16497, 7473, 4421,
            17061, 2094, 17491, 14013, 1872, 13480, 10045, 17585,
            1562, 10460, 12143, 11266, 2168, 15769, 3047, 7683,
            14260, 9889, 14090, 14179, 4404, 11389, 11461, 4622,
            18349, 14047, 7466, 13272, 5005, 12487, 615, 1829,
            13229, 15305, 3467, 11180, 2855, 8191, 3868, 9735,
            18383, 13189, 933, 7900, 18340, 17527, 4316, 14694,
            5680, 9549, 15669, 5777, 17938, 7070, 11080, 4478,
            1466, 10714, 15409, 8001, 7888, 3707, 14283, 7140,
            3046, 14214, 15419, 16423, 18200, 10217, 10615, 18381,
            13138, 1337, 8483, 7125, 6741, 10966, 18359, 4036,
            11656, 2954, 5907, 1652, 12095, 11393, 12093, 6022,
            11472, 6513, 15239, 12291, 16914, 3635, 2907, 373,
            12897, 8503, 16298, 8337, 10348, 11023, 8932, 5553,
            12984, 11729, 9882, 13024, 556, 65, 10270, 4317,
            14404, 9508, 9191, 9860, 14257, 11049, 13040, 14653,
            13038, 9282, 10349, 4492, 6555, 9154, 8558, 14991,
            4583, 3619, 379, 13206, 11105, 7100, 15820, 14978,
            7277, 12620, 3196, 11513, 7268, 16100, 46, 12935,
            10191, 4142, 9281, 11926, 14900, 14340, 16894, 5224,
            9309, 13388, 13942, 3818, 2937, 7206, 14135, 15212,
            7925, 1689, 8800, 1294, 5524, 14570, 16368, 11992,
            9491, 4458, 3910, 11928, 13598, 1656, 3586, 8177,
            13056, 2322, 16649, 1648, 14699, 18328, 1843, 116,
            10016, 4221, 3330, 2710, 5358, 11169, 13567, 1354,
            8715, 3439, 8805, 5505, 10680, 17825, 14534, 8396,
            4185, 3904, 8543, 2358, 13314, 13160, 14784, 16183,
            3842, 13644, 17524, 1253, 13782, 16530, 12687, 15971,
            13700, 17515, 2420, 10494, 7049, 8615, 15561, 10671,
            10485, 1060, 1583, 2340, 6599, 16718, 5525, 8039,
            12196, 15350, 10577, 8497, 16786, 10118, 13406, 2164,
            696, 7375, 3971, 630, 13829, 4501, 10704, 8545,
            8124, 10763, 4718, 6718, 13636, 11540, 16886, 2173,
            13510, 4961, 9652, 3648, 3009, 16232, 2469, 3836,
            4933, 3461, 12281, 13205, 11756, 13442, 4041, 4285,
            3661, 16043, 9473, 11418, 13814, 10301, 5454, 10915,
            8727, 17232, 13005, 3609, 9965, 5508, 3913, 10768,
            11368, 3716, 15705, 10290, 10822, 12073, 8935, 4393,
            3878, 18157, 11691, 13998, 11637, 16445, 17690, 4654,
            12911, 9234, 2765, 6125, 12586, 12014, 18046, 2176,
            17540, 7355, 811, 12063, 17878, 11837, 8513, 13958,
            16653, 12390, 3722, 4745, 7749, 8299, 2499, 10669,
            16214, 3951, 15969, 375, 13937, 18040, 11638, 9914,
            16136, 15678, 7102, 12699, 9368, 15152, 16159, 12929,
            14186, 13925, 6623, 7438, 5741, 16684, 153, 14572,
            14261, 3358, 14440, 14021, 15097, 18043, 12112, 10964,
            5242, 13012, 9833, 1249, 16386, 5032, 2437, 10065,
            1738, 3850, 11, 1891, 3970, 7161, 7025, 17895,
            6303, 14429, 12523, 17941, 6931, 5087, 11127, 10882,
            13926, 16149, 7788, 11652, 8944, 913, 15223, 6189,
            9511, 2869, 10910, 8768, 6262, 5705, 16606, 5986,
            10784, 2189, 14068, 10397, 14897, 15500, 15844, 5698,
            5743, 3622, 853, 14256, 9576, 2313, 15227, 16931,
            3810, 1440, 6324, 6309, 3400, 6365, 10288, 15790,
            16146, 5667, 10602, 11119, 5700, 7960, 4236, 2617,
            12801, 8757, 1131, 5072, 16068, 17394, 1735, 5010,
            2908, 12275, 3985, 1361, 17206, 13615, 12942, 9536,
            12505, 6468, 8129, 14974, 2983, 1708, 11802, 7944,
            17712, 8436, 5712, 3320, 13774, 13479, 9887, 17235,
            4487, 3873, 3645, 9941, 16825, 13471, 8623, 14435,
            5656, 396, 7269, 9569, 935, 13271, 13889, 18167,
            6320, 14000, 40, 15255, 4382, 7607, 3761, 8098,
            15702, 11450, 2666, 7539, 13722, 2864, 10120, 7018,
            11627, 8023, 14190, 6234, 15359, 2757, 11647, 6434,
            1917, 14513, 7362, 10475, 985, 82, 12956, 10267,
            10798, 2920, 535, 8185, 17135, 16491, 6525, 2321,
            11245, 14410, 9521, 11291, 4326, 4683, 2594, 16946,
            12878, 3561, 9648, 11339, 9944, 13628, 14996, 14086,
            16837, 8831, 12823, 12539, 2930, 16057, 11685, 16318,
            11722, 14300, 10574, 9657, 17379, 8165, 18193, 635,
            17483, 10962, 17727, 2636, 16666, 1219, 8272, 2691,
            15755, 15534, 2783, 17598, 9028, 5299, 7757, 11350,
            9421, 803, 16276, 4555, 2408, 15134, 13315, 6629,
            2575, 12004, 16466, 17109, 14006, 9793, 17355, 17445,
            9993, 6970, 13713, 6344, 17481, 5591, 17027, 2952,
            268, 827, 1635, 12955, 8609, 13704, 8571, 3820,
            15205, 13149, 13046, 12333, 8005, 13766, 18367, 7087,
            5414, 14093, 14734, 10939, 12282, 6674, 3811, 13342
    };

    // Hawk-512 (logn = 9, n = 512)
    public static final short[] SIG_GAUSS_HI_HAWK_512 = {
            (short) 0x580B, (short) 0x35F9,
            (short) 0x1D34, (short) 0x0DD7,
            (short) 0x05B7, (short) 0x020C,
            (short) 0x00A2, (short) 0x002B,
            (short) 0x000A, (short) 0x0001
    };

    public static final int SG_MAX_HI_HAWK_512 = SIG_GAUSS_HI_HAWK_512.length;

    public static final long[] SIG_GAUSS_LO_HAWK_512 = {
            0x0C27920A04F8F267L, 0x3C689D9213449DC9L,
            0x1C4FF17C204AA058L, 0x7B908C81FCE3524FL,
            0x5E63263BE0098FFDL, 0x4EBEFD8FF4F07378L,
            0x56AEDFB0876A3BD8L, 0x4628BC6B23887196L,
            0x061E21D588CC61CCL, 0x7F769211F07B326FL,
            0x2BA568D92EEC18E7L, 0x0668F461693DFF8FL,
            0x00CF0F8687D3B009L, 0x001670DB65964485L,
            0x000216A0C344EB45L, 0x00002AB6E11C2552L,
            0x000002EDF0B98A84L, 0x0000002C253C7E81L,
            0x000000023AF3B2E7L, 0x0000000018C14ABFL,
            0x0000000000EBCC6AL, 0x000000000007876EL,
            0x00000000000034CFL, 0x000000000000013DL,
            0x0000000000000006L, 0x0000000000000000L
    };

    public static final int[] SIG_GAUSS_LO_HI_HAWK_512 = {
            0x0C27920A, 0x3C689D92,
            0x1C4FF17C, 0x7B908C81,
            0x5E63263B, 0x4EBEFD8F,
            0x56AEDFB0, 0x4628BC6B,
            0x061E21D5, 0x7F769211,
            0x2BA568D9, 0x0668F461,
            0x00CF0F86, 0x001670DB,
            0x000216A0, 0x00002AB6,
            0x000002ED, 0x0000002C,
            0x00000002, 0x00000000,
            0x00000000, 0x00000000,
            0x00000000, 0x00000000,
            0x00000000, 0x00000000
    };

    public static final int[] SIG_GAUSS_LO_LO_HAWK_512 = {
            0x04F8F267, 0x13449DC9,
            0x204AA058, 0xFCE3524F,
            0xE0098FFD, 0xF4F07378,
            0x876A3BD8, 0x23887196,
            0x88CC61CC, 0xF07B326F,
            0x2EEC18E7, 0x693DFF8F,
            0x87D3B009, 0x65964485,
            0xC344EB45, 0xE11C2552,
            0xF0B98A84, 0x253C7E81,
            0x3AF3B2E7, 0x18C14ABF,
            0x00EBCC6A, 0x0007876E,
            0x000034CF, 0x0000013D,
            0x00000006, 0x00000000
    };

    public static final int SG_MAX_LO_HAWK_512 = SIG_GAUSS_LO_HAWK_512.length;

    // Constructor
    public HawkSigner() {
        q = 1;
        logn = 9;
        n = 1 << logn; // 2^logn = 512
        Q = 18433;
        R2 = 806;
        maxLogn = 9;
        saltLen = 24;
        maxXnorm = 8317;
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    }

    // Methods
    // Size calculations for private key and signature
    private static short HAWK_PRIVKEY_SIZE(int logn) {
        int n = 1 << logn;
        return (short) (8 + (1 << (logn - 5)) + 2 * (n >> 3) + (n >> 4));
    }

    public static short HAWK_SIG_SIZE(int logn) {
        return (short) (249 + 306 * (2 >> (10 - logn)) + 360 * (1 >> (10 - logn)));
    }

    /**
     * Hamming weight of a byte (number of 1 bits)
     */
    private static byte popcount8(byte x) {
        short v = (short) (x & 0xFF);

        v = (short) ((v & 0x55) + ((v >>> 1) & 0x55));
        v = (short) ((v & 0x33) + ((v >>> 2) & 0x33));
        v = (short) ((v & 0x0F) + ((v >>> 4) & 0x0F));

        return (byte) v;
    }

    /**
     * Regenerate f and g polynomials from seed using SHAKE256
     */
    public void regen_fg(byte[] f, short fOff, byte[] g, short gOff, byte[] seed) {
        byte[] state = new byte[200];
        int[] scratch = new int[120];
        for (byte j = 0; j < 4; j++) {
            SHAKE256JC shake = new SHAKE256JC(state, scratch);
            shake.absorbXor(seed, (short) 0, (short) 24);

            byte[] singleByte = new byte[1];
            singleByte[0] = j;
            shake.absorbXor(singleByte, (short) 0, (short) 1);

            shake.finalizeSqueeze();

            for (short u = 0; u < 1024; u += 32) {
                byte[] qb = new byte[8];
                shake.squeezeBytes(qb, (short) 0, (short) 8);

                for (short i = 0; i < 8; i++) {
                    byte coeff = (byte) (popcount8(qb[i]) - 4);

                    if (u < 512) {
                        f[(short) (fOff + u + (j << 3) + i)] = coeff;
                    } else {
                        g[(short) (gOff + (u - 512) + (j << 3) + i)] = coeff;
                    }
                }
            }
        }
    }

    // Encode 32-bit integer as little-endian bytes
    public static void enc32le(byte[] dst, int dstOffset, int x) {
        dst[dstOffset] = (byte) (x & 0xFF);
        dst[dstOffset + 1] = (byte) ((x >>> 8) & 0xFF);
        dst[dstOffset + 2] = (byte) ((x >>> 16) & 0xFF);
        dst[dstOffset + 3] = (byte) ((x >>> 24) & 0xFF);
    }

    private static int dec32le(byte[] src, int off) {
        return (src[off] & 0xFF)
                | ((src[off + 1] & 0xFF) << 8)
                | ((src[off + 2] & 0xFF) << 16)
                | ((src[off + 3] & 0xFF) << 24);
    }

    private static int dec16le(byte[] src, int off) {
        return (src[off] & 0xFF)
                | ((src[off + 1] & 0xFF) << 8);
    }

    /*
     * Returns 1 iff a < b when interpreted as unsigned ints.
     */
    private static int uLessThan(int a, int b) {
        return ((a ^ 0x80000000) < (b ^ 0x80000000)) ? 1 : 0;
    }

    // Extract the lowest bit of each coefficient
    private static void extract_lowbit(int logn, byte[] dst, byte[] src) {
        int n = 1 << logn;
        for (int i = 0; i < n; i += 8) {
            byte val = 0;
            for (int j = 0; j < 8; j++) {
                val |= ((src[i + j] & 1) << j);
            }
            dst[i >> 3] = val;
        }
    }

    static short tbmask(short x) {
        return (short) (x >> 15);
    }

    static int tbmaskInt(int x) {
        return x >> 31;
    }

    // Constants for sizes
    public static final int SIZE_64 = 64;
    public static final int SIZE_128 = 128;
    public static final int SIZE_256 = 256;
    public static final int SIZE_512 = 512;

    // Precomputed byte lengths
    private static final int BYTES_64 = SIZE_64 / 8;
    private static final int BYTES_128 = SIZE_128 / 8;

    private static void mul64(int a, int b, int[] out, int off) {
        int a0 = a & 0xFFFF;
        int a1 = a >>> 16;

        int b0 = b & 0xFFFF;
        int b1 = b >>> 16;

        int p00 = a0 * b0;
        int p01 = a0 * b1;
        int p10 = a1 * b0;
        int p11 = a1 * b1;

        int middle = (p00 >>> 16)
                + (p01 & 0xFFFF)
                + (p10 & 0xFFFF);

        int lo = (p00 & 0xFFFF)
                | ((middle & 0xFFFF) << 16);

        int hi = p11
                + (p01 >>> 16)
                + (p10 >>> 16)
                + (middle >>> 16);

        out[off] = hi;
        out[off + 1] = lo;
    }

    public static void bpXor64(byte[] d, int dOffset,
            byte[] a, int aOffset,
            byte[] b, int bOffset) {
        int lo = dec32le(a, aOffset)
                ^ dec32le(b, bOffset);

        int hi = dec32le(a, aOffset + 4)
                ^ dec32le(b, bOffset + 4);

        enc32le(d, dOffset, lo);
        enc32le(d, dOffset + 4, hi);
    }

    public static void bpMul32(
            int x,
            int y,
            int[] out,
            int off) {
        int x0 = x & 0x11111111;
        int x1 = x & 0x22222222;
        int x2 = x & 0x44444444;
        int x3 = x & 0x88888888;

        int y0 = y & 0x11111111;
        int y1 = y & 0x22222222;
        int y2 = y & 0x44444444;
        int y3 = y & 0x88888888;

        int[] t = new int[2];

        int z0hi = 0;
        int z0lo = 0;

        mul64(x0, y0, t, 0);
        z0hi ^= t[0];
        z0lo ^= t[1];

        mul64(x1, y3, t, 0);
        z0hi ^= t[0];
        z0lo ^= t[1];

        mul64(x2, y2, t, 0);
        z0hi ^= t[0];
        z0lo ^= t[1];

        mul64(x3, y1, t, 0);
        z0hi ^= t[0];
        z0lo ^= t[1];

        int z1hi = 0;
        int z1lo = 0;

        mul64(x0, y1, t, 0);
        z1hi ^= t[0];
        z1lo ^= t[1];

        mul64(x1, y0, t, 0);
        z1hi ^= t[0];
        z1lo ^= t[1];

        mul64(x2, y3, t, 0);
        z1hi ^= t[0];
        z1lo ^= t[1];

        mul64(x3, y2, t, 0);
        z1hi ^= t[0];
        z1lo ^= t[1];

        int z2hi = 0;
        int z2lo = 0;

        mul64(x0, y2, t, 0);
        z2hi ^= t[0];
        z2lo ^= t[1];

        mul64(x1, y1, t, 0);
        z2hi ^= t[0];
        z2lo ^= t[1];

        mul64(x2, y0, t, 0);
        z2hi ^= t[0];
        z2lo ^= t[1];

        mul64(x3, y3, t, 0);
        z2hi ^= t[0];
        z2lo ^= t[1];

        int z3hi = 0;
        int z3lo = 0;

        mul64(x0, y3, t, 0);
        z3hi ^= t[0];
        z3lo ^= t[1];

        mul64(x1, y2, t, 0);
        z3hi ^= t[0];
        z3lo ^= t[1];

        mul64(x2, y1, t, 0);
        z3hi ^= t[0];
        z3lo ^= t[1];

        mul64(x3, y0, t, 0);
        z3hi ^= t[0];
        z3lo ^= t[1];

        z0hi &= 0x11111111;
        z0lo &= 0x11111111;

        z1hi &= 0x22222222;
        z1lo &= 0x22222222;

        z2hi &= 0x44444444;
        z2lo &= 0x44444444;

        z3hi &= 0x88888888;
        z3lo &= 0x88888888;

        out[off] = z0hi | z1hi | z2hi | z3hi;

        out[off + 1] = z0lo | z1lo | z2lo | z3lo;
    }

    public static void bpMuladd64(
            byte[] d, int dOffset,
            byte[] a, int aOffset,
            byte[] b, int bOffset,
            byte[] tmp, int tmpOffset) {
        int a0 = dec32le(a, aOffset);
        int a1 = dec32le(a, aOffset + 4);

        int b0 = dec32le(b, bOffset);
        int b1 = dec32le(b, bOffset + 4);

        int[] c = new int[6];

        bpMul32(a0, b0, c, 0);
        bpMul32(a1, b1, c, 2);
        bpMul32(a0 ^ a1, b0 ^ b1, c, 4);

        c[4] ^= c[0];
        c[5] ^= c[1];

        c[4] ^= c[2];
        c[5] ^= c[3];

        int d0lo = dec32le(d, dOffset);
        int d0hi = dec32le(d, dOffset + 4);

        int d1lo = dec32le(d, dOffset + 8);
        int d1hi = dec32le(d, dOffset + 12);

        d0hi ^= c[0] ^ c[5];
        d0lo ^= c[1];

        d1hi ^= c[2];
        d1lo ^= c[3] ^ c[4];

        enc32le(d, dOffset, d0lo);
        enc32le(d, dOffset + 4, d0hi);

        enc32le(d, dOffset + 8, d1lo);
        enc32le(d, dOffset + 12, d1hi);
    }

    private static void bpXor512(byte[] d, int dOffset, byte[] a, int aOffset, byte[] b, int bOffset) {
        for (int u = 0; u < 64; u++) {
            d[dOffset + u] = (byte) (a[aOffset + u] ^ b[bOffset + u]);
        }
    }

    public static void bpXor128(byte[] d, int dOffset, byte[] a, int aOffset, byte[] b, int bOffset) {
        // Process as two 64-bit chunks
        bpXor64(d, dOffset, a, aOffset, b, bOffset);
        bpXor64(d, dOffset + 8, a, aOffset + 8, b, bOffset + 8);
    }

    // Specialized implementations for better performance
    public static void bpMuladd128(byte[] d, int dOffset,
            byte[] a, int aOffset,
            byte[] b, int bOffset,
            byte[] tmp, int tmpOffset) {
        // Use optimized implementation for 128-bit polynomials
        int t1Offset = tmpOffset;
        int t2Offset = t1Offset + BYTES_128;

        // Karatsuba algorithm for 128-bit polynomials (split into 64-bit halves)
        bpXor64(tmp, t2Offset, a, aOffset, a, aOffset + BYTES_64); // a0 + a1
        bpXor64(tmp, t2Offset + BYTES_64, b, bOffset, b, bOffset + BYTES_64); // b0 + b1

        // t1 = (a0+a1)*(b0+b1) + d0 + d1
        bpXor128(tmp, t1Offset, d, dOffset, d, dOffset + BYTES_128);
        bpMuladd64(tmp, t1Offset, tmp, t2Offset, tmp, t2Offset + BYTES_64, tmp, t2Offset + BYTES_128);

        // d0 += a0*b0
        bpMuladd64(d, dOffset, a, aOffset, b, bOffset, tmp, t2Offset);

        // d1 += a1*b1
        bpMuladd64(d, dOffset + BYTES_128, a, aOffset + BYTES_64, b, bOffset + BYTES_64, tmp, t2Offset);

        // t1 = t1 + d0 + d1 = a0*b1 + a1*b0
        bpXor128(tmp, t1Offset, tmp, t1Offset, d, dOffset);
        bpXor128(tmp, t1Offset, tmp, t1Offset, d, dOffset + BYTES_128);

        // d += (x^64)*t1: d[8:24] ⊕= t1[0:16]
        bpXor128(d, dOffset + BYTES_64, d, dOffset + BYTES_64, tmp, t1Offset);
    }

    private static void bpXor256(byte[] d, int dOffset, byte[] a, int aOffset, byte[] b, int bOffset) {
        for (int u = 0; u < 32; u++) {
            d[dOffset + u] = (byte) (a[aOffset + u] ^ b[bOffset + u]);
        }
    }

    /**
     * Binary polynomial multiplication and accumulation for 256-bit polynomials
     * Uses Karatsuba algorithm with 128-bit halves
     */
    public static void bpMuladd256(byte[] d, int dOffset,
            byte[] a, int aOffset,
            byte[] b, int bOffset,
            byte[] tmp, int tmpOffset) {
        final int n = 256;
        final int hn = 128;
        final int byteLen = n / 8;
        final int halfByteLen = hn / 8;

        // Temporary buffers within the provided tmp array
        int t1Offset = tmpOffset;
        int t2Offset = t1Offset + byteLen;
        int t3Offset = t2Offset + byteLen;

        // t1 <- (a0 + a1)*(b0 + b1) + d0 + d1
        bpXor128(tmp, t2Offset, a, aOffset, a, aOffset + halfByteLen); // a0 + a1
        bpXor128(tmp, t2Offset + halfByteLen, b, bOffset, b, bOffset + halfByteLen); // b0 + b1
        bpXor256(tmp, t1Offset, d, dOffset, d, dOffset + byteLen); // d0 + d1
        bpMuladd128(tmp, t1Offset, tmp, t2Offset, tmp, t2Offset + halfByteLen, tmp, t3Offset);

        // d0 <- d0 + a0*b0
        bpMuladd128(d, dOffset, a, aOffset, b, bOffset, tmp, t3Offset);

        // d1 <- d1 + a1*b1
        bpMuladd128(d, dOffset + byteLen, a, aOffset + halfByteLen, b, bOffset + halfByteLen, tmp, t3Offset);

        // t1 <- t1 + d0 + d1 = a0*b1 + a1*b0
        bpXor256(tmp, t1Offset, tmp, t1Offset, d, dOffset);
        bpXor256(tmp, t1Offset, tmp, t1Offset, d, dOffset + byteLen);

        // d <- d + (x^{n/2})*t1: d[16:48] ⊕= t1[0:32]
        bpXor256(d, dOffset + halfByteLen, d, dOffset + halfByteLen, tmp, t1Offset);
    }

    // Generic XOR for any size
    private static void bpXor(int bitSize, byte[] d, int dOffset, byte[] a, int aOffset, byte[] b, int bOffset) {
        int byteSize = bitSize / 8;
        for (int u = 0; u < byteSize; u++) {
            d[dOffset + u] = (byte) (a[aOffset + u] ^ b[bOffset + u]);
        }
    }

    // Generic binary polynomial multiplication using Karatsuba algorithm
    private static void bpMulmod(int n, int hn, byte[] d, int dOffset,
            byte[] a, int aOffset, byte[] b, int bOffset,
            byte[] tmp, int tmpOffset) {
        int byteLen = n / 8;
        int halfByteLen = hn / 8;

        int t1Offset = tmpOffset;
        int t2Offset = t1Offset + byteLen;

        // t1 <- (a0 + a1)*(b0 + b1)
        bpXor(hn, d, dOffset, a, aOffset, a, aOffset + halfByteLen);
        bpXor(hn, d, dOffset + halfByteLen, b, bOffset, b, bOffset + halfByteLen);
        bpXor(n, tmp, t1Offset, d, dOffset, d, dOffset + halfByteLen);
        Arrays.fill(tmp, t1Offset, t1Offset + byteLen, (byte) 0);
        bpMuladd256(tmp, t1Offset, d, dOffset, d, dOffset + halfByteLen, tmp, t2Offset);

        // d <- a0*b0 + a1*b1
        Arrays.fill(d, dOffset, dOffset + byteLen, (byte) 0);
        bpMuladd256(d, dOffset, a, aOffset, b, bOffset, tmp, t2Offset);
        bpMuladd256(d, dOffset, a, aOffset + halfByteLen, b, bOffset + halfByteLen, tmp, t2Offset);

        // t1 <- t1 + d = a0*b1 + a1*b0
        bpXor(n, tmp, t1Offset, tmp, t1Offset, d, dOffset);

        // d <- d + rotate_{n/2}(t1)
        bpXor(hn, d, dOffset, d, dOffset, tmp, t1Offset + halfByteLen);
        bpXor(hn, d, dOffset + halfByteLen, d, dOffset + halfByteLen, tmp, t1Offset);
    }

    // Basis multiplication modulo 2
    public static void basisM2Mul(int logn, byte[] t0, int t0Offset, byte[] t1, int t1Offset,
            byte[] h0, int h0Offset, byte[] h1, int h1Offset,
            byte[] f2, int f2Offset, byte[] g2, int g2Offset,
            byte[] F2, int F2Offset, byte[] G2, int G2Offset,
            byte[] tmp, int tmpOffset) {

        int n = 1 << logn;
        int byteLen = n >> 3;

        int w1Offset = tmpOffset;
        int w2Offset = w1Offset + byteLen;

        bpMulmod(512, 256, t0, t0Offset, h0, h0Offset, f2, f2Offset, tmp, w2Offset); // still need to resolve
        bpMulmod(512, 256, tmp, w1Offset, h1, h1Offset, F2, F2Offset, tmp, w2Offset);
        bpXor512(t0, t0Offset, t0, t0Offset, tmp, w1Offset);
        bpMulmod(512, 256, t1, t1Offset, h0, h0Offset, g2, g2Offset, tmp, w2Offset);
        bpMulmod(512, 256, tmp, w1Offset, h1, h1Offset, G2, G2Offset, tmp, w2Offset);
        bpXor512(t1, t1Offset, t1, t1Offset, tmp, w1Offset);
    }

    /**
     * Convert a signed byte to a mod q value in the range [0, q-1]
     * This is the equivalent of Zq(set_small)
     */
    public short mq18433SetSmall(byte x) {
        // C formula: uint32_t y = (uint32_t)-x; y += Q & (y >> 16); return Q - y;
        // This returns values in [1..Q] where Q represents 0 mod Q.
        int xInt = (int) x; // sign-extend byte to int
        int y = -xInt; // same bit pattern as C's (uint32_t)-x
        y += Q & (y >>> 16); // unsigned right shift to detect negative (large unsigned) values
        return (short) (Q - y);
    }

    /**
     * Convert a small polynomial (signed 8-bit coefficients) to mod q
     * representation.
     * This is the equivalent of Zq(poly_set_small)
     */
    public void mq18433PolySetSmall(int logn, short[] d, int dOffset, byte[] a, int aOffset) {
        int n = 1 << logn;
        for (int u = 0; u < n; u++) {
            d[dOffset + u] = mq18433SetSmall(a[aOffset + u]);
        }
    }

    /**
     * Modular subtraction: (x - y) mod Q, result in [1..Q] where Q represents 0 mod
     * Q.
     * Matches the C formula: {@code d = y-x; d += Q & (d>>16); return Q-d;}
     */
    public int mq18433Sub(int x, int y) {
        int d = y - x;
        d += Q & (d >> 16);
        return Q - d;
    }

    /**
     * Modular addition: (x + y) mod Q, result in [1..Q] where Q represents 0 mod Q.
     * Matches the C formula: {@code d = Q-(x+y); d += Q & (d>>16); return Q-d;}
     */
    public int mq18433Add(int x, int y) {
        int d = Q - (x + y);
        d += Q & (d >> 16);
        return Q - d;
    }

    /**
     * Montgomery reduction. The Hawk protocol never feeds x == 0 here (NTT/INTT
     * butterfly products in [1..Q] representation, where Q itself represents 0),
     * but the original short-circuit `if (x == 0) return 0;` is a data-dependent
     * branch on a secret-derived intermediate — replaced with a branchless mask
     * to preserve byte-identity while removing the L1 timing channel.
     */
    public int mq18433MontyRed(int x) {
        int xLo = x & 0xFFFF;
        int xHi = x >>> 16;

        int pLL = xLo * 18431;
        int pLH = xLo * 60352;
        int pHL = xHi * 18431;

        int word16 = ((pLL >>> 16) + pLH + pHL) & 0xFFFF;
        int step2 = word16 * Q;
        int result = (step2 >>> 16) + 1;

        int nonzero = -((x | -x) >>> 31);
        return result & nonzero;
    }

    /**
     * Montgomery multiplication: returns (x * y) mod Q in Montgomery form
     */
    public int mq18433MontyMul(int x, int y) {
        return mq18433MontyRed(x * y);
    }

    /**
     * Convert a number to Montgomery form
     */
    public int mq18433ToMonty(int x) {
        return mq18433MontyRed(x * R2);
    }

    /**
     * Number Theoretic Transform (NTT) for modulus 18433
     */
    public void mq18433NTT(int logn, short[] a, int aOffset) {
        if (logn == 0) {
            return;
        }

        int t = 1 << logn;

        for (int lm = 0; lm < logn; lm++) {
            int m = 1 << lm;
            int ht = t >> 1;
            int v0 = 0;

            for (int u = 0; u < m; u++) {
                int s = GM[u + m] & 0xFFFF; // NTT root

                for (int v = 0; v < ht; v++) {
                    int k1 = aOffset + v0 + v;
                    int k2 = k1 + ht;

                    int x1 = a[k1] & 0xFFFF;
                    int x2 = a[k2] & 0xFFFF;

                    // Montgomery multiplication
                    int x2_monty = mq18433MontyMul(x2, s);

                    // Butterfly operation
                    a[k1] = (short) mq18433Add(x1, x2_monty);
                    a[k2] = (short) mq18433Sub(x1, x2_monty);
                }
                v0 += t;
            }
            t = ht;
        }
    }

    public static int mq18433Snorm(int x) {
        int mask = ((Q >> 1) - x) >> 31; // -1 if x > Q/2, 0 otherwise
        return x - (Q & mask);
    }

    /**
     * Apply signed normalization to polynomial coefficients
     */
    public static void mq18433PolySnorm(int logn, short[] d, int dOffset) {
        int n = 1 << logn;
        for (int u = 0; u < n; u++) {
            d[dOffset + u] = (short) mq18433Snorm(d[dOffset + u] & 0xFFFF);
        }
    }

    /**
     * Returned value:
     * 1 first non-zero coefficient of s is positive
     * -1 first non-zero coefficient of s is negative
     * 0 s is entirely zero
     */
    public static int polySymBreak(int logn, short[] s, int sOffset) {
        // Matches C's poly_symbreak exactly:
        // returns 0 if polynomial is all-zero
        // returns 1 if first non-zero coefficient is positive
        // returns -1 (= 0xFFFFFFFF as uint32) if first non-zero coefficient is negative
        // The caller uses ~tbmask(r-1) to decide negation:
        // r=0: tbmask(-1)= -1, ~(-1)=0 -> no negation
        // r=1: tbmask(0) = 0, ~0 =-1 -> negate (positive first coeff -> negate)
        // r=-1: tbmask(-2)= -1, ~(-1)=0 -> no negation (negative first coeff)
        int n = 1 << logn;
        int r = 0;
        int c = 0xFFFFFFFF; // Mask for tracking first non-zero

        for (int u = 0; u < n; u++) {
            int x = s[sOffset + u];
            int nz = c & tbmaskInt(x | -x); // Non-zero mask
            c &= ~nz; // Clear the bit for this coefficient
            r |= nz & (tbmaskInt(x) | 1); // r=1 if positive, r=-1 if negative
        }

        // Return raw r (same bit pattern as C's uint32_t return value):
        // 0 = all-zero, 1 = positive first coeff, -1 (=0xFFFFFFFF) = negative first
        // coeff
        return r;
    }

    /**
     * Generate x with the right Gaussian, for the specified parity bits.
     * This JavaCard version avoids all long arithmetic.
     *
     * Returned value is the squared norm of x.
     */
    public int sigGauss(
        int logn,
        SHAKE256JC shake,
        byte[] x,
        int xOffset,
        byte[] t,
        int tOffset)
    {
        int[] tabLoHi;
        int[] tabLoLo;
        short[] tabHi;

        int hiLen;
        int loLen;

        switch (logn)
        {
        case 9:
            tabHi = SIG_GAUSS_HI_HAWK_512;
            tabLoHi = SIG_GAUSS_LO_HI_HAWK_512;
            tabLoLo = SIG_GAUSS_LO_LO_HAWK_512;
            hiLen = SG_MAX_HI_HAWK_512;
            loLen = SG_MAX_LO_HAWK_512;
            break;

        default:
            throw new IllegalArgumentException(
                "Unsupported logn: " + logn);
        }

        int n = 1 << logn;

        /*
        * Generate the 40-byte seed exactly like
        * the original Hawk implementation.
        */
        byte[] seed = new byte[41];
        byte[] tmp = new byte[40];
        random.nextBytes(seed, 0, 40);

        int sn = 0;

        for (int j = 0; j < 4; j++)
        {
            seed[40] = (byte)j;

            shake.reset();
            shake.absorbXor(seed, 0, 41);
            shake.finalizeSqueeze();

            for (int u = 0; u < (n << 1); u += 16)
            {
                shake.squeezeBytes(tmp, 0, 40);

                for (int k = 0; k < 4; k++)
                {
                    int v = u + (j << 2) + k;

                    int loLo =
                        dec32le(tmp, k * 8);

                    int loHi =
                        dec32le(tmp, (k * 8) + 4);

                    int hi =
                        dec16le(tmp, 32 + (k << 1));

                    /*
                    * Extract sign bit.
                    */
                    int neg = -(loHi >>> 31);

                    loHi &= 0x7FFFFFFF;
                    hi &= 0x7FFF;

                    int pbit =
                        (t[tOffset + (v >>> 3)]
                            >>> (v & 7)) & 1;

                    int pOddw = -pbit;

                    int r = 0;

                    /*
                    * Main comparison loop.
                    */
                    for (int i = 0; i < hiLen; i += 2)
                    {
                        int mask = pOddw;

                        int thi =
                            (tabHi[i] & 0xFFFF)
                            ^ (mask
                            & ((tabHi[i] & 0xFFFF)
                            ^ (tabHi[i + 1] & 0xFFFF));

                        int tloHi =
                            tabLoHi[i]
                            ^ (mask
                            & (tabLoHi[i]
                            ^ tabLoHi[i + 1]));

                        int tloLo =
                            tabLoLo[i]
                            ^ (mask
                            & (tabLoLo[i]
                            ^ tabLoLo[i + 1]));

                        int borrow =
                            uLessThan(loLo, tloLo);

                        int diffHi =
                            loHi - tloHi - borrow;

                        int cc =
                            diffHi >>> 31;

                        int diffHi16 =
                            hi - thi - cc;

                        r += diffHi16 >>> 31;
                    }

                    /*
                    * Remaining entries.
                    */
                    int hinz = (hi - 1) >>> 31;

                    for (int i = hiLen; i < loLen; i += 2)
                    {
                        int mask = pOddw;

                        int tloHi =
                            tabLoHi[i]
                            ^ (mask
                            & (tabLoHi[i]
                            ^ tabLoHi[i + 1]));

                        int tloLo =
                            tabLoLo[i]
                            ^ (mask
                            & (tabLoLo[i]
                            ^ tabLoLo[i + 1]));

                        int borrow =
                            uLessThan(loLo, tloLo);

                        int diffHi =
                            loHi - tloHi - borrow;

                        int cc =
                            diffHi >>> 31;

                        r += hinz & cc;
                    }

                    /*
                    * Enforce parity.
                    */
                    r = (r << 1) - pOddw;

                    /*
                    * Apply sign.
                    */
                    r = (r ^ neg) - neg;

                    x[xOffset + v] = (byte)r;

                    sn += r * r;
                }
            }
        }

        return sn;
    }

    public static boolean encodeSig(int logn, byte[] sig, short sigOffset, short sigLen, byte[] salt, short saltOffset,
            short saltLen, short[] s1, short s1Offset) {
        short n = (short) (1 << logn);
        byte low = (byte) ((logn == 10) ? 6 : 5);

        short bufOffset = sigOffset;
        short remainingLen = (short) sigLen;

        short minSize = (short) (saltLen + (((short) (low + 2)) << (logn - 3)));

        if (remainingLen < minSize) {
            return false;
        }

        // 1. Copy salt
        Util.arrayCopyNonAtomic(salt, saltOffset, sig, bufOffset, saltLen);

        bufOffset += saltLen;
        remainingLen -= saltLen;

        // 2. Sign bits
        short u;
        short v;

        for (u = 0; u < n; u += 8) {

            byte x = 0;

            for (v = 0; v < 8; v++) {
                short coeff = s1[(short) (s1Offset + u + v)];
                byte signBit = (byte) ((coeff >> 15) & 1);
                x |= (byte) (signBit << v);
            }

            sig[(short) (bufOffset + (u >> 3))] = x;
        }

        bufOffset += (short) (n >> 3);
        remainingLen -= (short) (n >> 3);

        // 3. Fixed-size low bits; reimplemented without long.
        short lowMask = (short) ((1 << low) - 1);

        int acc8 = 0; // using int for accumulation to avoid long arithmetic
        short accBits = 0;

        for (u = 0; u < n; u++) {

            short w = s1[(short) (s1Offset + u)];
            short mask = tbmask(w);

            w ^= mask; // abs(w)

            acc8 |= (w & lowMask) << accBits;
            accBits += low;

            while (accBits >= 8) {

                if (remainingLen <= 0) {
                    return false;
                }

                sig[bufOffset++] = (byte) (acc8 & 0xFF);

                acc8 >>>= 8;
                accBits -= 8;
                remainingLen--;
            }
        }

        // 4. Variable-size unary encoding
        int acc = 0;
        short accLen = 0;

        for (u = 0; u < n; u++) {

            short w = s1[(short) (s1Offset + u)];
            short mask = tbmask(w);

            w ^= mask;

            short k = (short) ((w & 0xFFFF) >>> low);

            acc |= (1 << (accLen + k));
            accLen += (short) (1 + k);

            while (accLen >= 8) {

                if (remainingLen <= 0) {
                    return false;
                }

                sig[bufOffset++] = (byte) acc;
                remainingLen--;

                acc >>>= 8;
                accLen -= 8;
            }
        }

        /*
         * Flush remaining bits
         */
        if (accLen > 0) {

            if (remainingLen <= 0) {
                return false;
            }

            sig[bufOffset++] = (byte) acc;
            remainingLen--;
        }

        // 5. Zero padding
        Util.arrayFillNonAtomic(sig, bufOffset, remainingLen, (byte) 0);

        return true;
    }

    public void reset(byte[] state, int[] scratch) {
        for (int i = 0; i < 200; i++) {
            state[i] = 0;
        }

        for (int i = 0; i < 120; i++) {
            scratch[i] = 0;
        }
    }

    // Sign method
    public int sign(int logn, int useShake, byte[] sig, SHAKE256JC shake256jc, byte[] priv, int privLen, byte[] tmp,
            int tmpLen) {
        // Ensure proper alignment for 64-bit access
        if (tmpLen < 7) {
            return 0;
        }
        if (logn < 8 || logn > 10) {
            return 0;
        }

        // Align temporary buffer for 64-bit access
        int utmp1 = 0;
        int utmp2 = (utmp1 + 7) & ~7;
        tmpLen -= (int) (utmp2 - utmp1);

        if (tmpLen < (6 << logn)) {
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

        // Regenerate f and g from seed // DecodePrivate(priv) & Regeneratefg(kgseed)
        byte[] seed = new byte[seedLen];
        Util.arrayCopy(priv, 0, seed, 0, seedLen);
        regen_fg(f, (short) 0, g, (short) 0, seed);
        Util.arrayCopy(priv, seedLen, F2, 0, n >> 3);
        Util.arrayCopy(priv, seedLen + (n >> 3), G2, 0, n >> 3);
        Util.arrayCopy(priv, seedLen + 2 * (n >> 3), hpub, 0, hpubLen);

        // Compute hm = SHAKE256(message || hpub)
        byte[] hm = new byte[64];
        shake256jc.absorbXor(hpub, 0, hpubLen);
        shake256jc.finalizeSqueeze();
        shake256jc.squeezeBytes(hm, 0, 64);

        // Main signing loop
        for (int attempt = 0;; attempt += 2) {
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

            byte[] state = new byte[200];
            int[] scratch = new int[120];

            if (useShake != 0) {
                byte[] tbuf = new byte[4];
                enc32le(tbuf, 0, attempt);

                SHAKE256JC saltShake = new SHAKE256JC(state, scratch);
                saltShake.absorbXor(hm, 0, hm.length);
                saltShake.absorbXor(priv, 0, seedLen);
                saltShake.absorbXor(tbuf, 0, tbuf.length);
                saltShake.absorbXor(salt, 0, saltLen);
                saltShake.finalizeSqueeze();
                saltShake.squeezeBytes(salt, 0, saltLen);
            }

            // Compute h = SHAKE256(hm || salt)
            reset(state, scratch);
            SHAKE256JC hShake = new SHAKE256JC(state, scratch);
            hShake.absorbXor(hm, 0, hm.length);
            hShake.absorbXor(salt, 0, saltLen);
            hShake.finalizeSqueeze();

            // Squeeze h0 and h1 (total n >> 2 bytes)
            hShake.squeezeBytes(ww, h0Offset, n >> 2);

            // Extract low bits and compute t = B*h (mod 2)
            byte[] f2 = new byte[n >> 3];
            byte[] g2 = new byte[n >> 3];
            extract_lowbit(logn, f2, f);
            extract_lowbit(logn, g2, g);

            basisM2Mul(logn,
                    ww, t0Offset, ww, t1Offset, // t0, t1
                    ww, h0Offset, ww, h1Offset, // h0, h1
                    f2, 0, g2, 0, // f2, g2
                    F2, 0, G2, 0, // F2, G2
                    tmp, xxOffset); // tmp space

            // Sample x using Gaussian distribution
            int xsn;
            byte[] tbuf = new byte[4];
            enc32le(tbuf, 0, attempt + 1);

            reset(state, scratch);
            SHAKE256JC gaussShake = new SHAKE256JC(state, scratch);

            gaussShake.reset();
            gaussShake.absorbXor(hm, 0, hm.length);
            gaussShake.absorbXor(priv, 0, seedLen);
            gaussShake.absorbXor(tbuf, 0, tbuf.length);
            gaussShake.finalizeSqueeze();

            xsn = sigGauss(logn, gaussShake, x0, 0, ww, t0Offset);

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
                w1[u] = (short) mq18433MontyMul(w1[u] & 0xFFFF, w2[u] & 0xFFFF);
            }

            // w3 <- f*x1 - g*x0, then INTT to get polynomial
            mq18433PolySetSmall(logn, w2, 0, x0, n); // x1 = x0[n..2n-1]
            mq18433PolySetSmall(logn, w3, 0, f, 0);
            mq18433NTT(logn, w2, 0);
            mq18433NTT(logn, w3, 0);
            for (int u = 0; u < n; u++) {
                w3[u] = (short) mq18433ToMonty(mq18433Sub(
                        mq18433MontyMul(w2[u] & 0xFFFF, w3[u] & 0xFFFF),
                        w1[u] & 0xFFFF));
            }
            mq18433NTT(logn, w3, 0);
            mq18433PolySnorm(logn, w3, 0);

            short[] s1 = w3;

            int ps = polySymBreak(logn, s1, 0);
            int lim = 1 << ((logn == 10) ? 10 : 9);
            short nm = (short) ~tbmask((short) (ps - 1));

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
                s1[u] = (short) y;
            }

            if (reject != 0) {
                continue;
            }

            // Encode signature
            short sigLen = HAWK_SIG_SIZE(logn);
            if (encodeSig(logn, tmp, (short) 0, sigLen, salt, (short) 0, saltLen, s1, (short) 0)) {
                if (sig != null) {
                    Util.arrayCopy(tmp, 0, sig, 0, sigLen);
                }
                return 1;
            }
        }
    }

    public int signMessage(
            int logn,
            byte[] sig,
            byte[] message,
            short messageLen,
            byte[] priv,
            int privLen,
            byte[] tmp,
            int tmpLen) {
        byte[] state = new byte[200];
        int[] scratch = new int[120];

        SHAKE256JC sc = new SHAKE256JC(state, scratch);

        // Equivalent of hawkSignStart(sc)
        sc.reset();

        // Equivalent of sc.update(message, 0, mlen);
        sc.absorbXor(message, 0, messageLen);

        // Equivalent of hawkSignFinish(...)
        return sign(
                logn,
                1,
                sig,
                sc,
                priv,
                privLen,
                tmp,
                tmpLen);
    }
}
