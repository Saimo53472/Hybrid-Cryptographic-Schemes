package Chameleon;

import javacard.framework.*; // Applet class
import javacard.security.*; // Cryptographic operations
import javacardx.crypto.*; // Extended cryptographic operations

public class ChameleonClassicApplet extends Applet {

    // Commands that can be sent from the terminal to control the applet behavior
    private static final byte INS_INIT = (byte) 0x10; // Initializes/resets session state
    private static final byte INS_GET_CERT = (byte) 0x20; // Returns the stored Certificate
    private static final byte INS_SIGN_BASE = (byte) 0x30; // Creates the ECDSA signature
    private static final byte INS_SIGN_RSA = (byte) 0x40; // Creates the RSA signature
    private static final byte INS_GET_SIG_BASE = (byte) 0x50; // Returns the computed ECDSA signature
    private static final byte INS_GET_SIG_RSA = (byte) 0x60; // Returns the computed RSA signature 

    private static final byte INS_LOAD_PRIVKEY_BASE = (byte) 0x70; 
    private static final byte INS_LOAD_PRIVKEY_RSA = (byte) 0x71; 
    private static final byte INS_LOAD_CERT = (byte) 0x72;
    private static final byte INS_LOCK_CARD = (byte) 0x73;

    private static final byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;

    private byte[] dataToSign; // data to be signed
    private short dataToSignLen;
    private static final short TOTAL_LEN = 255; // total length of data to be signed (including padding)

    // ECDSA values 
    private ECPrivateKey classicalPrivateKey; // on card
    private Signature classicalSignature; 

    // RSA values
    private RSAPrivateKey rsaPrivateKey;
    private Signature rsaSignature; 

    // Certificate storage
    private byte[] certificate; // stored on card
    private short certLen;

    // Temporary APDU buffer - communication
    private byte[] buffer;

    private byte[] rsaModulusBuffer = new byte[256];
    private short rsaModulusLen = 0;

    private byte[] rsaExponentBuffer = new byte[256];
    private short rsaExponentLen = 0;


    private byte[] signatureBuffer;
    private short signatureLen;

    private boolean personalized;
    private RandomData random;
    private byte[] iccDynamicData = new byte[8];

    protected ChameleonClassicApplet() {
        dataToSign = new byte[255];
        certificate = new byte[2048];
        signatureBuffer = new byte[256];

        classicalPrivateKey = (ECPrivateKey) KeyBuilder.buildKey( KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        classicalSignature = Signature.getInstance( Signature.ALG_ECDSA_SHA_256, false);

        rsaPrivateKey = (RSAPrivateKey) KeyBuilder.buildKey( KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_1024, false);
        rsaSignature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);

        personalized = false;
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        register(); // makes the applet selectable 
    }

    // Called once during applet installation on the card
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ChameleonClassicApplet();
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

            case INS_SIGN_RSA:
                createSignatureRSA(apdu);
                return;

            case INS_GET_SIG_BASE:
                sendSignatureBase(apdu);
                return;

            case INS_GET_SIG_RSA:
                sendSignatureRSA(apdu);
                return;

            case INS_LOAD_PRIVKEY_BASE:
                loadPrivateKeyBase(apdu);
                return;

            case INS_LOAD_PRIVKEY_RSA:
                loadPrivateKeyRSA(apdu);
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

    private void loadPrivateKeyRSA(APDU apdu) {
        if (personalized)
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        byte p1 = buf[ISO7816.OFFSET_P1];

        if (p1 == 0x00) {
            // modulus
            Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, rsaModulusBuffer, rsaModulusLen, len);
            rsaModulusLen += len;
        } else if (p1 == 0x01) {
            // exponent
            Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, rsaExponentBuffer, rsaExponentLen, len);
            rsaExponentLen += len;
        } else if (p1 == 0x02) {
            rsaPrivateKey.setModulus(rsaModulusBuffer, (short)0, rsaModulusLen);
            rsaPrivateKey.setExponent(rsaExponentBuffer, (short)0, rsaExponentLen);

            rsaModulusLen = 0;
            rsaExponentLen = 0;
        }
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
        byte[] dataToSign = this.dataToSign;
        short pos = 0;

        dataToSign[pos++] = 0x05;
        dataToSign[pos++] = 0x01;
        dataToSign[pos++] = 0x08;

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

        // challenge (from terminal in real EMV, but hardcoded here)
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

    private void createSignatureRSA(APDU apdu) {
        try {
            rsaSignature.init(rsaPrivateKey, Signature.MODE_SIGN);

            signatureLen = rsaSignature.sign(
                dataToSign,
                (short) 0,
                dataToSignLen,
                signatureBuffer,
                (short) 0
            );

        } catch (CryptoException e) {
            ISOException.throwIt((short)(0x6F00 | e.getReason()));
        }
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

    private void sendSignatureRSA(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength(signatureLen);
        apdu.sendBytesLong(signatureBuffer, (short) 0, signatureLen);
    }
}