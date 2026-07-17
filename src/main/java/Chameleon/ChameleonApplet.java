package Chameleon;

import javacard.framework.*; // Applet class
import javacard.security.*; // Cryptographic operations

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

    private byte[] dataToSign; // data to be signed
    private short dataToSignLen;

    // Classical values 
    private ECPrivateKey classicalPrivateKey; // on card
    private Signature classicalSignature; 
    private short classicalSigLen;
    private byte[] classicalSigBuffer;

    // Post-Quantum values
    private byte[] pqPrivateKey; // on card 
    private byte[] pqSignature; 
    private short pqSignatureLen;

    private short pqKeyOffset = 0;
    private short pqKeyLen = 0;

    // Certificate storage
    private byte[] certificate; // stored on card
    private short certLen;

    private boolean personalized;

    protected ChameleonApplet() {
        dataToSign = new byte[255];
        certificate = new byte[2048];

        classicalPrivateKey = (ECPrivateKey) KeyBuilder.buildKey( KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        classicalSignature = Signature.getInstance( Signature.ALG_ECDSA_SHA_256, false);
        classicalSigBuffer = new byte[128];

        pqPrivateKey = new byte[2048];
        pqSignature = new byte[600];

        personalized = false;
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
        pqKeyLen = pqKeyOffset;
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

    private void lockCard() {
        personalized = true;
    }

    private void initSession(APDU apdu) {
        classicalSigLen = 0;
        pqSignatureLen = 0;
        dataToSignLen = 0;
    }

    // private void internalAuthenticate(APDU apdu) {
    //     byte[] local = dataToSign;
    //     short pos = 0;

    //     local[pos++] = 0x05;
    //     local[pos++] = 0x01;
    //     local[pos++] = 0x08;

    //     byte[] dynamic = new byte[] {
    //         (byte)0x6c,(byte)0x55,(byte)0x44,(byte)0x79,
    //         (byte)0x7a,(byte)0x91,(byte)0x11,(byte)0x5d
    //     };

    //     Util.arrayCopy(dynamic, (short) 0, local, pos, (short) 8);
    //     pos += 8;

    //     // padding
    //     short paddingLen = (short) (255 - pos - 4);
    //     for (short i = 0; i < paddingLen; i++) {
    //         local[pos++] = (byte)0xBB;
    //     }

    //     // challenge
    //     local[pos++] = 0x01;
    //     local[pos++] = 0x02;
    //     local[pos++] = 0x03;
    //     local[pos++] = 0x04;

    //     dataToSignLen = pos;
    // }

    private void internalAuthenticate(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte[] local = dataToSign;
        short pos = 0;

        short challengeLen = (short)(buffer[ISO7816.OFFSET_LC] & 0xFF);

        local[pos++] = 0x05;
        local[pos++] = 0x01;
        local[pos++] = 0x08;

        byte[] dynamic = {
            (byte)0x6c, (byte)0x55, (byte)0x44, (byte)0x79,
            (byte)0x7a, (byte)0x91, (byte)0x11, (byte)0x5d
        };

        Util.arrayCopy(dynamic, (short)0, local, pos, (short)dynamic.length);
        pos += (short)dynamic.length;

        // padding
        short paddingLen = (short)(255 - pos - challengeLen);

        for (short i = 0; i < paddingLen; i++) {
            local[pos++] = (byte)0xBB;
        }

        // copy terminal challenge
        Util.arrayCopy(
            buffer,
            ISO7816.OFFSET_CDATA,
            local,
            pos,
            challengeLen
        );
        pos += challengeLen;
        dataToSignLen = pos;
    }

    private void createSignatureBase(APDU apdu) {
        classicalSignature.init(classicalPrivateKey, Signature.MODE_SIGN);
        classicalSigLen = classicalSignature.sign(dataToSign, (short) 0, dataToSignLen, classicalSigBuffer, (short) 0);
    }

    private void createSignatureDelta(APDU apdu) {
        if (dataToSignLen == 0)
            ISOException.throwIt(
                    ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        Hawk signer = new Hawk();

        byte[] tmp = new byte[6 * 1024]; 

        int ret = signer.signMessage(9, pqSignature, dataToSign, dataToSignLen, pqPrivateKey, pqKeyLen, tmp,
                tmp.length);

        if (ret == 0) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        pqSignatureLen = Hawk.HAWK_SIG_SIZE(9);
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
        apdu.setOutgoingLength(classicalSigLen);
        apdu.sendBytesLong(classicalSigBuffer, (short) 0, classicalSigLen);
    }

    private void sendSignatureDelta(APDU apdu) {
        byte[] buf = apdu.getBuffer();

        short offset = (short)(
                ((buf[ISO7816.OFFSET_P1] & 0xFF) << 8)
            |  (buf[ISO7816.OFFSET_P2] & 0xFF));

        if (offset >= pqSignatureLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short remaining = (short)(pqSignatureLen - offset);
        short chunk = remaining > 200 ? 200 : remaining;

        apdu.setOutgoing();
        apdu.setOutgoingLength(chunk);
        apdu.sendBytesLong(pqSignature, offset, chunk);
    }
}