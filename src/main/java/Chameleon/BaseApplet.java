package Chameleon;

import javacard.framework.*; // Applet class
import javacard.security.*; // Cryptographic operations

public class BaseApplet extends Applet {

    // Commands that can be sent from the terminal to control the applet behavior
    private static final byte INS_INIT = (byte) 0x10; // Initializes/resets session state
    private static final byte INS_GET_ISSUER_CERT = (byte) 0x20; // Returns the stored Issuer Certificate
    private static final byte INS_GET_CERT = (byte) 0x30; // Returns the stored ICC Certificate
    private static final byte INS_SIGN = (byte) 0x40; // Creates the ECDSA signature
    private static final byte INS_GET_SIG = (byte) 0x50; // Returns the computed ECDSA signature

    private static final byte INS_LOAD_PRIVKEY = (byte) 0x70;
    private static final byte INS_LOAD_ISSUER_CERT = (byte) 0x71; 
    private static final byte INS_LOAD_CERT = (byte) 0x72;
    private static final byte INS_LOCK_CARD = (byte) 0x73;

    private static final byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;

    private byte[] dataToSign; // data to be signed
    private short dataToSignLen;

    // ECDSA values 
    private ECPrivateKey classicalPrivateKey; // on card
    private Signature classicalSignature; 

    // Certificate storage
    private byte[] issuerCertificate; // stored on card
    private short issuerCertLen;
    private byte[] certificate; // stored on card
    private short certLen;

    private byte[] signatureBuffer;
    private short signatureLen;

    private boolean personalized;

    protected BaseApplet() {
        dataToSign = new byte[255];
        certificate = new byte[2048];
        issuerCertificate = new byte[2048];
        signatureBuffer = new byte[128];

        classicalPrivateKey = (ECPrivateKey) KeyBuilder.buildKey( KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        classicalSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

        personalized = false;
        register(); // makes the applet selectable 
    }

    // Called once during applet installation on the card
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new BaseApplet();
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

            case INS_GET_ISSUER_CERT:
                sendIssuerCertificate(apdu);
                return;

            case INS_GET_CERT:
                sendCertificate(apdu);
                return;
            
            case INS_SIGN:
                createSignatureBase(apdu);
                return;

            case INS_GET_SIG:
                sendSignatureBase(apdu);
                return;

            case INS_LOAD_PRIVKEY:
                loadPrivateKeyBase(apdu);
                return;

            case INS_LOAD_ISSUER_CERT:
                loadIssuerCertificate(apdu);
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

    private void loadIssuerCertificate(APDU apdu) {
        if (personalized)
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        if (buf[ISO7816.OFFSET_P1] == 0x00) {
            issuerCertLen = 0;
        }

        Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, issuerCertificate, issuerCertLen, len);
        issuerCertLen += len;
    }

    private void loadCertificate(APDU apdu) {
        if (personalized)
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        if (buf[ISO7816.OFFSET_P1] == 0x00) {
            certLen = 0;
        }

        Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, certificate, certLen, len);
        certLen += len;
    }

    private void lockCard() {
        personalized = true;
    }

    private void initSession(APDU apdu) {
        signatureLen = 0;
        dataToSignLen = 0;
    }

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
        signatureLen = classicalSignature.sign(dataToSign, (short) 0, dataToSignLen, signatureBuffer, (short) 0);
    }

    private void sendIssuerCertificate(APDU apdu) {

        if (issuerCertLen == 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buf = apdu.getBuffer();

        short offset = (short) (
            ((buf[ISO7816.OFFSET_P1] & 0xFF) << 8) |
            (buf[ISO7816.OFFSET_P2] & 0xFF)
        );

        if (offset >= issuerCertLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short remaining = (short) (issuerCertLen - offset);
        short chunk = remaining > 200 ? 200 : remaining;

        apdu.setOutgoing();
        apdu.setOutgoingLength(chunk);
        apdu.sendBytesLong(issuerCertificate, offset, chunk);
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
}