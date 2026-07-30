package com.test;

import javacard.framework.*; // Applet class
import javacard.security.*; // Cryptographic operations

public class ChameleonECDSAApplet extends Applet {
     // APDU command buffers
    private static final byte INS_INIT = (byte) 0x00; // Initializes/resets session state
    private static final byte INS_GET_ISSUER_CERT = (byte) 0x10; // Returns the stored Issuer Certificate
    private static final byte INS_GET_CERT = (byte) 0x20; // Returns the stored ICC Certificate
    private static final byte INS_SIGN_BASE = (byte) 0x30; // Creates the classical signature
    private static final byte INS_SIGN_DELTA = (byte) 0x40; // Creates the second classical signature
    private static final byte INS_GET_SIG_BASE = (byte) 0x50; // Returns the computed classical signature
    private static final byte INS_GET_SIG_DELTA = (byte) 0x60; // Returns the computed delta signature 

    // Personalization commands
    private static final byte INS_LOAD_PRIVKEY_BASE = (byte) 0xB0; // Load ICC ECDSA private key 
    private static final byte INS_LOAD_PRIVKEY_DELTA = (byte) 0xB1; // Load ICC ECDSA private key 
    private static final byte INS_LOAD_ISSUER_CERT = (byte) 0xB2; // Load issuer certificate
    private static final byte INS_LOAD_CERT = (byte) 0xB3; // Load ICC certificate
    private static final byte INS_LOCK_CARD = (byte) 0xB4; // Lock card

    // Internal authenticate command
    private static final byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88; // Create the data to be signed

    private byte[] dataToSign; // data to be signed
    private short dataToSignLen;

    // Classical values 
    private ECPrivateKey classicalPrivateKey; // on card
    private Signature classicalSignature; 
    private short classicalSigLen;
    private byte[] classicalSigBuffer;

    // Second ECDSA signature (hybrid mode)
    private ECPrivateKey secondPrivateKey; // on card
    private byte[] deltaSigBuffer;
    private short deltaSigLen;

    // Certificate storage
    private byte[] issuerCertificate; // stored on card
    private short issuerCertLen;
    private byte[] certificate; // stored on card
    private short certLen;

    // Prevents modification of credentials after personalization
    private boolean personalized;

    // Temporary key pair used only to obtain EC domain parameters accepted by the card implementation
    KeyPair kp = new KeyPair(
            KeyPair.ALG_EC_FP,
            KeyBuilder.LENGTH_EC_FP_192
        );

    protected ChameleonECDSAApplet() {
        // Working buffers
        dataToSign = new byte[255];
        certificate = new byte[2048];
        issuerCertificate = new byte[2048];

        // Create empty EC private key object
        classicalPrivateKey = (ECPrivateKey) KeyBuilder.buildKey( KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_192, false);
        secondPrivateKey = (ECPrivateKey) KeyBuilder.buildKey( KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_192, false);
        classicalSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
        classicalSigBuffer = new byte[128];

        // Create key and signature cotainers for
        deltaSigBuffer = new byte[128];

        personalized = false;
        register(); // Makes the applet selectable 
    }

    // Called once during applet installation on the card
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ChameleonECDSAApplet();
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
        // Private key may only be loaded during personalization
        if (personalized)
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        // Load externally generated private scalar d
        classicalPrivateKey.setS(buf, (short) ISO7816.OFFSET_CDATA, len);
        // Generate a temporary EC key pair.
        kp.genKeyPair();

        ECPrivateKey gen = (ECPrivateKey)kp.getPrivate();

        byte[] tmp = new byte[80];

        short lenn;

        // Copy EC domain parameters from the generated key into the imported key object.
        lenn = gen.getField(tmp,(short)0);
        classicalPrivateKey.setFieldFP(tmp,(short)0,lenn);

        lenn = gen.getA(tmp,(short)0);
        classicalPrivateKey.setA(tmp,(short)0,lenn);

        lenn = gen.getB(tmp,(short)0);
        classicalPrivateKey.setB(tmp,(short)0,lenn);

        lenn = gen.getG(tmp,(short)0);
        classicalPrivateKey.setG(tmp,(short)0,lenn);

        lenn = gen.getR(tmp,(short)0);
        classicalPrivateKey.setR(tmp,(short)0,lenn);
    }

    private void loadPrivateKeyDelta(APDU apdu) {
        // Private key may only be loaded during personalization
        if (personalized)
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        // Load externally generated private scalar d
        secondPrivateKey.setS(buf, (short) ISO7816.OFFSET_CDATA, len);
        // Generate a temporary EC key pair.
        kp.genKeyPair();

        ECPrivateKey gen = (ECPrivateKey)kp.getPrivate();

        byte[] tmp = new byte[80];
        short lenn;

        // Copy EC domain parameters from the generated key into the imported key object.
        lenn = gen.getField(tmp,(short)0);
        secondPrivateKey.setFieldFP(tmp,(short)0,lenn);

        lenn = gen.getA(tmp,(short)0);
        secondPrivateKey.setA(tmp,(short)0,lenn);

        lenn = gen.getB(tmp,(short)0);
        secondPrivateKey.setB(tmp,(short)0,lenn);

        lenn = gen.getG(tmp,(short)0);
        secondPrivateKey.setG(tmp,(short)0,lenn);

        lenn = gen.getR(tmp,(short)0);
        secondPrivateKey.setR(tmp,(short)0,lenn);
    }

    private void loadIssuerCertificate(APDU apdu) {
        // Certificate may only be loaded during personalization
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
        // Certificate may only be loaded during personalization
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

    // Finalize personalization.
    // After this point no credentials or certificates may be modified.
    private void lockCard() {
        personalized = true;
    }

    // Clear data from a previous authentication session
    private void initSession(APDU apdu) {
        classicalSigLen = 0;
        deltaSigLen = 0;
        dataToSignLen = 0;
    }

    // Construct the message that will be authenticated.
    // Structure:
    // Header || Dynamic Data || Padding || Terminal Challenge
    // The resulting 255-byte message is later signed using ECDSA.
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

    // Generate ECDSA signature over the assembled authentication data
    private void createSignatureBase(APDU apdu) {
        classicalSignature.init(classicalPrivateKey, Signature.MODE_SIGN);
        classicalSigLen = classicalSignature.sign(dataToSign, (short) 0, dataToSignLen, classicalSigBuffer, (short) 0);
    }

    // Generate ECDSA signature over the assembled authentication data
    private void createSignatureDelta(APDU apdu) {
        classicalSignature.init(secondPrivateKey, Signature.MODE_SIGN);
        deltaSigLen = classicalSignature.sign(dataToSign, (short) 0, dataToSignLen, deltaSigBuffer,(short) 0);
    }

    // Return certificate data in chunks.
    // The host repeatedly requests blocks until the entire certificate has been transferred.
    private void sendIssuerCertificate(APDU apdu) {
        if (issuerCertLen == 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] buf = apdu.getBuffer();
        short offset = (short)(((buf[ISO7816.OFFSET_P1] & 0xFF) << 8) |  (buf[ISO7816.OFFSET_P2] & 0xFF));
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
        short offset = (short)(((buf[ISO7816.OFFSET_P1] & 0xFF) << 8) |  (buf[ISO7816.OFFSET_P2] & 0xFF));
        if (offset >= certLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short remaining = (short) (certLen - offset);
        short chunk = remaining > 200 ? 200 : remaining;

        apdu.setOutgoing();
        apdu.setOutgoingLength(chunk);
        apdu.sendBytesLong(certificate, offset, chunk);
    }

    // Return the generated ECDSA signature to the terminal
    private void sendSignatureBase(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength(classicalSigLen);
        apdu.sendBytesLong(classicalSigBuffer, (short) 0, classicalSigLen);
    }

    // Return the generated HAWK signature to the terminal
    private void sendSignatureDelta(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength(deltaSigLen);
        apdu.sendBytesLong(deltaSigBuffer, (short) 0, deltaSigLen);

    }
}
