package Chameleon;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

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

    private byte[] dataToSign; // data to be signed
    private short dataToSignLen;

    // Classical values 
    private ECPrivateKey classicalPrivateKey; // on card

    // Post-Quantum values
    private Object pqPrivateKey; // on card 

    // Certificate storage
    private byte[] certificate; // stored on card
    private short certLen;

    // Temporary APDU buffer - communictaion
    private byte[] buffer;

    private byte[] signatureBuffer;
    private short signatureLen;

    private boolean personalized;

    protected ChameleonApplet() {
        dataToSign = new byte[255];
        certificate = new byte[512];
        signatureBuffer = new byte[128];

        classicalPrivateKey = (ECPrivateKey) KeyBuilder.buildKey( KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        classicalSignature = Signature.getInstance( Signature.ALG_ECDSA_SHA_256, false);

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

        if ((apduBuffer[ISO7816.OFFSET_CLA] == 0) && (aopduBuffer[ISO7816.OFFSET_INS] == (byte) (0xA4)) ) // SELECT APDU command
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
                loadPrivateKey(apdu);
                return;

            case INS_LOAD_PRIVKEY_DELTA:
                loadPrivateKey(apdu); // change
                return;

            case INS_LOAD_CERT:
                loadCertificate(apdu);
                return;

            case INS_LOCK_CARD:
                lockCard();
                return;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void loadPrivateKey(APDU apdu) {

        if (personalized)
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        // Loads EC private scalar S
        classicalPrivateKey.setS(
            buf,
            ISO7816.OFFSET_CDATA,
            len
        );
    }

    private void loadCertificate(APDU apdu) {

        if (personalized)
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        Util.arrayCopy(
            buf,
            ISO7816.OFFSET_CDATA,
            certificate,
            (short) 0,
            len
        );
        certLen = len;
    }

    private void lockCard() {
        personalized = true;
    }

    private void initSession(APDU apdu) {
        signatureLen = 0;
        dataToSignLen = 0;
    }

    private void createSignatureBase(APDU apdu) {
        classicalSignature.init(classicalPrivateKey, Signature.MODE_SIGN);
        signatureLen = classicalSignature.sign(data, 0, (short) data.length, signatureBuffer, 0);
        
        apdu.setOutgoing();
        apdu.setOutgoingLength(signatureLen);
        apdu.sendBytes(signatureBuffer, 0, signatureLen);
    }

    private void createSignatureDelta(APDU apdu) {
        pqSignature.init(pqPrivateKey, Signature.MODE_SIGN);
        signatureLen = pqSignature.sign(data, 0, (short) data.length, signatureBuffer, 0);

        apdu.setOutgoing();
        apdu.setOutgoingLength(signatureLen);
        apdu.sendBytes(signatureBuffer, 0, signatureLen);
    }

    // TODO: if the certificate / signature exceeds the buffer size
    private void sendCertificate(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength(certLen);
        apdu.sendBytesLong(certificate, (short) 0, certLen);
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