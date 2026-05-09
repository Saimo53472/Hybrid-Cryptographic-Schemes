package Chameleon;

import java.security.interfaces.ECPublicKey;

import javacard.framework.*; // Applet class
import javacard.security.*; // Cryptographic operations

public class ChameleonApplet extends Applet {

    // Commands that can be sent from the terminal to control the applet behavior
    private static final byte INS_INIT = (byte) 0x10; // Initializes/resets session state
    private static final byte INS_GENERATE_DELTA = (byte) 0x20; // Triggers generation of the Delta Certificate
    private static final byte INS_GET_BASE_CERT = (byte) 0x30; // Returns the stored Base Certificate
    private static final byte INS_GET_DELTA_CERT = (byte) 0x40; // Returns the computed Delta Certificate
    private static final byte INS_SIGN = (byte) 0x50; // Creates the classical signature
    private static final byte INS_SIGN_DELTA = (byte) 0x60; // Creates the post-quantum signature
    private static final byte INS_GET_SIGN = (byte) 0x70; // Returns the computed signature

    // TODO
    // Classical values 
    private ECPrivateKey classicalPrivateKey;
    private ECPublicKey classicalPublicKey;
    private Signature classicalSignature;

    private byte[] signatureBuffer;
    private short signatureLen;

    // Post-Quantum values
    // private Object pqPublicKey;  
    // private Object pqPrivateKey;  
    // private Object pqEngine;      

    // Certificate storage
    private byte[] baseCertificate; // stored on card
    private short baseCertLen;

    private byte[] deltaCertificate; // derived from base certificate + DCD
    private short deltaCertLen;

    private byte[] dcd; // Delta Certificate Descriptor - defines how delta certificate is derived
    private short dcdLen;

    // Temporary APDU buffer - communictaion
    private byte[] buffer;

    protected ChameleonApplet() {
        buffer = new byte[255];

        // initClassicalCrypto();
        // initPostQuantumCrypto();

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

            case INS_GENERATE_DELTA:
                generateDeltaCertificate(apdu);
                return;

            case INS_GET_BASE_CERT:
                sendBaseCertificate(apdu);
                return;

            case INS_GET_DELTA_CERT:
                sendDeltaCertificate(apdu);
                return;
            
            case INS_SIGN:
                createSignature(apdu);
                return;

            case INS_SIGN_DELTA:
                createDeltaSignature(apdu);
                return;

            case INS_GET_SIGN:
                sendSignature(apdu);
                return;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // TODO
    private void initClassicalCrypto() {
        classicalPrivateKey =
        (ECPrivateKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PRIVATE,
            KeyBuilder.LENGTH_EC_FP_256,
            false
        );

        classicalPublicKey =
        (ECPublicKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PUBLIC,
            KeyBuilder.LENGTH_EC_FP_256,
            false
        );

        classicalSignature =
        Signature.getInstance(
            Signature.ALG_ECDSA_SHA_256,
            false
        );

        signatureBuffer = new byte[80];
    }

    // TODO
    private void initPostQuantumCrypto() {
        pqPublicKey = null;
        pqPrivateKey = null;
        pqEngine = null;
    }

    private void initSession(APDU apdu) {
        baseCertLen = 0;
        deltaCertLen = 0;
        dcdLen = 0;
    }

    // TODO
    private void generateDeltaCertificate(APDU apdu) {
        if (deltaCertificate == null) {
            deltaCertificate = new byte[256];
        }

        short len = (short) 96; // placeholder

        Util.arrayFillNonAtomic(deltaCertificate, (short) 0, len, (byte) 0x02); // sth like this??

        deltaCertLen = len;
    }

    private void createSignature(APDU apdu) {
        // TODO
    }

    // TODO: if the certificate / signature exceeds the buffer size
    private void sendBaseCertificate(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength(baseCertLen);
        apdu.sendBytesLong(baseCertificate, (short) 0, baseCertLen);
    }

    private void sendDeltaCertificate(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength(deltaCertLen);
        apdu.sendBytesLong(deltaCertificate, (short) 0, deltaCertLen);
    }

    private void sendSignature(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength(signatureLen);
        apdu.sendBytesLong(signatureBuffer, (short) 0, signatureLen);
    }
}