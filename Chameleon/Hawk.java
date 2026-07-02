package Chameleon;

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
