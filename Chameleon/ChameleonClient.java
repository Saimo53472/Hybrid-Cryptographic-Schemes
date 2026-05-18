package Chameleon;

import Reader.CardSession;

public class ChameleonClient {

    private final CardSession session;

    public ChameleonClient(CardSession session) {
        this.session = session;
    }

    public class ChameleonCommands {
        public static final byte INS_INIT = 0x10;
        public static final byte INS_GET_CERT = 0x20;
        public static final byte INS_SIGN_BASE = 0x30;
        public static final byte INS_SIGN_DELTA = 0x40;
        public static final byte INS_LOAD_PRIVKEY_BASE = 0x70;
        public static final byte INS_LOAD_PRIVKEY_Delta = 0x71;
        public static final byte INS_LOAD_CERT = 0x72;
        public static final byte INS_LOCK_CARD = 0x73;
    }

    private byte[] apdu(byte ins, byte[] data) {

        int len = (data == null) ? 5 : 5 + data.length;

        byte[] cmd = new byte[len];

        cmd[0] = 0x00;   // CLA
        cmd[1] = ins;
        cmd[2] = 0x00;
        cmd[3] = 0x00;
        cmd[4] = (byte)(data == null ? 0 : data.length);

        if (data != null) {
            System.arraycopy(data, 0, cmd, 5, data.length);
        }

        return cmd;
    }

    public void initSession() {
        session.transmit(apdu(ChameleonApplet.INS_INIT, null));
    }

    public void loadCertificate(byte[] cert) {
        session.transmit(apdu(ChameleonApplet.INS_LOAD_CERT, cert));
    }

    public void lockCard() {
        session.transmit(apdu(ChameleonApplet.INS_LOCK_CARD, null));
    }

    public byte[] signBase() {
        return session.transmit(apdu(ChameleonApplet.INS_SIGN_BASE, null));
    }

    public byte[] signDelta() {
        return session.transmit(apdu(ChameleonApplet.INS_SIGN_DELTA, null));
    }

    public byte[] getCertificate() {
        return session.transmit(apdu(ChameleonApplet.INS_GET_CERT, null));
    }

    public void internalAuthenticate(byte[] data) {
        session.transmit(apdu(ChameleonApplet.INS_INTERNAL_AUTHENTICATE, data));
    }
}
