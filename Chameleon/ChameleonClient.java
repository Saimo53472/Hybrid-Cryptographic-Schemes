package Chameleon;

import Reader.*;
import Chameleon.ChameleonApplet;

public class ChameleonClient {

    private final CardSession session;

    public ChameleonClient(CardSession session) {
        this.session = session;
    }

    public void initSession() {
        ResponseApdu r = session.transmit(
            command(ChameleonApplet.INS_INIT, null)
        );
        check(r);
    }

    public void loadPrivateKeyBase(byte[] key) {
        ResponseApdu r = session.transmit(
            command(ChameleonApplet.INS_LOAD_PRIVKEY_BASE, key)
        );
        check(r);
    }

    public void loadPrivateKeyDelta(byte[] key) {
        ResponseApdu r = session.transmit(
            command(ChameleonApplet.INS_LOAD_PRIVKEY_DELTA, key)
        );
        check(r);
    }
    
    public void loadCertificate(byte[] cert) {
        ResponseApdu r = session.transmit(
            command(ChameleonApplet.INS_LOAD_CERT, cert)
        );
        check(r);
    }

    public void lockCard() {
        ResponseApdu r = session.transmit(
            command(ChameleonApplet.INS_LOCK_CARD, null)
        );
        check(r);
    }

    public byte[] getCertificate() {
        ResponseApdu r = session.transmit(
            command(ChameleonApplet.INS_GET_CERT, null)
        );
        check(r);
        return r.getData();
    }

    public byte[] signBase() {
        ResponseApdu r = session.transmit(
            command(ChameleonApplet.INS_SIGN_BASE, null)
        );
        check(r);
        return r.getData();
    }

    public byte[] getSignatureBase() {
        ResponseApdu r = session.transmit(
            command(ChameleonApplet.INS_GET_SIG_BASE, null)
        );
        check(r);
        return r.getData();
    }

    public byte[] getSignatureDelta() {
        ResponseApdu r = session.transmit(
            command(ChameleonApplet.INS_GET_SIG_DELTA, null)
        );
        check(r);
        return r.getData();
    }

    public void internalAuthenticate(byte[] data) {
        ResponseApdu r = session.transmit(
            command(ChameleonApplet.INS_INTERNAL_AUTHENTICATE, data)
        );
        check(r);
    }

    private CommandApdu command(byte ins, byte[] data) {
        CommandApdu cmd = new CommandApdu();
        cmd.cla = (byte) 0x00;
        cmd.ins = ins;
        cmd.p1  = (byte) 0x00;
        cmd.p2  = (byte) 0x00;
        cmd.data = data;
        return cmd;
    }

    private void check(ResponseApdu r) {
        if (!r.isOK()) {
            throw new RuntimeException(
                String.format("APDU failed: SW=%04X", r.getSW())
            );
        }
    }
}