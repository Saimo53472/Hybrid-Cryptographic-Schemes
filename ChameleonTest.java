import com.licel.jcardsim.smartcardio.CardSimulator;
import javacard.framework.AID;

import javax.smartcardio.*;

public class ChameleonTest {

    private static final byte CLA = (byte) 0x80;

    public static void main(String[] args) throws Exception {

        CardSimulator simulator = new CardSimulator();

        // Applet AID
        byte[] aidBytes = {(byte) 0xA0, 0x00, 0x00, 0x00, 0x62, 0x01};
        AID aid = new AID(aidBytes, (short) 0, (byte) aidBytes.length);

        // Install + select
        simulator.installApplet(aid, Chameleon.ChameleonApplet.class);
        simulator.selectApplet(aid);

        System.out.println("Applet selected");

        // 1. INIT
        send(simulator, new CommandAPDU(CLA, 0x10, 0x00, 0x00));

        // 2. Load EC private key (dummy 32 bytes)
        byte[] fakeKey = new byte[32];
        for (int i = 0; i < 32; i++) fakeKey[i] = (byte) (i + 1);

        send(simulator, new CommandAPDU(CLA, 0x70, 0x00, 0x00, fakeKey));

        // 3. Load certificate
        byte[] cert = "MY_TEST_CERT".getBytes();
        send(simulator, new CommandAPDU(CLA, 0x72, 0x00, 0x00, cert));

        // 4. Internal authenticate (build dataToSign)
        byte[] challenge = {0x01, 0x02, 0x03, 0x04};
        send(simulator, new CommandAPDU(0x00, 0x88, 0x00, 0x00, challenge));

        // 5. Create classical signature
        ResponseAPDU sigResponse = send(simulator,
                new CommandAPDU(CLA, 0x30, 0x00, 0x00));

        // 6. Get signature again (stored)
        send(simulator, new CommandAPDU(CLA, 0x50, 0x00, 0x00));

        // 7. Get certificate
        send(simulator, new CommandAPDU(CLA, 0x20, 0x00, 0x00));

        // 8. Lock card
        send(simulator, new CommandAPDU(CLA, 0x73, 0x00, 0x00));

        System.out.println("Test completed");
    }

    private static ResponseAPDU send(CardSimulator sim, CommandAPDU cmd) {
        ResponseAPDU resp = sim.transmitCommand(cmd);

        System.out.println(">> " + toHex(cmd.getBytes()));
        System.out.println("<< " + toHex(resp.getBytes()));
        System.out.println("SW = " + Integer.toHexString(resp.getSW()));
        System.out.println();

        return resp;
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}
