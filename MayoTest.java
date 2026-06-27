import com.licel.jcardsim.smartcardio.CardSimulator;
import javacard.framework.AID;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;

import javax.smartcardio.*;

public class MayoTest {

    private static final byte CLA = (byte) 0x00;

    private static int apduCount = 0;
    private static int bytesSent = 0;
    private static int bytesReceived = 0;

    private static long timeDeltaSign = 0;

    public static void main(String[] args) {

        CardSimulator simulator = new CardSimulator();

        byte[] aidBytes = {(byte) 0xA0, 0x00, 0x00, 0x00, 0x62, 0x01};
        AID aid = new AID(aidBytes, (short) 0, (byte) aidBytes.length);

        simulator.installApplet(aid, Chameleon.Mayo.class);
        simulator.selectApplet(aid);

        System.out.println("Applet selected");

        ResponseAPDU response = send(simulator, new CommandAPDU(CLA, 0x10, 0x00, 0x00));

        if (response.getSW() != 0x9000) {
            throw new RuntimeException("Assertion failed: expected 0x9000");
        }

        try {
            byte[] qkey = loadRawFile("qkey.pem");
            byte[] cert = loadCertificate("chameleon_cert.pem");

            int offset = 0;
            int chunkSize = 200;

            while (offset < qkey.length) {
                int len = Math.min(chunkSize, qkey.length - offset);

                byte[] chunk = Arrays.copyOfRange(qkey, offset, offset + len);

                send(simulator, new CommandAPDU(CLA, 0x71,
                        offset == 0 ? 0x00 : 0x01,
                        0x00,
                        chunk));

                offset += len;
            }

            offset = 0;

            // while (offset < cert.length) {
            //     int len = Math.min(chunkSize, cert.length - offset);

            //     byte[] chunk = Arrays.copyOfRange(cert, offset, offset + len);

            //     send(simulator, new CommandAPDU(CLA, 0x72,
            //             offset == 0 ? 0x00 : 0x01,
            //             0x00,
            //             chunk));

            //     offset += len;
            // }
        } catch (Exception e) {
            e.printStackTrace();
        }

        send(simulator, new CommandAPDU(CLA, 0x73, 0x00, 0x00));

        ResponseAPDU eskResp = send(simulator, new CommandAPDU(CLA, 0x92, 0x00, 0x00));

        byte[] esk = eskResp.getData();

        System.out.println("ESK length = " + esk.length);
        System.out.println("ESK (first 64 bytes) = " + Arrays.toString(Arrays.copyOfRange(esk, 0, 64)));

        int offset = 0;

        // while (true) {
        //     int p1 = (offset >> 8) & 0xFF;
        //     int p2 = offset & 0xFF;

        //     ResponseAPDU resp = send(simulator, new CommandAPDU(CLA, 0x20, p1, p2));

        //     byte[] data = resp.getData();

        //     if (data.length == 0) break;

        //     offset += data.length;

        //     if (data.length < 200) break;
        // }

        // byte[] challenge = {0x01, 0x02, 0x03, 0x04};
        // send(simulator, new CommandAPDU(CLA, 0x88, 0x00, 0x00, challenge));

        // send(simulator, new CommandAPDU(CLA, 0x40, 0x00, 0x00));

        // ResponseAPDU pqSigResponse = send(simulator, new CommandAPDU(CLA, 0x60, 0x00, 0x00));
    }

    private static ResponseAPDU send(CardSimulator sim, CommandAPDU cmd) {
        apduCount++;
        bytesSent += cmd.getBytes().length;

        ResponseAPDU resp = sim.transmitCommand(cmd);

        bytesReceived += resp.getBytes().length;

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

    private static byte[] loadRawFile(String path) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(path));

        String pem = new String(data);

        if (pem.contains("BEGIN")) {
            pem = pem
                    .replaceAll("-----BEGIN (.*)-----", "")
                    .replaceAll("-----END (.*)-----", "")
                    .replaceAll("\\s", "");

            data = Base64.getDecoder().decode(pem);
        }

        return data;
    }

    private static byte[] loadCertificate(String pemPath) throws Exception {
        String pem = new String(Files.readAllBytes(Paths.get(pemPath)));

        pem = pem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");

        return Base64.getDecoder().decode(pem);
    }
}