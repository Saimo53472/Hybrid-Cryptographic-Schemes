import com.licel.jcardsim.smartcardio.CardSimulator;
import javacard.framework.AID;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

import javax.smartcardio.*;

import org.bouncycastle.pqc.crypto.hawk.HawkParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkPublicKeyParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkSigner;

public class HawkTest {
    private static final byte CLA = (byte) 0x00;

    public static void main(String[] args) throws Exception {

        CardSimulator simulator = new CardSimulator();

        byte[] aidBytes = { (byte) 0xA0, 0x00, 0x00, 0x00, 0x62, 0x01 };
        AID aid = new AID(aidBytes, (short) 0, (byte) aidBytes.length);

        simulator.installApplet(aid, Chameleon.HawkApplet.class);
        simulator.selectApplet(aid);

        System.out.println("Applet selected");

        ResponseAPDU response = send(simulator, new CommandAPDU(CLA, 0x10, 0x00, 0x00));

        if (response.getSW() != 0x9000) {
            throw new RuntimeException("Assertion failed: expected 0x9000");
        }

        byte[] pub = Files.readAllBytes(Paths.get("src","test","resources", "keys", "hawk512_public.key"));
        HawkPublicKeyParameters pk = new HawkPublicKeyParameters(
            HawkParameters.Hawk_512,
            pub,
            0,
            pub.length);

        byte[] priv = Files.readAllBytes(Paths.get("src","test","resources", "keys", "hawk512_private.key"));
        HawkPrivateKeyParameters sk = new HawkPrivateKeyParameters(HawkParameters.Hawk_512, priv, 0, priv.length);

        try {

            int offset = 0;
            int chunkSize = 200;

            while (offset < priv.length) {
                int len = Math.min(chunkSize, priv.length - offset);

                byte[] chunk = Arrays.copyOfRange(priv, offset, offset + len);

                send(simulator, new CommandAPDU(CLA, 0x71, offset == 0 ? 0x00 : 0x01, 0x00, chunk));

                offset += len;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        send(simulator, new CommandAPDU(CLA, 0x73, 0x00, 0x00));

        byte[] challenge = { 0x01, 0x02, 0x03, 0x04 };
        send(simulator, new CommandAPDU(CLA, 0x88, 0x00, 0x00, challenge));

        send(simulator, new CommandAPDU(CLA, 0x40, 0x00, 0x00));

        byte[] signature = new byte[555];

        int offset = 0;

        while (offset < signature.length) {

            ResponseAPDU rsp = send(
                    simulator,
                    new CommandAPDU(
                            CLA,
                            0x60,
                            (offset >> 8) & 0xFF,
                            offset & 0xFF));

            if (rsp.getSW() != 0x9000) {
                throw new RuntimeException(
                        "Signature fetch failed at offset " + offset);
            }

            byte[] chunk = rsp.getData();

            System.arraycopy(
                    chunk,
                    0,
                    signature,
                    offset,
                    chunk.length);

            offset += chunk.length;
        }
        System.out.println("Signature length = " + signature.length);
        System.out.println("Public key length = " + pub.length);
        System.out.println("Message length = " + buildExpectedMessage().length);
        System.out.println("MSG=" + toHex(buildExpectedMessage()));
        Files.write(Paths.get("src", "test", "resources", "sigs", "jc-hawk.sig"), signature);

        HawkSigner verifier = new HawkSigner();
        verifier.init(false, pk);
        boolean ok = verifier.verifySignature(buildExpectedMessage(), signature);

        System.out.println("VERIFY = " + ok);

        // sign with BC software
        HawkSigner signer = new HawkSigner();
        signer.init(true, sk);
        byte[] sig = signer.generateSignature(buildExpectedMessage());

        // verify with BC software
        boolean ok2 =
            verifier.verifySignature(
                buildExpectedMessage(),
                sig);

        System.out.println(ok2);
    }

    private static ResponseAPDU send(CardSimulator sim, CommandAPDU cmd) {
        // apduCount++;
        // bytesSent += cmd.getBytes().length;

        ResponseAPDU resp = sim.transmitCommand(cmd);

        // bytesReceived += resp.getBytes().length;

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

    private static byte[] buildExpectedMessage() {
        byte[] msg = new byte[255];

        int pos = 0;

        msg[pos++] = 0x05;
        msg[pos++] = 0x01;
        msg[pos++] = 0x08;

        byte[] dynamic = {
                (byte)0x6c,
                (byte)0x55,
                (byte)0x44,
                (byte)0x79,
                (byte)0x7a,
                (byte)0x91,
                (byte)0x11,
                (byte)0x5d
        };

        System.arraycopy(dynamic, 0, msg, pos, dynamic.length);
        pos += dynamic.length;

        while (pos < 251) {
            msg[pos++] = (byte)0xBB;
        }

        msg[pos++] = 0x01;
        msg[pos++] = 0x02;
        msg[pos++] = 0x03;
        msg[pos++] = 0x04;

        return msg;
    }
}
