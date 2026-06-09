import com.licel.jcardsim.smartcardio.CardSimulator;
import javacard.framework.AID;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;

import java.security.*;
import java.security.cert.*;
import java.io.*;

import javax.smartcardio.*;

import java.math.BigInteger;
import java.io.ByteArrayOutputStream;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.interfaces.ECPrivateKey;

public class ChameleonTest {

    private static final byte CLA = (byte) 0x00;

    public static void main(String[] args) {

        CardSimulator simulator = new CardSimulator();

        // Applet AID
        byte[] aidBytes = {(byte) 0xA0, 0x00, 0x00, 0x00, 0x62, 0x01};
        AID aid = new AID(aidBytes, (short) 0, (byte) aidBytes.length);

        // Install + select
        simulator.installApplet(aid, Chameleon.ChameleonApplet.class);
        simulator.selectApplet(aid);

        System.out.println("Applet selected");

        // 1. INIT
        ResponseAPDU response = send(simulator, new CommandAPDU(CLA, 0x10, 0x00, 0x00));
        
        if (response.getSW() != 0x9000) {
            throw new RuntimeException("Assertion failed: expected 0x9000");
        }

        // 2. Load EC private key and certificate
        try {
            byte[] key = loadECPrivateKey("key_pkcs8.pem"); 
            byte[] qkey = loadRawFile("qkey.pem"); 
            byte[] cert = loadCertificate("chameleon_cert.pem"); 

            send(simulator, new CommandAPDU(CLA, 0x70, 0x00, 0x00, key));

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
            chunkSize = 200;

            while (offset < cert.length) {
                int len = Math.min(chunkSize, cert.length - offset);

                byte[] chunk = Arrays.copyOfRange(cert, offset, offset + len);

                send(simulator, new CommandAPDU(CLA, 0x72, offset == 0 ? 0x00 : 0x01, 0x00, chunk)); // fix

                offset += len;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        // 3. Lock card
        send(simulator, new CommandAPDU(CLA, 0x73, 0x00, 0x00));

        // 4. Get certificate
        int offset = 0;

        while (true) {
            int p1 = (offset >> 8) & 0xFF;
            int p2 = offset & 0xFF;

            ResponseAPDU resp = send(simulator, new CommandAPDU(CLA, 0x20, p1, p2));

            byte[] data = resp.getData();

            if (data.length == 0) break;

            // store / append data
            offset += data.length;

            if (data.length < 200) break; // last chunk
        }

        // 5. Internal authenticate (build dataToSign)
        byte[] challenge = {0x01, 0x02, 0x03, 0x04};
        send(simulator, new CommandAPDU(0x00, 0x88, 0x00, 0x00, challenge));

        // 6. Create classical signature
        send(simulator, new CommandAPDU(CLA, 0x30, 0x00, 0x00));

        // 7. Get signature
        ResponseAPDU sigResponse = send(simulator, new CommandAPDU(CLA, 0x50, 0x00, 0x00));
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
    
    private static byte[] loadECPrivateKey(String path) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(path));

        String pem = new String(keyBytes);

        if (pem.contains("BEGIN")) {
            pem = pem
                .replaceAll("-----BEGIN (.*)-----", "")
                .replaceAll("-----END (.*)-----", "")
                .replaceAll("\\s", "");

            keyBytes = Base64.getDecoder().decode(pem);
        }

        KeyFactory kf = KeyFactory.getInstance("EC");
        PrivateKey pk = kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));

        ECPrivateKey ecKey = (ECPrivateKey) pk;

        byte[] d = ecKey.getS().toByteArray();

        // Ensure 32 bytes for P-256
        if (d.length > 32) {
            d = Arrays.copyOfRange(d, d.length - 32, d.length);
        } else if (d.length < 32) {
            byte[] padded = new byte[32];
            System.arraycopy(d, 0, padded, 32 - d.length, d.length);
            d = padded;
        }

        return d;
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

    private static byte[] loadCertificate(String pemPath)
        throws Exception {

        String pem = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(pemPath)));

        pem = pem
            .replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")
            .replaceAll("\\s", "");

        return Base64.getDecoder().decode(pem);
    }

    public static PublicKey loadPublicKeyFromCert(String certPath) throws Exception {
        FileInputStream fis = new FileInputStream(certPath);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
        return cert.getPublicKey();
    }
}
