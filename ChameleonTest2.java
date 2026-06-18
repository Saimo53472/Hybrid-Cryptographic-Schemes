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
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;

public class ChameleonTest2 {

    private static final byte CLA = (byte) 0x00;

    // Metrics
    private static int apduCount = 0;          // N_APDU
    private static int bytesSent = 0;          // B_comm (host -> card)
    private static int bytesReceived = 0;      // B_comm (card -> host)

    // Timing
    private static long timeBaseSign = 0;
    private static long timeDeltaSign = 0;     // will be used later

    public static void main(String[] args) {

        CardSimulator simulator = new CardSimulator();

        // Applet AID
        byte[] aidBytes = {(byte) 0xA0, 0x00, 0x00, 0x00, 0x62, 0x01};
        AID aid = new AID(aidBytes, (short) 0, (byte) aidBytes.length);

        // Install + select
        simulator.installApplet(aid, Chameleon.ChameleonClassicApplet.class);
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
            byte[][] rsaKey = loadRSAPrivateKeyFull("rsa_key_pkcs8.pem");
            byte[] cert = loadCertificate("hybrid_cert.pem");

            byte[] modulus = rsaKey[0];
            byte[] exponent = rsaKey[1];

            send(simulator, new CommandAPDU(CLA, 0x70, 0x00, 0x00, key));
            send(simulator, new CommandAPDU(CLA, 0x71, 0x00, 0x00, modulus));
            send(simulator, new CommandAPDU(CLA, 0x71, 0x01, 0x00, exponent));
            send(simulator, new CommandAPDU(CLA, 0x71, 0x02, 0x00)); // finalize RSA key

            int offset = 0;
            int chunkSize = 200;

            int S_cert = cert.length;  // certificate size in bytes

            while (offset < cert.length) {
                int len = Math.min(chunkSize, cert.length - offset);

                byte[] chunk = Arrays.copyOfRange(cert, offset, offset + len);

                send(simulator, new CommandAPDU(CLA, 0x72, offset == 0 ? 0x00 : 0x01, 0x00, chunk)); 
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
        send(simulator, new CommandAPDU(CLA, 0x88, 0x00, 0x00, challenge));

        // 6. Create ECDSA signature
        long startBase = System.nanoTime();
        send(simulator, new CommandAPDU(CLA, 0x30, 0x00, 0x00));
        long endBase = System.nanoTime();
        timeBaseSign = endBase - startBase;

        // 8. Get signature
        ResponseAPDU sigResponse = send(simulator, new CommandAPDU(CLA, 0x50, 0x00, 0x00));
        byte[] sigData = sigResponse.getData();

        // 8. Create RSA signature
        long startDelta = System.nanoTime();
        send(simulator, new CommandAPDU(CLA, 0x40, 0x00, 0x00));
        long endDelta = System.nanoTime();
        timeDeltaSign = endDelta - startDelta;

        // 9. Get RSA signature
        ResponseAPDU rsaSigResponse = send(simulator, new CommandAPDU(CLA, 0x60, 0x00, 0x00));
        byte[] rsaSigData = rsaSigResponse.getData();

        // 10. Print metrics
        System.out.println("METRICS");

        // Time
        System.out.println("Signing time ECDSA (ns): " + timeBaseSign);
        System.out.println("Signing time RSA (ns): " + timeDeltaSign);

        // Communication
        System.out.println("APDU transmisions: " + apduCount);
        System.out.println("Communication bytes sent: " + bytesSent);
        System.out.println("Communication bytes received: " + bytesReceived);
        System.out.println("Total communication bytes: " + (bytesSent + bytesReceived));

        // Certificate and signature sizes
        System.out.println("Certificate size (bytes): " + S_cert);
        System.out.println("ECDSA signature size (bytes): " + sigData.length);
        System.out.println("RSA signature size (bytes): " + rsaSigData.length);
    }

    private static ResponseAPDU send(CardSimulator sim, CommandAPDU cmd) {
        // Count APDU
        apduCount++;

        // Count bytes sent
        bytesSent += cmd.getBytes().length;

        ResponseAPDU resp = sim.transmitCommand(cmd);

        // Count bytes received
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

    private static byte[][] loadRSAPrivateKeyFull(String path) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(path));

        String pem = new String(keyBytes);

        if (pem.contains("BEGIN")) {
            pem = pem
                .replaceAll("-----BEGIN (.*)-----", "")
                .replaceAll("-----END (.*)-----", "")
                .replaceAll("\\s", "");

            keyBytes = Base64.getDecoder().decode(pem);
        }

        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey pk = kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));

        RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) pk;

        BigInteger modulus = rsaKey.getModulus();
        BigInteger privateExponent = rsaKey.getPrivateExponent();

        byte[] n = modulus.toByteArray();
        byte[] d = privateExponent.toByteArray();

        // Remove leading zero (BigInteger sign byte)
        if (n[0] == 0x00) {
            n = Arrays.copyOfRange(n, 1, n.length);
        }
        if (d[0] == 0x00) {
            d = Arrays.copyOfRange(d, 1, d.length);
        }

        return new byte[][] { n, d };
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
