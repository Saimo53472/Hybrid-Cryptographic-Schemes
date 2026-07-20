package Chameleon;

import com.licel.jcardsim.smartcardio.CardSimulator;
import javacard.framework.AID;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;

import java.security.*;
import java.security.cert.*;
import java.io.*;

import javax.smartcardio.*;

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.interfaces.ECPrivateKey;

public class BaseTest {

    private static final byte CLA = (byte) 0x00;

    // Metrics
    private static int apduCount = 0;          // N_APDU
    private static int bytesSent = 0;          // B_comm (host -> card)
    private static int bytesReceived = 0;      // B_comm (card -> host)

    // Timing
    private static long timeBaseSign = 0;

    public static void main(String[] args) throws Exception{

        CardSimulator simulator = new CardSimulator();

        // Applet AID
        byte[] aidBytes = {(byte) 0xA0, 0x00, 0x00, 0x00, 0x62, 0x01};
        AID aid = new AID(aidBytes, (short) 0, (byte) aidBytes.length);

        // Install + select
        simulator.installApplet(aid, BaseApplet.class);
        simulator.selectApplet(aid);

        System.out.println("Applet selected");

        // 1. INIT
        ResponseAPDU response = send(simulator, new CommandAPDU(CLA, 0x10, 0x00, 0x00));
        
        if (response.getSW() != 0x9000) {
            throw new RuntimeException("Assertion failed: expected 0x9000");
        }

        // 2. Load EC private key and certificate
        try {
            byte[] key = loadECPrivateKey(Paths.get("src", "test", "resources", "keys", "key_pkcs8.pem"));
            byte[] issuer_cert = loadCertificate(Paths.get("src", "test", "resources", "certs", "issuer_ecdsa.crt"));
            byte[] cert = loadCertificate(Paths.get("src", "test", "resources", "certs", "ecdsa.crt"));

            send(simulator, new CommandAPDU(CLA, 0x70, 0x00, 0x00, key));
            int offset = 0;
            int chunkSize = 200;
            int S_cert = issuer_cert.length; // certificate size in bytes
            System.out.println("S_issuer_cert = " + S_cert);
            while (offset < issuer_cert.length) {
                int len = Math.min(chunkSize, issuer_cert.length - offset);

                byte[] chunk = Arrays.copyOfRange(issuer_cert, offset, offset + len);

                send(simulator, new CommandAPDU(CLA, 0x71, offset == 0 ? 0x00 : 0x01, 0x00, chunk));

                offset += len;
            }

            offset = 0;
            chunkSize = 200;
            S_cert = cert.length; // certificate size in bytes
            System.out.println("S_cert = " + S_cert);
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

        // Reset metrics
        apduCount = 0;
        bytesSent = 0;
        bytesReceived = 0;

        // 4. Get certificate
        int offset = 0;
        ByteArrayOutputStream issuerCertBuffer = new ByteArrayOutputStream();

        while (true) {
            int p1 = (offset >> 8) & 0xFF;
            int p2 = offset & 0xFF;

            ResponseAPDU resp = send(simulator, new CommandAPDU(CLA, 0x20, p1, p2));
            byte[] data = resp.getData();
            if (data.length == 0)
                break;
            issuerCertBuffer.write(data);
            offset += data.length;
            if (data.length < 200)
                break; // last chunk
        }
        byte[] receivedIssuerCert = issuerCertBuffer.toByteArray();

        offset = 0;
        ByteArrayOutputStream certBuffer = new ByteArrayOutputStream();

        while (true) {
            int p1 = (offset >> 8) & 0xFF;
            int p2 = offset & 0xFF;

            ResponseAPDU resp = send(simulator, new CommandAPDU(CLA, 0x30, p1, p2));
            byte[] data = resp.getData();
            if (data.length == 0)
                break;
            certBuffer.write(data);
            offset += data.length;
            if (data.length < 200)
                break; // last chunk
        }
        byte[] receivedCert = certBuffer.toByteArray();

        // 4*. Verify certificate
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate caCert = (X509Certificate) cf.generateCertificate(new FileInputStream("src/test/resources/certs/CA_ECDSA.crt"));
        X509Certificate issuerCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(receivedIssuerCert));
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(receivedCert));

        // 4.1 Verify ECDSA
        boolean issuerECDSAOK;
        try {
            issuerCert.verify(caCert.getPublicKey());
            issuerECDSAOK = true;
        } catch (Exception e) {
            issuerECDSAOK = false;
        }

        System.out.println("Issuer certificate ECDSA: " + issuerECDSAOK);

        boolean iccECDSAOK;
        try {
            cert.verify(issuerCert.getPublicKey());
            iccECDSAOK = true;
        } catch (Exception e) {
            iccECDSAOK = false;
        }

        System.out.println("ICC certificate ECDSA: " + iccECDSAOK);

        // 5. Internal authenticate (build dataToSign)
        byte[] challenge = {0x01, 0x02, 0x03, 0x04};
        send(simulator, new CommandAPDU(CLA, 0x88, 0x00, 0x00, challenge));

        // 6. Create ECDSA signature
        long startBase = System.nanoTime();
        send(simulator, new CommandAPDU(CLA, 0x40, 0x00, 0x00));
        long endBase = System.nanoTime();
        timeBaseSign = endBase - startBase;

        // 8. Get signature
        ResponseAPDU sigResponse = send(simulator, new CommandAPDU(CLA, 0x50, 0x00, 0x00));
        byte[] sigData = sigResponse.getData();

        // 9. Verify signature 
        byte[] expectedMessage = buildExpectedMessage(challenge);
        Signature ecdsaVerifier = Signature.getInstance("SHA256withECDSA");
        ecdsaVerifier.initVerify(cert.getPublicKey());
        ecdsaVerifier.update(expectedMessage);
        boolean ecdsaOK = ecdsaVerifier.verify(sigData);
        System.out.println("Card ECDSA signature: " + ecdsaOK);

        // 10. Print metrics
        System.out.println("METRICS");

        // Time
       System.out.println("Signing time ECDSA (ns): " + timeBaseSign);

        // Communication
        System.out.println("Number of APDU transmissions: " + apduCount);
        System.out.println("Communication bytes sent: " + bytesSent);
        System.out.println("Communication bytes received: " + bytesReceived);
        System.out.println("Total communication bytes: " + (bytesSent + bytesReceived));

        // Certificate and signature sizes
        int issuerCertSize = receivedIssuerCert.length;
        int iccCertSize = receivedCert.length;
        System.out.println("Issuer certificate size = " + issuerCertSize);
        System.out.println("ICC certificate size = " + iccCertSize);
        System.out.println("ECDSA signature size (bytes): " + sigData.length);
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
    
    private static byte[] loadECPrivateKey(Path path) throws Exception {
        byte[] keyBytes = Files.readAllBytes(path);

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

        if (d.length > 32) {
            d = Arrays.copyOfRange(d, d.length - 32, d.length);
        } else if (d.length < 32) {
            byte[] padded = new byte[32];
            System.arraycopy(d, 0, padded, 32 - d.length, d.length);
            d = padded;
        }

        return d;
    }

    private static byte[] loadCertificate(Path pemPath)
            throws Exception {

        String pem = new String(Files.readAllBytes(pemPath));

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

    private static byte[] buildExpectedMessage(byte[] challenge) {
        byte[] msg = new byte[255];
        int pos = 0;

        msg[pos++] = 0x05;
        msg[pos++] = 0x01;
        msg[pos++] = 0x08;

        byte[] dynamic = {
                (byte) 0x6c,
                (byte) 0x55,
                (byte) 0x44,
                (byte) 0x79,
                (byte) 0x7a,
                (byte) 0x91,
                (byte) 0x11,
                (byte) 0x5d
        };

        System.arraycopy(dynamic, 0, msg, pos, dynamic.length);
        pos += dynamic.length;

        while (pos < 251) {
            msg[pos++] = (byte) 0xBB;
        }

        System.arraycopy(challenge, 0, msg, pos, challenge.length);
        pos += challenge.length;

        return msg;
    }
}
