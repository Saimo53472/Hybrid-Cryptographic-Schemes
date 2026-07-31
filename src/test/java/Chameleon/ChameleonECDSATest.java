package Chameleon;

import com.licel.jcardsim.base.Simulator;
import com.test.ChameleonECDSAApplet;

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

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;

public class ChameleonECDSATest {

    private static final byte CLA = (byte) 0x00;

    // Metrics
    private static int apduCount = 0; // N_APDU
    private static int bytesSent = 0; // B_comm (host -> card)
    private static int bytesReceived = 0; // B_comm (card -> host)

    // Timing
    private static long timeBaseSign = 0;
    private static long timeDeltaSign = 0;

    private static final String Issuer_DCD_OID = "1.3.6.1.4.1.55555.1.101";
    private static final String ICC_DCD_OID = "1.3.6.1.4.1.55555.1.102";

    public static void main(String[] args) throws Exception {

        Simulator simulator = new Simulator();

        // Applet AID
        byte[] aidBytes = { (byte) 0xA0, 0x00, 0x00, 0x00, 0x62, 0x01 };
        AID aid = new AID(aidBytes, (short) 0, (byte) aidBytes.length);

        // Install + select
        simulator.installApplet(aid, ChameleonECDSAApplet.class);
        simulator.selectApplet(aid);

        System.out.println("Applet selected");

        // 1. INIT
        ResponseAPDU response = send(simulator, new CommandAPDU(CLA, 0x00, 0x00, 0x00));

        if (response.getSW() != 0x9000) {
            throw new RuntimeException("Assertion failed: expected 0x9000");
        }

        // 2. Load private keys and certificates
        try {
            byte[] key = loadECPrivateKey(Paths.get("src", "test", "resources", "keys", "key_pkcs8.pem"));
            byte[] key2 = loadECPrivateKey(Paths.get("src", "test", "resources", "keys", "key2_pkcs8.pem"));
            byte[] issuer_cert = loadCertificate(Paths.get("src", "test", "resources", "certs", "issuer_ecdsa_signed.crt"));
            byte[] cert = loadCertificate(Paths.get("src", "test", "resources", "certs", "ecdsa_signed.crt"));

            send(simulator, new CommandAPDU(CLA, 0xB0, 0x00, 0x00, key));
            send(simulator, new CommandAPDU(CLA, 0xB1, 0x00, 0x00, key2));

            int offset = 0;
            int chunkSize = 200;
            while (offset < issuer_cert.length) {
                int len = Math.min(chunkSize, issuer_cert.length - offset);
                byte[] chunk = Arrays.copyOfRange(issuer_cert, offset, offset + len);
                send(simulator, new CommandAPDU(CLA, 0xB2, offset == 0 ? 0x00 : 0x01, 0x00, chunk));
                offset += len;
            }

            offset = 0;
            chunkSize = 200;
            while (offset < cert.length) {
                int len = Math.min(chunkSize, cert.length - offset);
                byte[] chunk = Arrays.copyOfRange(cert, offset, offset + len);
                send(simulator, new CommandAPDU(CLA, 0xB3, offset == 0 ? 0x00 : 0x01, 0x00, chunk));
                offset += len;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        // 3. Lock card
        send(simulator, new CommandAPDU(CLA, 0xB4, 0x00, 0x00));

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

            ResponseAPDU resp = send(simulator, new CommandAPDU(CLA, 0x10, p1, p2));
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

            ResponseAPDU resp = send(simulator, new CommandAPDU(CLA, 0x20, p1, p2));
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
        X509Certificate caCert = (X509Certificate) cf.generateCertificate(new FileInputStream("src/test/resources/certs/CA_ecdsa.crt"));
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
            e.printStackTrace();
            iccECDSAOK = false;
        }

        System.out.println("ICC certificate ECDSA: " + iccECDSAOK);

        // 4.2 Extract and parse DCD 
        byte[] issuerDCD = unwrapExtension(issuerCert.getExtensionValue(Issuer_DCD_OID));
        DCDData issuerData = DCDData.parseDCD(issuerDCD);
        byte[] iccDCD = unwrapExtension(cert.getExtensionValue(ICC_DCD_OID));
        DCDData iccData = DCDData.parseDCD(iccDCD);

        // 4.3 Verify ECDSA Delta Certificates
        byte[] issuerDeltaTbs = Files.readAllBytes(Paths.get("src/test/resources/certs/issuer_delta_tbs2.der"));
        byte[] deltaTbs = Files.readAllBytes(Paths.get("src/test/resources/certs/delta_tbs2.der"));

        boolean issuerDCDOK;
        try {
            verifyECDSA(caCert.getPublicKey(), issuerData.getSignature(), issuerDeltaTbs);
            issuerDCDOK = true;
        } catch (Exception e) {
            issuerDCDOK = false;
        }

        System.out.println("Issuer DCD ECDSA: " + issuerDCDOK);

        boolean iccDCDOK;
        try {
            verifyECDSA(issuerCert.getPublicKey(), iccData.getSignature(), deltaTbs);
            iccDCDOK = true;
        } catch (Exception e) {
            iccDCDOK = false;
        }

        System.out.println("ICC DCD ECDSA: " + iccDCDOK);

        // 5. Internal authenticate (build dataToSign)
        SecureRandom rnd = new SecureRandom();
        byte[] challenge = new byte[4];
        rnd.nextBytes(challenge);
        send(simulator, new CommandAPDU(CLA, 0x88, 0x00, 0x00, challenge));

        // 6. Create classical signature
        send(simulator, new CommandAPDU(CLA, 0x30, 0x00, 0x00));
        for (int i = 0; i < 1000; i++) {
            send2(simulator, new CommandAPDU(CLA, 0x30, 0x00, 0x00));
        }

        long total = 0;

        for (int i = 0; i < 1000; i++) {
            long start = System.nanoTime();
            send2(simulator, new CommandAPDU(CLA, 0x30, 0x00, 0x00));
            long end = System.nanoTime();

            total += (end - start);
        }

        double avg = total / 1000.0;

        // 7. Create second signature
        send(simulator, new CommandAPDU(CLA, 0x40, 0x00, 0x00));

        for (int i = 0; i < 1000; i++) {
            send2(simulator, new CommandAPDU(CLA, 0x40, 0x00, 0x00));
        }

        total = 0;

        for (int i = 0; i < 1000; i++) {
            long start = System.nanoTime();
            send2(simulator, new CommandAPDU(CLA, 0x40, 0x00, 0x00));
            long end = System.nanoTime();

            total += (end - start);
        }

        double avg2 = total / 1000.0;

        // 8. Get classical signature
        ResponseAPDU sigResponse = send(simulator, new CommandAPDU(CLA, 0x50, 0x00, 0x00));
        byte[] sigData = sigResponse.getData();

        // 9. Get second signature
        ResponseAPDU sigResponse2 = send(simulator, new CommandAPDU(CLA, 0x60, 0x00, 0x00));
        byte[] signature = sigResponse2.getData();

        // 10. Verify signatures
        byte[] expectedMessage = buildExpectedMessage(challenge);
        Signature ecdsaVerifier = Signature.getInstance("SHA1withECDSA");
        ecdsaVerifier.initVerify(cert.getPublicKey());
        ecdsaVerifier.update(expectedMessage);
        boolean ecdsaOK = ecdsaVerifier.verify(sigData);
        System.out.println("Card ECDSA signature: " + ecdsaOK);

        // change for ecdsa
        X509Certificate delta = (X509Certificate) cf.generateCertificate(new FileInputStream("src/test/resources/certs/ecdsa2.crt"));
        boolean secondOk;
        try {
            verifyECDSA(delta.getPublicKey(), signature, expectedMessage);
            secondOk = true;
        } catch (Exception e) {
            secondOk = false;
        }
        System.out.println("Card DCD signature: " + secondOk);

        // 11. Print metrics
        System.out.println("METRICS");
        // Time
        System.out.println("Time classical signing (ns): " + avg);
        System.out.println("Time second signing (ns): " + avg2);
        System.out.println("Time hybrid signing (ns): " + (avg + avg2));

        // Communication
        System.out.println("Number of APDU transmissions: " + apduCount);
        System.out.println("Communication bytes sent: " + bytesSent);
        System.out.println("Communication bytes received: " + bytesReceived);
        System.out.println("Total communication bytes: " + (bytesSent + bytesReceived));

        // Certificate sizes
        int issuerCertSize = receivedIssuerCert.length;
        int iccCertSize = receivedCert.length;
        System.out.println("Issuer certificate size = " + issuerCertSize);
        System.out.println("ICC certificate size = " + iccCertSize);
        System.out.println("Total memory required by certificates = " + (issuerCertSize + iccCertSize));

        // Signature sizes
        int classicalSigSize = sigData.length;
        int pqSigSize = signature.length;
        System.out.println("Base signature size = " + classicalSigSize);
        System.out.println("Delta signature size = " + pqSigSize);
        System.out.println("Total memory required for signatures = " + (classicalSigSize + pqSigSize));
    }

    private static ResponseAPDU send(Simulator sim, CommandAPDU cmd) {
        // Count APDU
        apduCount++;

        // Count bytes sent
        bytesSent += cmd.getBytes().length;

        ResponseAPDU resp = new ResponseAPDU(sim.transmitCommand(cmd.getBytes()));

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

        if (d.length > 24) {
            d = Arrays.copyOfRange(d, d.length - 24, d.length);
        } else if (d.length < 24) {
            byte[] padded = new byte[24];
            System.arraycopy(d, 0, padded, 24 - d.length, d.length);
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

    private static byte[] unwrapExtension(byte[] extension) throws Exception {
        ASN1OctetString oct = ASN1OctetString.getInstance(
                ASN1Primitive.fromByteArray(extension));

        return oct.getOctets();
    }

    private static ResponseAPDU send2(Simulator sim, CommandAPDU cmd) {
        ResponseAPDU resp = new ResponseAPDU(sim.transmitCommand(cmd.getBytes()));
        return resp;
    }

    public static boolean verifyECDSA( PublicKey pk, byte[] signature, byte[] message) throws Exception{
        Signature verifier = Signature.getInstance("SHA1withECDSA");
        verifier.initVerify(pk);
        verifier.update(message);
        return verifier.verify(signature);
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