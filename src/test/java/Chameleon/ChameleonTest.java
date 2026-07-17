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

import org.bouncycastle.pqc.crypto.hawk.HawkParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkPublicKeyParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkSigner;

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.interfaces.ECPrivateKey;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;

public class ChameleonTest {

    private static final byte CLA = (byte) 0x00;

    // Metrics
    private static int apduCount = 0; // N_APDU
    private static int bytesSent = 0; // B_comm (host -> card)
    private static int bytesReceived = 0; // B_comm (card -> host)

    // Timing
    private static long timeBaseSign = 0;
    private static long timeDeltaSign = 0;

    private static final String Issuer_DCD_OID = "1.3.6.1.4.1.55555.1.100";
    private static final String ICC_DCD_OID = "1.3.6.1.4.1.55555.1.101";

    public static void main(String[] args) throws Exception {

        CardSimulator simulator = new CardSimulator();

        // Applet AID
        byte[] aidBytes = { (byte) 0xA0, 0x00, 0x00, 0x00, 0x62, 0x01 };
        AID aid = new AID(aidBytes, (short) 0, (byte) aidBytes.length);

        // Install + select
        simulator.installApplet(aid, ChameleonApplet.class);
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
            byte[] qkey = Files.readAllBytes(Paths.get("src", "test", "resources", "keys", "hawk512_private.key"));
            byte[] issuer_cert = loadCertificate(
                    Paths.get("src", "test", "resources", "certs", "issuer_chameleon_signed.crt"));
            byte[] cert = loadCertificate(Paths.get("src", "test", "resources", "certs", "chameleon_signed.crt"));

            send(simulator, new CommandAPDU(CLA, 0x70, 0x00, 0x00, key));

            int offset = 0;
            int chunkSize = 200;
            while (offset < qkey.length) {
                int len = Math.min(chunkSize, qkey.length - offset);
                byte[] chunk = Arrays.copyOfRange(qkey, offset, offset + len);
                send(simulator, new CommandAPDU(CLA, 0x71, offset == 0 ? 0x00 : 0x01, 0x00, chunk));
                offset += len;
            }

            offset = 0;
            chunkSize = 200;
            int S_cert = issuer_cert.length; // certificate size in bytes
            System.out.println("S_issuer_cert = " + S_cert);
            while (offset < issuer_cert.length) {
                int len = Math.min(chunkSize, issuer_cert.length - offset);

                byte[] chunk = Arrays.copyOfRange(issuer_cert, offset, offset + len);

                send(simulator, new CommandAPDU(CLA, 0x72, offset == 0 ? 0x00 : 0x01, 0x00, chunk));

                offset += len;
            }

            offset = 0;
            chunkSize = 200;
            S_cert = cert.length; // certificate size in bytes
            System.out.println("S_cert = " + S_cert);
            while (offset < cert.length) {
                int len = Math.min(chunkSize, cert.length - offset);

                byte[] chunk = Arrays.copyOfRange(cert, offset, offset + len);

                send(simulator, new CommandAPDU(CLA, 0x73, offset == 0 ? 0x00 : 0x01, 0x00, chunk));

                offset += len;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        // 3. Lock card
        send(simulator, new CommandAPDU(CLA, 0x74, 0x00, 0x00));

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
        X509Certificate caCert = (X509Certificate) cf
                .generateCertificate(new FileInputStream("src/test/resources/certs/CA_ECDSA.crt"));
        X509Certificate issuerCert = (X509Certificate) cf
                .generateCertificate(new ByteArrayInputStream(receivedIssuerCert));
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

        // 4.2 Extract and parse DCD 
        byte[] issuerDCD = unwrapExtension(issuerCert.getExtensionValue(Issuer_DCD_OID));
        DCDData issuerData = DCDData.parseDCD(issuerDCD);
        byte[] iccDCD = unwrapExtension(cert.getExtensionValue(ICC_DCD_OID));
        DCDData iccData = DCDData.parseDCD(iccDCD);

        // 4.3 Verify HAWK
        byte[] issuerDeltaTbs = Files.readAllBytes(Paths.get("src/test/resources/certs/issuer_delta_tbs.der"));
        byte[] deltaTbs = Files.readAllBytes(Paths.get("src/test/resources/certs/delta_tbs.der"));

        byte[] caPub = Files.readAllBytes(Paths.get("src", "test", "resources", "keys", "CA_hawk512_public.key"));
        verifyHAWK(caPub, issuerData.getHawkSignature(), issuerDeltaTbs);
        verifyHAWK(issuerData.getHawkPublicKey(), iccData.getHawkSignature(), deltaTbs);

        // 5. Internal authenticate (build dataToSign)
        SecureRandom rnd = new SecureRandom();
        byte[] challenge = new byte[4];
        rnd.nextBytes(challenge);
        send(simulator, new CommandAPDU(CLA, 0x88, 0x00, 0x00, challenge));

        Runtime rt = Runtime.getRuntime();
        rt.gc();
        long ramBefore = rt.totalMemory() - rt.freeMemory();

        // 6. Create classical signature
        long startBase = System.nanoTime();
        send(simulator, new CommandAPDU(CLA, 0x30, 0x00, 0x00));
        long endBase = System.nanoTime();
        timeBaseSign = endBase - startBase;

        // 7. Create post-quantum signature
        long startDelta = System.nanoTime();
        send(simulator, new CommandAPDU(CLA, 0x40, 0x00, 0x00));
        long endDelta = System.nanoTime();
        timeDeltaSign = endDelta - startDelta;

        long ramAfter = rt.totalMemory() - rt.freeMemory();
        long ramUsed = ramAfter - ramBefore;

        // 8. Get classical signature
        ResponseAPDU sigResponse = send(simulator, new CommandAPDU(CLA, 0x50, 0x00, 0x00));
        byte[] sigData = sigResponse.getData();

        // 9. Get post-quantum signature
        byte[] signature = new byte[555];
        offset = 0;

        while (offset < signature.length) {
            ResponseAPDU rsp = send(simulator, new CommandAPDU(CLA, 0x60, (offset >> 8) & 0xFF, offset & 0xFF));
            byte[] chunk = rsp.getData();
            System.arraycopy(chunk, 0, signature, offset, chunk.length);
            offset += chunk.length;
        }

        // 10. Verify signatures
        byte[] expectedMessage = buildExpectedMessage(challenge);
        Signature ecdsaVerifier = Signature.getInstance("SHA256withECDSA");
        ecdsaVerifier.initVerify(cert.getPublicKey());
        ecdsaVerifier.update(expectedMessage);
        boolean ecdsaOK = ecdsaVerifier.verify(sigData);
        System.out.println("Card ECDSA signature: " + ecdsaOK);

        byte[] pub = Files.readAllBytes(Paths.get("src", "test", "resources", "keys", "hawk512_public.key"));
        HawkPublicKeyParameters pk = new HawkPublicKeyParameters(
                HawkParameters.Hawk_512,
                pub,
                0,
                pub.length);
        HawkSigner verifier = new HawkSigner();
        verifier.init(false, pk);
        boolean hawkOK = verifier.verifySignature(expectedMessage, signature);
        System.out.println("Card HAWK signature: " + hawkOK);

        // 10. Print metrics
        System.out.println("METRICS");
        // Time
        System.out.println("Time classical signing (ns): " + timeBaseSign);
        System.out.println("Time post-quantum signing (ns): " + timeDeltaSign);
        System.out.println("Time hybrid signing (ns): " + (timeBaseSign + timeDeltaSign));

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
        System.out.println("Total memory required bt signatures = " + (classicalSigSize + pqSigSize));

        // RAM used for signing
        System.out.println("Signing RAM (bytes) = "+ ramUsed);
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

    private static void verifyHAWK(byte[] hawkPublicKey, byte[] signature, byte[] message) throws Exception {
        HawkPublicKeyParameters pk = new HawkPublicKeyParameters(HawkParameters.Hawk_512, hawkPublicKey, 0,
                hawkPublicKey.length);
        HawkSigner verifier = new HawkSigner();
        verifier.init(false, pk);
        boolean ok = verifier.verifySignature(message, signature);
        System.out.println("HAWK: " + ok);
    }

    private static byte[] unwrapExtension(byte[] extension) throws Exception {
        ASN1OctetString oct = ASN1OctetString.getInstance(
                ASN1Primitive.fromByteArray(extension));

        return oct.getOctets();
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