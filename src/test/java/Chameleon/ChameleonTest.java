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
import org.bouncycastle.pqc.crypto.hawk.HawkPrivateKeyParameters;
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

    private static final String DCD_OID = "1.3.6.1.4.1.55555.1.100";

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
        ResponseAPDU response = send(simulator, new CommandAPDU(CLA, 0x10, 0x00, 0x00));

        if (response.getSW() != 0x9000) {
            throw new RuntimeException("Assertion failed: expected 0x9000");
        }

        // 2. Load EC private key and certificate
        try {
            byte[] key = loadECPrivateKey(Paths.get("src", "test", "resources", "keys", "key_pkcs8.pem"));
            byte[] qkey = Files.readAllBytes(Paths.get("src", "test", "resources", "keys", "hawk512_private.key"));
            HawkPrivateKeyParameters sk = new HawkPrivateKeyParameters(HawkParameters.Hawk_512, qkey, 0, qkey.length);
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
            int S_cert = cert.length; // certificate size in bytes
            System.out.println("S_cert = " + S_cert);

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
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(receivedCert));

        // 4.1 Verify ECDSA
        cert.verify(cert.getPublicKey());
        System.out.println("ECDSA: OK");

        // 4.2 Extract DCD
        byte[] dcd = unwrapExtension(cert.getExtensionValue(DCD_OID));

        // 4.3 Parse DCD
        DCDData data = DCDData.parseDCD(dcd);

        // 4.4 Verify HAWK
        byte[] deltaTbs = Files.readAllBytes(Paths.get("src/test/resources/certs/delta_tbs.der"));

        verifyHAWK(data.getHawkPublicKey(), data.getHawkSignature(), deltaTbs);

        // 5. Internal authenticate (build dataToSign)
        byte[] challenge = { 0x01, 0x02, 0x03, 0x04 };
        send(simulator, new CommandAPDU(CLA, 0x88, 0x00, 0x00, challenge));

        // 6. Create classical signature
        long startBase = System.nanoTime();
        send(simulator, new CommandAPDU(CLA, 0x30, 0x00, 0x00));
        long endBase = System.nanoTime();
        timeBaseSign = endBase - startBase;

        // 8. Get signature
        ResponseAPDU sigResponse = send(simulator, new CommandAPDU(CLA, 0x50, 0x00, 0x00));
        byte[] sigData = sigResponse.getData();

        // 8. Create post-quantum signature
        long startDelta = System.nanoTime();
        send(simulator, new CommandAPDU(CLA, 0x40, 0x00, 0x00));
        long endDelta = System.nanoTime();
        timeDeltaSign = endDelta - startDelta;

        // 9. Get post-quantum signature
        byte[] signature = new byte[555];
        offset = 0;

        while (offset < signature.length) {
            ResponseAPDU rsp = send(simulator, new CommandAPDU(CLA, 0x60, (offset >> 8) & 0xFF, offset & 0xFF));
            byte[] chunk = rsp.getData();
            System.arraycopy(chunk, 0, signature, offset, chunk.length);
            offset += chunk.length;
        }

        // 10. Print metrics
        System.out.println("METRICS");
        // Time
        System.out.println("T_sign_classical (ns): " + timeBaseSign);
        System.out.println("T_sign_post-quantum (ns): " + timeDeltaSign);

        // Communication
        System.out.println("N_APDU: " + apduCount);
        System.out.println("B_comm_sent: " + bytesSent);
        System.out.println("B_comm_received: " + bytesReceived);
        System.out.println("B_comm_total: " + (bytesSent + bytesReceived));

        // Signature sizes
        System.out.println("S_sig_base = " + sigData.length);
        System.out.println("S_sig_delta = " + signature.length);
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
        System.out.println("HAWK signature: " + ok);
    }

    private static byte[] unwrapExtension(byte[] extension) throws Exception {
        ASN1OctetString oct = ASN1OctetString.getInstance(
                ASN1Primitive.fromByteArray(extension));

        return oct.getOctets();
    }
}