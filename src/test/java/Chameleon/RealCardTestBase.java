package Chameleon;

import javax.smartcardio.*;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.interfaces.ECPrivateKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

public class RealCardTestBase {

    private static final byte CLA = (byte)0x00;

    public static void main(String[] args) throws Exception {

        // Retrieve the list of smart card readers available on the host system
        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();

        if (terminals.isEmpty()) {
            throw new RuntimeException("No smart card readers found");
        }

        // Display all detected readers to the users
        System.out.println("Available readers:");
        for (int i = 0; i < terminals.size(); i++) {
            System.out.println(
                i + ": " + terminals.get(i).getName());
        }

        // Select the first available reader
        CardTerminal terminal = terminals.get(0);
        System.out.println("\nUsing: " + terminal.getName());

        // Wait until a smart card is inserted into the reader
        terminal.waitForCardPresent(0);

        // Establish a connection with the inserted card
        Card card = terminal.connect("*");
        System.out.println("Connected");

        // Obtain the basic communication channel used to exchange APDU commands
        CardChannel channel = card.getBasicChannel();

        // Select Applet
        byte[] aid = {(byte)0xA0, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
        ResponseAPDU selectResp = send(channel, new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid));
        if (selectResp.getSW() != 0x9000) {
            throw new RuntimeException(String.format("SELECT failed: %04X",selectResp.getSW()));
        }
        System.out.println("Applet selected");

        // 1. Init
        ResponseAPDU initResp = send(channel,new CommandAPDU(CLA, 0x10, 0x00, 0x00));
        System.out.printf("INIT SW = %04X%n", initResp.getSW());

        // 2. Load EC private key and certificate
        try {
            byte[] key = loadECPrivateKey(Paths.get("src", "test", "resources", "keys", "key_pkcs8.pem"));
            byte[] issuer_cert = loadCertificate(Paths.get("src", "test", "resources", "certs", "issuer_ecdsa.crt"));
            byte[] cert = loadCertificate(Paths.get("src", "test", "resources", "certs", "ecdsa.crt"));

            send(channel, new CommandAPDU(CLA, 0xB0, 0x00, 0x00, key));
            int offset = 0;
            int chunkSize = 200;
            while (offset < issuer_cert.length) {
                int len = Math.min(chunkSize, issuer_cert.length - offset);

                byte[] chunk = Arrays.copyOfRange(issuer_cert, offset, offset + len);

                send(channel, new CommandAPDU(CLA, 0xB1, offset == 0 ? 0x00 : 0x01, 0x00, chunk));

                offset += len;
            }

            offset = 0;
            chunkSize = 200;
            while (offset < cert.length) {
                int len = Math.min(chunkSize, cert.length - offset);

                byte[] chunk = Arrays.copyOfRange(cert, offset, offset + len);

                send(channel, new CommandAPDU(CLA, 0xB2, offset == 0 ? 0x00 : 0x01, 0x00, chunk));

                offset += len;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        // 3. Lock card
        send(channel, new CommandAPDU(CLA, 0xB3, 0x00, 0x00));

        // 4. Get certificate
        int offset = 0;
        ByteArrayOutputStream issuerCertBuffer = new ByteArrayOutputStream();

        while (true) {
            int p1 = (offset >> 8) & 0xFF;
            int p2 = offset & 0xFF;

            ResponseAPDU resp = send(channel, new CommandAPDU(CLA, 0x20, p1, p2));
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

            ResponseAPDU resp = send(channel, new CommandAPDU(CLA, 0x30, p1, p2));
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
            e.printStackTrace();
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

        // 5. Internal authenticate
        SecureRandom rnd = new SecureRandom();
        byte[] challenge = new byte[4];
        rnd.nextBytes(challenge);
        send(channel, new CommandAPDU(CLA,0x88, 0x00, 0x00, challenge));

        // 6. Create ECDSA signature
        send(channel, new CommandAPDU(CLA, 0x40, 0x00, 0x00));

        // 8. Get signature
        ResponseAPDU sigResponse = send(channel, new CommandAPDU(CLA, 0x50, 0x00, 0x00));
        byte[] sigData = sigResponse.getData();

        // 9. Verify signature 
        byte[] expectedMessage = buildExpectedMessage(challenge);
        Signature ecdsaVerifier = Signature.getInstance("SHA1withECDSA");
        ecdsaVerifier.initVerify(cert.getPublicKey());
        ecdsaVerifier.update(expectedMessage);
        boolean ecdsaOK = ecdsaVerifier.verify(sigData);
        System.out.println("Card ECDSA signature: " + ecdsaOK);

        card.disconnect(false);
    }

    private static ResponseAPDU send(CardChannel channel, CommandAPDU cmd) throws Exception {

        ResponseAPDU resp = channel.transmit(cmd);
        System.out.println(">> " + toHex(cmd.getBytes()));
        System.out.println("<< " + toHex(resp.getBytes()));
        System.out.printf("SW=%04X%n", resp.getSW());
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
