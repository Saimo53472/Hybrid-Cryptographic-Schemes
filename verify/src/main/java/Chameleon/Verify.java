package Chameleon;

import java.io.*;
import java.nio.file.*;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.pqc.crypto.hawk.HawkParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkPublicKeyParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkSigner;

public class Verify {

    private static final String ISSUER_DCD_OID =
            "1.3.6.1.4.1.55555.1.101";

    private static final String ICC_DCD_OID =
            "1.3.6.1.4.1.55555.1.102";

    public static void main(String[] args) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate caCert = (X509Certificate) cf.generateCertificate(new FileInputStream("../src/test/resources/certs/CA_ecdsa.crt"));
        X509Certificate issuerCert = (X509Certificate) cf.generateCertificate(new FileInputStream("../src/test/resources/certs/issuer_chameleon_signed.crt"));
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new FileInputStream("../src/test/resources/certs/chameleon_signed.crt"));

        verifyCertificateChain(caCert, issuerCert, cert);
        byte[] issuerDCD = unwrapExtension(issuerCert.getExtensionValue(ISSUER_DCD_OID));

        DCDData issuerData = DCDData.parseDCD(issuerDCD);
        byte[] iccDCD = unwrapExtension(cert.getExtensionValue(ICC_DCD_OID));
        DCDData iccData = DCDData.parseDCD(iccDCD);

        byte[] issuerDeltaTbs = Files.readAllBytes(Paths.get("../src/test/resources/certs/issuer_delta_tbs.der"));
        byte[] deltaTbs = Files.readAllBytes(Paths.get("../src/test/resources/certs/delta_tbs.der"));
        byte[] caPub = Files.readAllBytes(Paths.get("../src/test/resources/keys/CA_hawk512_public.key"));
        verifyHAWK(caPub, issuerData.getSignature(), issuerDeltaTbs);
        verifyHAWK(issuerData.getPublicKey(), iccData.getSignature(), deltaTbs);

        byte[] message = Files.readAllBytes(Paths.get("../out/message.bin"));
        byte[] ecdsaSignature = Files.readAllBytes(Paths.get("../out/ecdsa_signature.bin"));
        verifyECDSASignature(cert, message, ecdsaSignature);

        byte[] hawkPublicKey = Files.readAllBytes(Paths.get("../src/test/resources/keys/hawk512_public.key"));
        byte[] hawkSignature = Files.readAllBytes(Paths.get("../out/signature.bin"));
        verifyHAWK(hawkPublicKey, hawkSignature, message);
    }

    private static void verifyCertificateChain(X509Certificate caCert,
            X509Certificate issuerCert,
            X509Certificate cert)
            throws Exception {

        try {
            issuerCert.verify(caCert.getPublicKey());
            System.out.println("Issuer certificate ECDSA: true");
        } catch (Exception e) {
            System.out.println("Issuer certificate ECDSA: false");
        }

        try {
            cert.verify(issuerCert.getPublicKey());
            System.out.println("ICC certificate ECDSA: true");
        } catch (Exception e) {
            System.out.println("ICC certificate ECDSA: false");
        }
    }

    private static void verifyECDSASignature(
            X509Certificate cert,
            byte[] message,
            byte[] signature)
            throws Exception {

        Signature verifier =
                Signature.getInstance("SHA1withECDSA");

        verifier.initVerify(cert.getPublicKey());
        verifier.update(message);

        boolean ok = verifier.verify(signature);

        System.out.println(
                "Card ECDSA signature: " + ok);
    }

    private static void verifyHAWK(
            byte[] hawkPublicKey,
            byte[] signature,
            byte[] message)
            throws Exception {

        HawkPublicKeyParameters pk =
                new HawkPublicKeyParameters(
                        HawkParameters.Hawk_512,
                        hawkPublicKey,
                        0,
                        hawkPublicKey.length);

        HawkSigner verifier =
                new HawkSigner();

        verifier.init(false, pk);

        boolean ok =
                verifier.verifySignature(
                        message,
                        signature);

        System.out.println(
                "HAWK: " + ok);
    }

    private static byte[] unwrapExtension(
            byte[] extension)
            throws Exception {

        ASN1OctetString oct =
                ASN1OctetString.getInstance(
                        ASN1Primitive.fromByteArray(
                                extension));

        return oct.getOctets();
    }
}