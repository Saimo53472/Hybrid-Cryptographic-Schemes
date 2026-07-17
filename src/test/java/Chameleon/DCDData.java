package Chameleon;

import java.util.Arrays;

import org.bouncycastle.pqc.crypto.hawk.HawkParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkPublicKeyParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkSigner;

import com.licel.jcardsim.bouncycastle.asn1.ASN1BitString;
import com.licel.jcardsim.bouncycastle.asn1.ASN1OctetString;
import com.licel.jcardsim.bouncycastle.asn1.ASN1Primitive;
import com.licel.jcardsim.bouncycastle.asn1.ASN1Sequence;

public class DCDData {

    private byte[] hawkPublicKey;
    private byte[] hawkSignature;

    public static DCDData parseDCD(byte[] dcdBytes)
            throws Exception {

        ASN1Sequence dcd = ASN1Sequence.getInstance(
                ASN1Primitive.fromByteArray(dcdBytes));

        ASN1Sequence spki = ASN1Sequence.getInstance(
                dcd.getObjectAt(0));

        ASN1BitString keyBits = ASN1BitString.getInstance(
                spki.getObjectAt(1));

        byte[] hawkPublicKey = keyBits.getBytes();
        if (hawkPublicKey.length == 1025 && hawkPublicKey[0] == 0x00) {
            hawkPublicKey = Arrays.copyOfRange(
                    hawkPublicKey,
                    1,
                    hawkPublicKey.length);
        }

        ASN1OctetString sig = ASN1OctetString.getInstance(
                dcd.getObjectAt(2));

        DCDData result = new DCDData();

        result.hawkPublicKey = hawkPublicKey;
        result.hawkSignature = sig.getOctets();
        return result;
    }

    public static void verifyHAWK(
            byte[] hawkPublicKey,
            byte[] signature,
            byte[] message) throws Exception {
        HawkPublicKeyParameters pk = new HawkPublicKeyParameters(
                HawkParameters.Hawk_512,
                hawkPublicKey,
                0,
                hawkPublicKey.length);

        HawkSigner verifier = new HawkSigner();
        verifier.init(false, pk);

        boolean ok = verifier.verifySignature(
                message,
                signature);

        System.out.println(
                "HAWK signature: " + ok);
    }

    public byte[] getHawkPublicKey() {
        return hawkPublicKey;
    }

    public byte[] getHawkSignature() {
        return hawkSignature;
    }
}