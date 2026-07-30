package Chameleon;

import java.security.*;
import java.util.Arrays;

import org.bouncycastle.pqc.crypto.hawk.HawkParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkPublicKeyParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkSigner;

import com.licel.jcardsim.bouncycastle.asn1.ASN1BitString;
import com.licel.jcardsim.bouncycastle.asn1.ASN1OctetString;
import com.licel.jcardsim.bouncycastle.asn1.ASN1Primitive;
import com.licel.jcardsim.bouncycastle.asn1.ASN1Sequence;

public class DCDData {
    private byte[] publicKey;
    private byte[] signature;

    public static DCDData parseDCD(byte[] dcdBytes) throws Exception {
        ASN1Sequence dcd = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(dcdBytes));
        ASN1Sequence spki = ASN1Sequence.getInstance(dcd.getObjectAt(0));
        ASN1BitString keyBits = ASN1BitString.getInstance(spki.getObjectAt(1));
        byte[] publicKey = keyBits.getBytes();
        if (publicKey.length == 1025 && publicKey[0] == 0x00) {
            publicKey = Arrays.copyOfRange(publicKey,1, publicKey.length);
        }

        ASN1OctetString sig = ASN1OctetString.getInstance( dcd.getObjectAt(2));
        DCDData result = new DCDData();
        result.publicKey = publicKey;
        result.signature = sig.getOctets();
        return result;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public byte[] getSignature() {
        return signature;
    }
}