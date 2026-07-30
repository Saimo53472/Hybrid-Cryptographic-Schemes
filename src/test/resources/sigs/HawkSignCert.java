import java.nio.file.Files;
import java.nio.file.Paths;

import org.bouncycastle.pqc.crypto.hawk.HawkParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkSigner;

public class HawkSignCert {

    private static final String TBS_FILE = "src/test/resources/certs/delta_tbs.der";
    private static final String PRIVATE_KEY_FILE = "src/test/resources/keys/issuer_hawk512_private.key";
    private static final String SIGNATURE_FILE = "src/test/resources/sigs/hawk_signature.bin";

    public static void main(String[] args) throws Exception {
        // Data that gets signed
        byte[] message = Files.readAllBytes(Paths.get(TBS_FILE));
        // HAWK private key
        byte[] privateKey = Files.readAllBytes(Paths.get(PRIVATE_KEY_FILE));
        HawkPrivateKeyParameters sk = new HawkPrivateKeyParameters(HawkParameters.Hawk_512, privateKey, 0, privateKey.length);
        HawkSigner signer = new HawkSigner();
        signer.init(true, sk);
        // Sign the TBSCertificate bytes
        byte[] signature = signer.generateSignature(message);
        Files.write(Paths.get(SIGNATURE_FILE),signature);
    }
}