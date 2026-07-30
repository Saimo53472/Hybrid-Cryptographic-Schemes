from asn1crypto import x509, core, algos
from pyasn1.type import univ
from pyasn1.codec.der.encoder import encode

# Files - change for issuer or ICC
TBS_FILE = "src/test/resources/certs/tbs2.der"
HAWK_KEY_FILE = "src/test/resources/keys/public_key2.der"
OUTPUT_FILE = "src/test/resources/certs/delta_tbs2.der"

HAWK_OID = "1.3.6.1.4.1.55555.1.512"

# Generic AlgorithmIdentifier that accepts unknown OIDs
class CustomAlgorithmIdentifier(core.Sequence):
    _fields = [
        ("algorithm", core.ObjectIdentifier),
        ("parameters", core.Any, {"optional": True})
    ]

# Load TBSCertificate
with open(TBS_FILE, "rb") as f:
    tbs = x509.TbsCertificate.load(f.read())

with open(HAWK_KEY_FILE, "rb") as f:
    hawk_key = f.read()

# Create HAWK AlgorithmIdentifier
#
# AlgorithmIdentifier ::= SEQUENCE {
#     algorithm OBJECT IDENTIFIER
# }
algorithm_identifier = univ.Sequence()
algorithm_identifier.setComponentByPosition(0, univ.ObjectIdentifier(HAWK_OID))

# Create HAWK public key BIT STRING
bit_string = univ.BitString(hexValue="00" + hawk_key.hex())

# Create SubjectPublicKeyInfo
#
# SubjectPublicKeyInfo ::= SEQUENCE {
#     algorithm AlgorithmIdentifier,
#     subjectPublicKey BIT STRING
# }
spki = univ.Sequence()
spki.setComponentByPosition(0, algorithm_identifier)
spki.setComponentByPosition(1, bit_string)
spki_der = encode(spki)

# Replace EC SubjectPublicKeyInfo with HAWK SPKI
tbs["subject_public_key_info"] = x509.PublicKeyInfo.load(spki_der)

# Replace TBSCertificate signature algorithm
hawk_signature_der = encode(algorithm_identifier)
hawk_signature_algorithm = algos.SignedDigestAlgorithm.load(hawk_signature_der)
tbs["signature"] = hawk_signature_algorithm

# Write modified TBSCertificate
with open(OUTPUT_FILE, "wb") as f:
    f.write(tbs.dump())

print("Written:", OUTPUT_FILE)