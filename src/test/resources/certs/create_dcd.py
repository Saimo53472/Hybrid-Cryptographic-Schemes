from pyasn1.type import univ
from pyasn1.codec.der.encoder import encode


OUTPUT = "src/test/resources/certs/dcd.der"
PUBLIC_KEY_FILE = "src/test/resources/keys/hawk512_public.key"
SIGNATURE_FILE = "src/test/resources/sigs/hawk_signature.bin"

HAWK_OID = "1.3.6.1.4.1.55555.1.512"

# Read key and signature
with open(PUBLIC_KEY_FILE, "rb") as f:
    public_key = f.read()
with open(SIGNATURE_FILE, "rb") as f:
    signature = f.read()


print("Public key:", len(public_key))
print("Signature:", len(signature))

# AlgorithmIdentifier
algorithm_identifier = univ.Sequence()
algorithm_identifier.setComponentByPosition(
    0,
    univ.ObjectIdentifier(HAWK_OID)
)

# SubjectPublicKeyInfo
spki = univ.Sequence()
spki.setComponentByPosition(
    0,
    algorithm_identifier
)
spki.setComponentByPosition(
    1,
    univ.BitString(
        hexValue="00" + public_key.hex()
    )
)

# DCD
#
# SEQUENCE {
#     SubjectPublicKeyInfo,
#     AlgorithmIdentifier,
#     OCTET STRING
# }
dcd = univ.Sequence()
dcd.setComponentByPosition(
    0,
    spki
)
dcd.setComponentByPosition(
    1,
    algorithm_identifier
)
dcd.setComponentByPosition(
    2,
    univ.OctetString(signature)
)

# Write DER
with open(OUTPUT, "wb") as f:
    f.write(encode(dcd))

print("Written:", OUTPUT)