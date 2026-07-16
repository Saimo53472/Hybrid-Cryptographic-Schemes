from asn1crypto import x509, core


CERT_FILE = "src/test/resources/certs/chameleon_cert.der"
SIG_FILE = "src/test/resources/sigs/ecdsa_new_signature.bin"

OUTPUT = "src/test/resources/certs/chameleon_signed.der"


with open(CERT_FILE, "rb") as f:
    cert = x509.Certificate.load(f.read())


with open(SIG_FILE, "rb") as f:
    signature = f.read()


# X.509 signatureValue is an OctetBitString in asn1crypto
cert["signature_value"] = core.OctetBitString(signature)


with open(OUTPUT, "wb") as f:
    f.write(cert.dump())


print("Written:", OUTPUT)
print("Signature length:", len(signature))