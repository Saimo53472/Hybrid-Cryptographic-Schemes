from asn1crypto import x509, core


CERT_FILE = "src/test/resources/certs/ecdsa.der"
DCD_FILE = "src/test/resources/certs/dcd.der"

OUTPUT = "src/test/resources/certs/chameleon_cert.der"


# Experimental DCD extension OID
DCD_OID = "1.3.6.1.4.1.55555.1.102"


# Load certificate
with open(CERT_FILE, "rb") as f:
    cert = x509.Certificate.load(f.read())


with open(DCD_FILE, "rb") as f:
    dcd = f.read()

# Create extension
extension = x509.Extension({
    "extn_id": DCD_OID,
    "critical": False,
    "extn_value": dcd
})


# Add extension to TBSCertificate
tbs = cert["tbs_certificate"]
extensions = tbs["extensions"]
if extensions.native is None:
    extensions = x509.Extensions([])


extensions.append(extension)
tbs["extensions"] = extensions

# Write certificate
with open(OUTPUT, "wb") as f:
    f.write(cert.dump())

print("Written:", OUTPUT)