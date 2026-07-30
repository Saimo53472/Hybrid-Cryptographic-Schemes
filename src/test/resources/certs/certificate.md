# Certificate Generation
> **Note**
>
> Pre-generated certificates are already included in the repository.
> This document is only required if you want to regenerate the hybrid certificates from scratch.
>
> The Python scripts used during certificate generation contain file-specific input and output paths. Before running them, verify that the filenames referenced inside the scripts match the certificate currently being generated (e.g., Issuer vs. ICC certificates) and update them if necessary.

## Prerequisites

Install:
- OpenSSL
- Python 3.x
- JDK 17

Install the required Python packages
```powershell
pip install -r requirements.txt
```
This step is only required when regenerating certificates or running the Python utilities contained in the repository.

## Hybrid Certificate (ECDSA+HAWK)
### CA Certificate 
Create CA key
```
openssl ecparam -name prime192v1 -genkey -noout -out src/test/resources/keys/CA_ecdsa.key
```

Create CA ECDSA certificate signed by CA sk
```
openssl req -new -x509 -key src/test/resources/keys/CA_ecdsa.key -sha1 -days 365 -out src/test/resources/certs/CA_ecdsa.crt -subj "/CN=PoC"
```

### Issuer Certificate
Create issuer key
```
openssl ecparam -name prime192v1 -genkey -noout -out src/test/resources/keys/issuer_ecdsa.key
```

Create Issuer ECDSA certificate signed by CA sk
```
openssl req -new -key src/test/resources/keys/issuer_ecdsa.key -out src/test/resources/certs/issuer.csr -subj "/CN=Issuer"
```

```
openssl x509 -req -in src/test/resources/certs/issuer.csr -CA src/test/resources/certs/CA_ecdsa.crt -CAkey src/test/resources/keys/CA_ecdsa.key -CAcreateserial -out src/test/resources/certs/issuer_ecdsa.crt -days 365 -sha1
```

Inspect the certificate
```
openssl x509 -in src/test/resources/certs/issuer_ecdsa.crt -text -noout
```

Extract the ECDSA certificate in DER
```
openssl x509 -in src/test/resources/certs/issuer_ecdsa.crt -outform DER -out src/test/resources/certs/issuer_ecdsa.der
```

Parse the certificate with ASN.1
```
openssl asn1parse -inform DER -in src/test/resources/certs/issuer_ecdsa.der -i
```

Extract the data
```
openssl asn1parse -inform DER -in src/test/resources/certs/issuer_ecdsa.der -strparse 4 -out src/test/resources/certs/issuer_tbs.der
```

Run the python script
```
python src/test/resources/certs/cert.py
```

Check the data for hawk is there
```
openssl asn1parse -inform DER -in src/test/resources/certs/issuer_delta_tbs.der -i
```

Run HawkSignCert.java to get the signature of the Delta Certificate data
```
.\mvnw.cmd clean test-compile

.\mvnw.cmd exec:java "-Dexec.mainClass=HawkSignCert" "-Dexec.classpathScope=test"
```

Create DCD
```
python src/test/resources/certs/create_dcd.py
```

Inspect it
```
openssl asn1parse -inform DER -in src/test/resources/certs/issuer_dcd.der -i
```

Add DCD extension
```
python src/test/resources/certs/add_dcd_extension.py
```

Inspect it 
```
openssl x509 -inform DER -in src/test/resources/certs/issuer_chameleon_cert.der -text -noout
```

Find the data length of the newly created certificate
```
openssl asn1parse -inform DER -in src/test/resources/certs/issuer_chameleon_cert.der -i
```

Extract it
```
openssl asn1parse -inform DER -in src/test/resources/certs/issuer_chameleon_cert.der -strparse 4 -out src/test/resources/certs/issuer_final_tbs.der
```

Sign with ECDSA
```
openssl dgst -sha1 -sign src/test/resources/keys/CA_ecdsa.key -out src/test/resources/sigs/issuer_ecdsa_new_signature.bin src/test/resources/certs/issuer_final_tbs.der
```

Replace the SignatureValue in the hybrid certificate
```
 python src/test/resources/sigs/replace_signature.py
```

Check certificate
```
openssl x509 -inform DER -in src/test/resources/certs/issuer_chameleon_signed.der -text -noout
```

Convert
```
openssl x509 -inform DER -in src/test/resources/certs/issuer_chameleon_signed.der -outform PEM -out src/test/resources/certs/issuer_chameleon_signed.crt
```

### ICC Certificate
Create ECDSA private key
```
openssl ecparam -name prime192v1 -genkey -noout -out src/test/resources/keys/ecdsa.key
```

Convert it to pkcs8
```
openssl pkcs8 -topk8 -nocrypt -in src/test/resources/keys/ecdsa.key -out src/test/resources/keys/key_pkcs8.pem
```

Create ICC ECDSA certificate signed by Issuer sk
```
openssl req -new -key src/test/resources/keys/ecdsa.key -out src/test/resources/certs/icc.csr -subj "/CN=ICC"
```
```
openssl x509 -req -in src/test/resources/certs/icc.csr -CA src/test/resources/certs/issuer_ecdsa.crt -CAkey src/test/resources/keys/issuer_ecdsa.key -CAcreateserial -out src/test/resources/certs/ecdsa.crt -days 365 -sha1
```

Inspect the certificate
```
openssl x509 -in src/test/resources/certs/ecdsa.crt -text -noout
```

Extract the ECDSA certificate in DER
```
openssl x509 -in src/test/resources/certs/ecdsa.crt -outform DER -out src/test/resources/certs/ecdsa.der
```

Parse the certificate with ASN.1
```
openssl asn1parse -inform DER -in src/test/resources/certs/ecdsa.der -i
```

Extract the data
```
openssl asn1parse -inform DER -in src/test/resources/certs/ecdsa.der -strparse 4 -out src/test/resources/certs/tbs.der
```

Run the python script
```
 python src/test/resources/certs/cert.py
```

Check the data for hawk is there
```
openssl asn1parse -inform DER -in src/test/resources/certs/delta_tbs.der -i
```

Check the signature is there
```
openssl asn1parse -inform DER -in src/test/resources/certs/delta_tbs.der -strparse 132 -dump
```

Run HawkSignCert.java to get the signature of the Delta Certificate data
```
.\mvnw.cmd clean test-compile

.\mvnw.cmd exec:java `
  "-Dexec.mainClass=HawkSignCert" `
  "-Dexec.classpathScope=test"
```

Create DCD
```
python src/test/resources/certs/create_dcd.py
```

Inspect it
```
openssl asn1parse -inform DER -in src/test/resources/certs/dcd.der -i
```

Add DCD extension
```
python src/test/resources/certs/add_dcd_extension.py
```

Inspect it 
```
openssl x509 -inform DER -in src/test/resources/certs/chameleon_cert.der -text -noout
```

Find the data length of the newly created certificate
```
openssl asn1parse -inform DER -in src/test/resources/certs/chameleon_cert.der -i
```

Extract it
```
openssl asn1parse -inform DER -in src/test/resources/certs/chameleon_cert.der -strparse 4 -out src/test/resources/certs/final_tbs.der
```

Sign with ECDSA
```
openssl dgst -sha1 -sign src/test/resources/keys/issuer_ecdsa.key -out src/test/resources/sigs/ecdsa_new_signature.bin src/test/resources/certs/final_tbs.der
```

Replace the SignatureValue in the hybrid certificate
```
 python src/test/resources/sigs/replace_signature.py
```

Check certificate
```
openssl x509 -inform DER -in src/test/resources/certs/chameleon_signed.der -text -noout
```

Convert
```
openssl x509 -inform DER -in src/test/resources/certs/chameleon_signed.der -outform PEM -out src/test/resources/certs/chameleon_signed.crt
```