# X.509 Certificates

Create ECDSA private key
```
openssl ecparam -name prime256v1 -genkey -noout -out src/test/resources/keys/ecdsa.key
```

Create ECDSA self-signed certificate
```
openssl req -new -x509 \
    -key src/test/resources/keys/ecdsa.key \
    -sha256 \
    -days 365 \
    -out src/test/resources/certs/ecdsa.crt \
    -subj "/CN=PoC"
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
openssl asn1parse \
  -inform DER \
  -in src/test/resources/certs/ecdsa.der \
  -strparse 4 \
  -out src/test/resources/certs/tbs.der
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
openssl asn1parse \
  -inform DER \
  -in src/test/resources/certs/delta_tbs.der \
  -strparse 126 \
  -dump
```

Run HawkSignCert.java to get the signature of the Delta Certificate data
```
 mvn clean test-compile 
 mvn exec:java "-Dexec.mainClass=HawkSignCert" "-Dexec.classpathScope=test"
```

Create DCD
```
python src/test/resources/certs/create_dcd.py
```

Inspect it
```
openssl asn1parse \
  -inform DER \
  -in src/test/resources/certs/dcd.der \
  -i
```

Add DCD extension
```
python src/test/resources/certs/add_dcd_extension.py
```

Inspect it 
```
openssl x509 \
 -inform DER \
 -in src/test/resources/certs/chameleon_cert.der \
 -text \
 -noout
```

Find the data length of the newly created certificate
```
openssl asn1parse \
    -inform DER \
    -in src/test/resources/certs/chameleon_cert.der \
    -i
```

Extract it
```
openssl asn1parse \
    -inform DER \
    -in src/test/resources/certs/chameleon_cert.der \
    -strparse 4 \
    -out src/test/resources/certs/final_tbs.der
```

Sign with ECDSA
```
openssl dgst \
    -sha256 \
    -sign src/test/resources/keys/ecdsa.key \
    -out src/test/resources/sigs/ecdsa_new_signature.bin \
    src/test/resources/certs/final_tbs.der
```

Replace the SignatureValue in the hybrid certificate
```
 python src/test/resources/sigs/replace_signature.py
```

Check certificate
```
openssl x509 \
  -inform DER \
  -in src/test/resources/certs/chameleon_signed.der \
  -text \
  -noout
```

Verify
```
openssl verify \
  -CAfile src/test/resources/certs/chameleon_signed.der \
  src/test/resources/certs/chameleon_signed.der
```

Convert
```
openssl x509 \
    -inform DER \
    -in src/test/resources/certs/chameleon_signed.der \
    -outform PEM \
    -out src/test/resources/certs/chameleon_signed.crt
```