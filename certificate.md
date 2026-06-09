# X.509 Certificates
## P-256
Create key pair
```
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
```

Create self-sgined certificate 
```
openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj "/CN=PoC-Test"
```

## MAYO
In a WSL terminal
```
mkdir ~/oqs-test && cd ~/oqs-test
```
```
export OPENSSL_CONF=$PWD/oqs.cnf
```
```
export OPENSSL_MODULES=/mnt/c/Users/culachisi/oqs-provider/_build/lib
```
```
openssl list -providers -provider oqsprovider
```
```
openssl list -signature-algorithms -provider oqsprovider | grep mayo
```

Create key
```
openssl genpkey \
  -provider default \
  -provider oqsprovider \
  -algorithm mayo1 \
  -out qkey.pem
```

Get certificate info
```
openssl x509 -in qcert.pem -text -noout
```
> OID: 1.3.9999.8.1.3

Create certificate 
```
openssl req -x509 \
  -provider default \
  -provider oqsprovider \
  -key qkey.pem \
  -out qcert.pem \
  -days 365 \
  -subj "/CN=MAYO-POC"
```
Check certificate
```
openssl x509 -in qcert.pem -text -noout
```
Copy them to this project
```
cp ~/oqs-test/qkey.pem /mnt/c/Users/culachisi/Hybrid-Cryptographic-Schemes/
cp ~/oqs-test/qcert.pem /mnt/c/Users/culachisi/Hybrid-Cryptographic-Schemes/
```

## Composite Certificate Creation
Extract PQ certificate structure: 
```
openssl x509 -in qcert.pem -outform DER -out qcert.der
```
```
openssl asn1parse -in qcert.der -inform DER
```

Extract PQ public key:
```
openssl asn1parse \
  -in qcert.der \
  -inform DER \
  -strparse 119 \
  -out pq_spki.der
```

Convert public key to hex 
```
xxd -p pq_spki.der | tr -d '\n'
```

Create DCD:
```
nano dcd.asn1
```
```
algorithm = OID:1.3.9999.8.1.3
subjectPK = FORMAT:HEX,OCTETSTRING:3082059b300806062bce0f0801030382058d00506c6722db689e552448d44e2fb1c9497fad015dbf45c11150c2db5ca71fe32642f>
```
```
openssl asn1parse -genconf dcd.asn1 -out dcd.der
```

Convert DCD to hex:
```
xxd -p dcd.der | tr -d '\n'
```

Embed DCD into cert:
```
nano ext.cnf
```
```
[ v3_ext ]
1.3.6.1.4.1.55555.1.1 = ASN1:SEQUENCE:dcd

[dcd]
subjectPKInfo = FORMAT:HEX,OCTETSTRING:3082059b300806062bce0f0801030382058d00506c6722db689e552448d44e2fb1c9497fad015dbf45c11150c2db5ca71fe32>
```

Create the new certificate
```
openssl x509 \
  -in cert.pem \
  -out chameleon_cert.pem \
  -extfile ext.cnf \
  -extensions v3_ext \
  -signkey key.pem
```

Verify the new certificate 
```
openssl x509 -in chameleon_cert.pem -text -noout
```

Convert key to pkcs8: 
```
openssl pkcs8 -topk8 -nocrypt -in key.pem -out key_pkcs8.pem
```