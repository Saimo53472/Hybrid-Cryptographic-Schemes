# Hybrid-Cryptographic-Schemes

## Commands
To use jdk17:
WSL
```
export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
export PATH=$JAVA_HOME/bin:$PATH
```

Pwsh
```
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-17.0.19.10-hotspot"
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
```

To use the Java card development kit:
WSL
```
export JC_HOME=$HOME/Downloads/java_card_devkit_tools-bin-v25.1-b_611-26-OCT-2025
export PATH=$JC_HOME/bin:$PATH
```

Pwsh
```
$env:JC_HOME = "$env:USERPROFILE\Downloads\java_card_devkit_tools-bin-v25.1-b_611-26-OCT-2025"
$env:PATH = "$env:JC_HOME\bin;$env:PATH"
```

## Test - Simulator
Pwsh
```
javac -source 8 -target 8 -d out -cp "out;.;jcardsim.jar;gp.jar;api_classic-3.0.5.jar" src/main/java/Chameleon/ChameleonApplet.java
```

To convert to cap:
WSL
``` 
$JC_HOME/bin/converter.sh -classdir . -applet 0xa0:0x00:0x00:0x00:0x00:0x00:0x01 ChameleonApplet Chameleon 0xa0:0x00:0x00:0x00:0x00:0x00 1.0
```
Pwsh
``` 
& "$env:JC_HOME\bin\converter.bat" -classdir out -d capout -out CAP EXP JCA -applet 0xa0:0x00:0x00:0x00:0x00:0x00:0x01 Chameleon.ChameleonApplet Chameleon 0xa0:0x00:0x00:0x00:0x00:0x00 1.0
```

Install the applet on the card:
```
java -jar gp.jar -install .\capout\Chameleon\javacard\Chameleon.cap -r "SCM Microsystems Inc. SCR33x USB Smart Card Reader 0"
```

Run 
WSL
```
java -cp .:jcardsim.jar:api_classic-3.0.5.jar ChameleonTest
```
Pwsh
```
java -cp "out;.;jcardsim.jar;gp.jar;api_classic-3.0.5.jar" ChameleonTest
```

### Verifying the Signature 
Extract public key
ECDSA
````
openssl x509 -in ecdsa_cert.pem -pubkey -noout > pubkey.pem
```
RSA
```
openssl x509 -in rsa_cert.pem -pubkey -noout > rsa_pub.pem
```

Save signature
ECDSA
```
echo "304502202B495A9B4142DC317624626AD108D4896C12A97AF1A1372E9A7B0F29ADCAEB490221009E28C2CE063D309A14A1C39E1B3C9898B721963257B307C078B6047D982207BD" | xxd -r -p > sig.der
```
RSA
```
echo "39CCD2436B6BD36EFD88B2160E1DEF470B2ADD2168154B56B9E22B79FD5ABFCEBCA86C832E347996B4A38FA62634CB2BDDF786E6DFE30C6A4AF1FA6C030022B050F2E28027A8EFB7798A25C6D42857A2586D419089CFC08DA6F4338039CA03A0C6C02BBD5A89523A41B03C684E984241AB5E76179D52F974805DCC7A6348FA6232FC878CC9ED65C10674BB9E7D63B6D302C7B9023458209E11434C61078776BA7CC5B2ABDF9CA77BB7B2EE2A0E1CC36A44A7D3486779BD874A7FBF353B8EA1BACDD83B5240909ACD055C17E8E46C17086416432C173A601D51995D6DB50FAADEF9C9DB99C05375E0376BAEA9FC6EDA42F489D5BB1BE304C3" | xxd -r -p > sig2.der
```

Save dataToSign
```
echo "0501086C5544797A91115DBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB01020304" | xxd -r -p > data.bin
```

Verify the signature
ECDSA
```
openssl dgst -sha256 -verify pubkey.pem -signature sig.der data.bin
```
RSA
```
openssl dgst -sha1 -verify rsa_pub.pem -signature sig2.der data.bin
```