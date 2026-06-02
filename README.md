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

## X.509 Certificates
### P-256
Create key pair
```
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
```

Create self-sgined certificate 
```
openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj "/CN=PoC-Test"
```

## Test - Simulator
Compile
WSL
```
javac -cp .:jcardsim.jar:api_classic-3.0.5.jar Chameleon/ChameleonApplet.java
```
Pwsh
```
javac --release 8 -cp ".;jcardsim.jar;api_classic-3.0.5.jar" Chameleon\ChameleonApplet.java
```

WSL
```
javac -cp .:jcardsim.jar:api_classic-3.0.5.jar ChameleonTest.java
```
Pwsh
```
javac -cp ".;jcardsim.jar;api_classic-3.0.5.jar" ChameleonTest.java
```

To convert to cap:
WSL
``` 
$JC_HOME/bin/converter.sh -classdir . -applet 0xa0:0x00:0x00:0x00:0x00:0x00:0x01 ChameleonApplet Chameleon 0xa0:0x00:0x00:0x00:0x00:0x00 1.0
```
Pwsh
``` 
& "$env:JC_HOME\bin\converter.bat" -classdir . -applet 0xa0:0x00:0x00:0x00:0x00:0x00:0x01 ChameleonApplet Chameleon 0xa0:0x00:0x00:0x00:0x00:0x00 1.0
```

Install the applet on the card:
```
java -jar gp.jar -install ChameleonApplet.cap
```

Run 
WSL
```
java -cp .:jcardsim.jar:api_classic-3.0.5.jar ChameleonTest
```
Pwsh
```
java -cp ".;jcardsim.jar;gp.jar;api_classic-3.0.5.jar" ChameleonTest
```

### Verifying the Signature 
Extract public key
````
openssl x509 -in cert.pem -pubkey -noout > pubkey.pem
```

Save signature
```
echo "304502202B495A9B4142DC317624626AD108D4896C12A97AF1A1372E9A7B0F29ADCAEB490221009E28C2CE063D309A14A1C39E1B3C9898B721963257B307C078B6047D982207BD" | xxd -r -p > sig.der
```

Save dataToSign
```
$ echo "0501086C5544797A91115DBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB01020304" | xxd -r -p > data.bin
```

Verify the signature
```
openssl dgst -sha256 -verify pubkey.pem -signature sig.der data.bin
```