# Hybrid-Cryptographic-Schemes

## Commands
To use jdk17:
MAC
```
export JAVA_HOME=$(/usr/libexec/java_home -v 17)
export PATH=$JAVA_HOME/bin:$PATH
```

WSL
```
export JAVA_HOME=/mnt/c/Java/jdk-17/jdk-17.0.12
export PATH=$JAVA_HOME/bin:$PATH
```

Pwsh
```
$env:JAVA_HOME = "C:\Java\jdk-17\jdk-17.0.12"
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
```

To use the Java card development kit:
MAC
```
export JC_HOME=~/Downloads/java_card_devkit_tools-bin-v25.1-b_611-26-OCT-2025
export PATH=$JC_HOME/bin:$PATH
```

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

To convert to class:
```
javac -source 8 -target 8 -classpath $JC_HOME/lib/api_classic-3.0.5.jar Chameleon/ChameleonApplet.java 
```

To convert to cap:
``` 
$JC_HOME/bin/converter.sh -classdir . -applet 0xa0:0x00:0x00:0x00:0x00:0x00:0x01 ChameleonApplet Chameleon 0xa0:0x00:0x00:0x00:0x00:0x00 1.0
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