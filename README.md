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
export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
export PATH=$JAVA_HOME/bin:$PATH
```

Pwsh
```
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-8.0.492.9-hotspot"
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-17.0.19.10-hotspot"
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

```
$env:JC_CLASSIC_HOME = "$env:USERPROFILE\Downloads\java_card_devkit_tools-bin-v25.1-b_611-26-OCT-2025"
$env:PATH = "$env:JC_CLASSIC_HOME\bin;$env:PATH"
```

MVN Pwsh
```
$env:Path += ";C:\Program Files\apache-maven-3.9.16\bin"   
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

## GlobalPlatformPro
Clone the repo of the project
```
git clone https://github.com/martinpaljak/GlobalPlatformPro
cd GlobalPlatformPro
```

Build the project and create the gp.jar
```
./mvnw package
```

Connect the reader, then
```
java -jar ./tool/target/gp.jar -r
```

## Test - Simulator
Compile
```
javac -cp .:jcardsim.jar:api_classic-3.0.5.jar Chameleon/ChameleonApplet.java
```
```
javac -cp .:jcardsim.jar:api_classic-3.0.5.jar ChameleonTest.java
```

Run 
```
java -cp .:jcardsim.jar:api_classic-3.0.5.jar ChameleonTest
```