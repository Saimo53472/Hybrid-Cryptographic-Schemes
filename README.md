<!-- # Hybrid-Cryptographic-Schemes

## Prerequisites

- JDK 8
- JDK 17
- Java Card SDK 2.2.2

Copy:

config/local.example.ps1

to:

config/local.ps1

and update the paths.

## Build applets

.\scripts\build-card.ps1

## Run host application

.\mvnw.cmd exec:java `
  "-Dexec.mainClass=Chameleon.RealCardTestECDSAChameleon" `
  "-Dexec.classpathScope=test"


## Install
Configure Maven so the mvn command is available in the current PowerShell session.
```
$env:MAVEN_HOME = "C:\tools\apache-maven-3.9.16"
$env:PATH = "$env:MAVEN_HOME\bin;$env:PATH"
```

Using the wrapper
```
.\mvnw.cmd clean package
```
REMOVE
The Java Card SDK does not provide Maven artifacts by default, so the API JAR must be installed manually into the local Maven repository.
```
mvn install:install-file `
  "-Dfile=$env:JC_HOME\lib\api.jar" `
  "-DgroupId=org.javacard" `
  "-DartifactId=javacard-api" `
  "-Dversion=2.2.2" `
  "-Dpackaging=jar"
```

## Card
Remove any previously generated compilation and conversion output.
```
Remove-Item -Recurse -Force out -ErrorAction Ignore
Remove-Item -Recurse -Force capout -ErrorAction Ignore

mkdir out
mkdir capout
```

jdk8: 
Java Card 2.2.2 tooling requires an older Java runtime. Use JDK 8 while compiling and converting applets.
```
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-8.0.492.9-hotspot"
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
```

Configure the Java Card SDK.
```
$env:JC_HOME = "$env:USERPROFILE\Downloads\java_card_kit-2_2_2"
$env:PATH = "$env:JC_HOME\bin;$env:PATH"
```

Compile BaseApplet
```
javac -source 1.5 -target 1.5 -cp "$env:JC_HOME\lib\api.jar" -d out src\main\java\com\test\BaseApplet.java
```

Convert Class Files to CAP Format
``` 
& "$env:JC_HOME\bin\converter.bat" -classdir out -exportpath "$env:JC_HOME\api_export_files" -d capout  -out CAP EXP JCA -applet 0xA0:0x01:0x01:0x01:0x01:0x01:0x01 com.test.BaseApplet com.test 0xA0:0x01:0x01:0x01:0x01:0x01  1.0
```

Switch Back to JDK 17
```
$env:JAVA_HOME="C:\Program Files\Eclipse Adoptium\jdk-17.0.19.10-hotspot"
$env:PATH="$env:JAVA_HOME\bin;" + (($env:PATH -split ';' | Where-Object {$_ -notmatch 'jdk-8.0.492.9-hotspot'}) -join ';')
```

Compile ChameleonApplet
```
javac -source 1.5 -target 1.5 `
  -cp "$env:JC_HOME\lib\api.jar" `
  -d out `
  src\main\java\com\test\ChameleonApplet.java `
  src\main\java\com\test\Hawk.java `
  src\main\java\SHAKE\SHAKE256JC.java `
  src\main\java\SHAKE\KeccakF1600.java `
  src\main\java\com\test\U32.java `
  src\main\java\com\test\U64.java 
```

Convert Class Files to CAP Format
```
& "$env:JC_HOME\bin\converter.bat" `
 -classdir out `
 -exportpath "$env:JC_HOME\api_export_files" `
 -d capout `
 -out CAP EXP JCA `
 -applet 0xA0:0x01:0x01:0x01:0x01:0x01:0x01 com.test.ChameleonApplet `
 com.test 0xA0:0x01:0x01:0x01:0x01:0x01 1.0
```

Install CAP File on the Card
```
java -jar gp.jar `
 -install "capout\com\test\javacard\test.cap" `
 -r "SCM Microsystems Inc. SCR33x USB Smart Card Reader 0"
```

List Installed Packages and Applets
```
java -jar gp.jar -l -r "SCM Microsystems Inc. SCR33x USB Smart Card Reader 0"
```

Remove Existing Applet
```
java -jar gp.jar --delete A0010101010101 -r "SCM Microsystems Inc. SCR33x USB Smart Card Reader 0"
```

Remove Package
```
java -jar gp.jar --delete A00101010101 -r "SCM Microsystems Inc. SCR33x USB Smart Card Reader 0"
```

Testing
```
.\scripts\run-test.ps1 `
  -MainClass "Chameleon.RealCardTestECDSAChameleon"
``` -->

# Hybrid-Cryptographic-Schemes

## Prerequisites

Install the following:
- JDK 8
- JDK 17
- Java Card SDK 2.2.2

Copy:
```text
config/local.example.ps1
```
to:
```text
config/local.ps1
```
and update the paths for your local machine.

## First-Time Setup
Install the Java Card API into the local Maven repository:
```powershell
.\scripts\setup-javacard.ps1
```

Build the project using the Maven Wrapper:
```powershell
.\mvnw.cmd clean package
```

## Run Simulator
For BaseTest, ChameleonECDSATest or ChameleonTest
```
.\scripts\run-simulator.ps1 -MainClass "Chameleon.ChameleonECDSATest"
```

## Build CAP Files
Generate the Java Card CAP files:
```powershell
.\scripts\build-card.ps1
```

## Install CAP File on the Card
Install the generated CAP file:
```powershell
.\scripts\install-card.ps1
```

## List Installed Packages and Applets
Display all packages and applets currently installed on the card:
```powershell
.\scripts\list-card.ps1
```

## Remove an Installed Applet
Delete the configured applet from the card:
```powershell
.\scripts\remove-applet.ps1
```

## Run Tests
Run a specific host-side test application (for RealCardTestBase, RealCardTestECDSAChameleon, RealCardTestChameleon):
```powershell
.\scripts\run-test-card.ps1 `
  -MainClass "Chameleon.RealCardTestECDSAChameleon"
```

## Notes
- Java Card compilation and CAP generation require **JDK 8**.
- Host-side applications and tests run using **JDK 17**.
- Machine-specific configuration is stored in `config/local.ps1`. 
- The Maven Wrapper (`mvnw.cmd`) is included in the repository and handles Maven automatically.
- Smart card reader configuration is managed through `config/local.ps1`.
