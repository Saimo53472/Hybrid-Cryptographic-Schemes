# Hybrid-Cryptographic-Schemes

## Install
Configure Maven so the mvn command is available in the current PowerShell session.
```
$env:MAVEN_HOME = "C:\tools\apache-maven-3.9.16"
$env:PATH = "$env:MAVEN_HOME\bin;$env:PATH"
```

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
  src\main\java\SHAKE\KeccakF1600.java
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