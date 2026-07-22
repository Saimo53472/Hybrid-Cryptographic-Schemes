# Hybrid-Cryptographic-Schemes

## Install
```
$env:MAVEN_HOME = "C:\tools\apache-maven-3.9.16"
$env:PATH = "$env:MAVEN_HOME\bin;$env:PATH"
```

```
mvn install:install-file `
  "-Dfile=$env:JC_HOME\lib\api.jar" `
  "-DgroupId=org.javacard" `
  "-DartifactId=javacard-api" `
  "-Dversion=2.2.2" `
  "-Dpackaging=jar"
```

## Card
```
Remove-Item -Recurse -Force out -ErrorAction Ignore
Remove-Item -Recurse -Force capout -ErrorAction Ignore

mkdir out
mkdir capout
```

jdk8: 
```
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-8.0.492.9-hotspot"
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
```

```
$env:JC_HOME = "$env:USERPROFILE\Downloads\java_card_kit-2_2_2"
$env:PATH = "$env:JC_HOME\bin;$env:PATH"
```

```
javac -source 1.5 -target 1.5 -cp "$env:JC_HOME\lib\api.jar" -d out src\main\java\com\test\BaseApplet.java
```

To convert to cap:
``` 
& "$env:JC_HOME\bin\converter.bat" -classdir out -exportpath "$env:JC_HOME\api_export_files" -d capout  -out CAP EXP JCA -applet 0xA0:0x01:0x01:0x01:0x01:0x01:0x01 com.test.BaseApplet com.test 0xA0:0x01:0x01:0x01:0x01:0x01  1.0
```

```
$env:JAVA_HOME="C:\Program Files\Eclipse Adoptium\jdk-17.0.19.10-hotspot"
$env:PATH="$env:JAVA_HOME\bin;" + (($env:PATH -split ';' | Where-Object {$_ -notmatch 'jdk-8.0.492.9-hotspot'}) -join ';')
```

Install the applet on the card:
```
java -jar gp.jar `
 -install "capout\com\test\javacard\test.cap" `
 -r "SCM Microsystems Inc. SCR33x USB Smart Card Reader 0"
```

```
java -jar gp.jar -l -r "SCM Microsystems Inc. SCR33x USB Smart Card Reader 0"
```

First the APP:
```
java -jar gp.jar --delete A0010101010101 -r "SCM Microsystems Inc. SCR33x USB Smart Card Reader 0"
```

Then the PKG:
```
java -jar gp.jar --delete A00101010101 -r "SCM Microsystems Inc. SCR33x USB Smart Card Reader 0"
```