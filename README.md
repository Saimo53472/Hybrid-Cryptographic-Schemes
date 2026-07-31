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
Install the Java Card API into the local Maven repository.
```powershell
.\scripts\setup-javacard.ps1
```

Build the project using the Maven Wrapper.
```powershell
.\mvnw.cmd clean package
```

## Run Simulator
Run a simulator-based test.
```powershell
.\scripts\run-simulator.ps1 -MainClass <class>
```

### Available Main Classes
- `Chameleon.BaseTest`
- `Chameleon.ChameleonECDSATest`
- `Chameleon.ChameleonTest`

## Verify Certificates and Signatures
Run verification for the Chameleon scheme.

```powershell
.\scripts\run-verify.ps1
```

## Build CAP Files
Generate Java Card CAP files.
```powershell
.\scripts\build-cap.ps1 - Applet <applet> 
```
### Available Applets
- `BaseApplet`
- `ChameleonECDSAApplet`
- `ChameleonApplet`

### Optional Parameters
- `-PackageName`
- `-AppletAID`
- `-PackageAID`

## Install CAP File on the Card
Install the generated CAP file.
```powershell
.\scripts\install-cap.ps1
```

## List Installed Packages and Applets
Display all packages and applets currently installed on the card.
```powershell
.\scripts\list-card.ps1
```

## Remove an Installed Applet
Delete the configured applet from the card.
```powershell
.\scripts\remove-applet.ps1
```

### Optional Parameters
- `-AppletAID`
- `-PackageAID`

## Run Tests
Run a card test.
```powershell
.\scripts\run-test-card.ps1 -MainClass <class>
```

### Available Main Classes
- `Chameleon.RealCardTestBase`
- `Chameleon.RealCardTestECDSAChameleon`
- `Chameleon.RealCardTestChameleon`

## Notes
- Java Card compilation and CAP generation require **JDK 8**.
- Host-side applications and tests run using **JDK 17**.
- Machine-specific configuration is stored in `config/local.ps1`. 
- The Maven Wrapper (`mvnw.cmd`) is included in the repository and handles Maven automatically.
- Smart card reader configuration is managed through `config/local.ps1`.
