param(
    [string]$Applet = "BaseApplet",
    [string]$PackageName = "com.test",
    [string]$AppletAID = "0xA0:0x01:0x01:0x01:0x01:0x01:0x01",
    [string]$PackageAID = "0xA0:0x01:0x01:0x01:0x01:0x01"
)

$ROOT = Split-Path -Parent $PSScriptRoot

$AppletPath = "$ROOT\src\main\java\com\test\$Applet.java"
$AppletClass = "com.test.$Applet"

. "$ROOT\config\local.ps1"

# Switch to JDK 8
$env:JAVA_HOME = $JDK8_HOME
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"

# Java Card SDK
$env:JC_HOME = $JC_HOME
$env:PATH = "$env:JC_HOME\bin;$env:PATH"

# Convert to CAP
& "$env:JC_HOME\bin\converter.bat" `
  -classdir "$ROOT\out" `
  -exportpath "$env:JC_HOME\api_export_files" `
  -d "$ROOT\capout" `
  -out CAP EXP JCA `
  -applet $AppletAID `
  $AppletClass `
  $PackageName `
  $PackageAID `
  1.0