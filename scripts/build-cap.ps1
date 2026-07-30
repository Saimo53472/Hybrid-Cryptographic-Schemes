param(
    [string]$AppletClass = "com.test.ChameleonApplet",
    [string]$PackageName = "com.test",
    [string]$AppletAID = "0xA0:0x01:0x01:0x01:0x01:0x01:0x01",
    [string]$PackageAID = "0xA0:0x01:0x01:0x01:0x01:0x01"
)

$ROOT = Split-Path -Parent $PSScriptRoot

. "$ROOT\config\local.ps1"

# Switch to JDK 8
$env:JAVA_HOME = $JDK8_HOME
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"

# Java Card SDK
$env:JC_HOME = $JC_HOME
$env:PATH = "$env:JC_HOME\bin;$env:PATH"

# Clean output
Remove-Item -Recurse -Force "$ROOT\out" -ErrorAction Ignore
Remove-Item -Recurse -Force "$ROOT\capout" -ErrorAction Ignore

New-Item -ItemType Directory "$ROOT\out" -Force | Out-Null
New-Item -ItemType Directory "$ROOT\capout" -Force | Out-Null

# Compile
javac -source 1.5 -target 1.5 `
  -cp "$env:JC_HOME\lib\api.jar" `
  -d "$ROOT\out" `
  "$ROOT\src\main\java\com\test\BaseApplet.java"

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