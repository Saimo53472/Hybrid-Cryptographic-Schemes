param(
    [string]$AppletAID = "0xA0:0x01:0x01:0x01:0x01:0x01:0x01",
    [string]$PackageAID = "0xA0:0x01:0x01:0x01:0x01:0x01"
)

$ROOT = Split-Path -Parent $PSScriptRoot
. "$ROOT\config\local.ps1"

$env:JAVA_HOME = $JDK17_HOME
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"

java -jar $GP_JAR --delete $AppletAID -r $READER_NAME
java -jar $GP_JAR --delete $PackageAID -r $READER_NAME