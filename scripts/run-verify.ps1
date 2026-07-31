param(
    [string]$MainClass = "Chameleon.Verify"
)

$ROOT = Split-Path -Parent $PSScriptRoot

. "$ROOT\config\local.ps1"

# HAWK/BC 1.85 is happy on newer JDKs
$env:JAVA_HOME = $JDK8_HOME
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"

Push-Location "$ROOT\verify"

try {
    & "$ROOT\mvnw.cmd" -f pom-verify.xml compile
    & "$ROOT\mvnw.cmd" -f pom-verify.xml exec:java "-Dexec.mainClass=$MainClass"
}
finally {
    Pop-Location
}