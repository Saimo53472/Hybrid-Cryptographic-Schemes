param(
    [string]$MainClass
)

$ROOT = Split-Path -Parent $PSScriptRoot

. "$ROOT\config\local.ps1"

$env:JAVA_HOME = $JDK8_HOME
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"

& "$ROOT\mvnw.cmd" compile

& "$ROOT\mvnw.cmd" exec:java `
  "-Dexec.mainClass=$MainClass" `
  "-Dexec.classpathScope=test"