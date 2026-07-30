$ROOT = Split-Path -Parent $PSScriptRoot

. "$ROOT\config\local.ps1"

# Switch to JDK 8
$env:JAVA_HOME = $JDK8_HOME
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"

# Java Card SDK
$env:JC_HOME = $JC_HOME
$env:PATH = "$env:JC_HOME\bin;$env:PATH"

& "$ROOT\mvnw.cmd" install:install-file `
  "-Dfile=$env:JC_HOME\lib\api.jar" `
  "-DgroupId=org.javacard" `
  "-DartifactId=javacard-api" `
  "-Dversion=2.2.2" `
  "-Dpackaging=jar"