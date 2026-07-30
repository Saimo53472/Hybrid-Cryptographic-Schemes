$ROOT = Split-Path -Parent $PSScriptRoot
. "$ROOT\config\local.ps1"

$env:JAVA_HOME = $JDK17_HOME
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"

java -jar $GP_JAR -l -r $READER_NAME