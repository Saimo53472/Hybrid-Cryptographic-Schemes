param(
    [string]$Applet = "BaseApplet"
)

$ROOT = Split-Path -Parent $PSScriptRoot

. "$ROOT\config\local.ps1"

# Use JDK 8
$env:JAVA_HOME = $JDK8_HOME
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"

# Java Card SDK
$env:JC_HOME = $JC_HOME

# Clean output
Remove-Item -Recurse -Force "$ROOT\out" -ErrorAction Ignore
New-Item -ItemType Directory "$ROOT\out" -Force | Out-Null

switch ($Applet) {

    "BaseApplet" {
        $Sources = @(
            "$ROOT\src\main\java\com\test\BaseApplet.java"
        )
    }

    "ChameleonECDSAApplet" {
        $Sources = @(
            "$ROOT\src\main\java\com\test\ChameleonECDSAApplet.java"
        )
    }

    "ChameleonApplet" {
        $Sources = @(
            "$ROOT\src\main\java\com\test\ChameleonApplet.java"
            "$ROOT\src\main\java\com\test\Hawk.java"
            "$ROOT\src\main\java\com\test\SHAKE256JC.java"
            "$ROOT\src\main\java\com\test\KeccakF1600.java"
            "$ROOT\src\main\java\com\test\U32.java"
            "$ROOT\src\main\java\com\test\U64.java"
        )
    }

    default {
        throw "Unknown applet: $Applet"
    }
}

Write-Host "Compiling $Applet"

javac -source 1.5 -target 1.5 `
    -cp "$env:JC_HOME\lib\api.jar" `
    -d "$ROOT\out" `
    $Sources

if ($LASTEXITCODE -ne 0) {
    throw "Compilation failed"
}

Write-Host "Compilation successful"