param(
    [string]$OutputName = 'AgentSshKeyManager.exe'
)

$ErrorActionPreference = 'Stop'

$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$compilerCandidates = @(
    "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe"
)
$compiler = $compilerCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $compiler) {
    throw 'The .NET Framework C# compiler was not found.'
}

if ([System.IO.Path]::GetFileName($OutputName) -ne $OutputName -or -not $OutputName.EndsWith('.exe', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputName must be a simple filename ending in .exe.'
}
$output = Join-Path $projectDir $OutputName
$source = Join-Path $projectDir 'Program.cs'
$manifest = Join-Path $projectDir 'app.manifest'
$buildDir = Join-Path ([System.IO.Path]::GetTempPath()) ('AgentSshKeyManager-build-' + [Guid]::NewGuid().ToString('N'))
$tempOutput = Join-Path $buildDir $OutputName

try {
    [System.IO.Directory]::CreateDirectory($buildDir) | Out-Null
    Push-Location -LiteralPath $buildDir
    try {
        & $compiler `
            /nologo `
            /target:winexe `
            /platform:anycpu `
            /optimize+ `
            /warn:4 `
            "/win32manifest:$manifest" `
            "/out:$tempOutput" `
            /reference:System.dll `
            /reference:System.Core.dll `
            /reference:System.Drawing.dll `
            /reference:System.Windows.Forms.dll `
            /reference:System.Xml.dll `
            $source
        $compilerExitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }

    if ($compilerExitCode -ne 0) {
        throw "Compilation failed (code $compilerExitCode)."
    }
    Copy-Item -LiteralPath $tempOutput -Destination $output -Force
}
finally {
    $resolvedTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    $resolvedBuild = [System.IO.Path]::GetFullPath($buildDir)
    if ($resolvedBuild.StartsWith($resolvedTemp, [System.StringComparison]::OrdinalIgnoreCase) -and
        [System.IO.Path]::GetFileName($resolvedBuild).StartsWith('AgentSshKeyManager-build-', [System.StringComparison]::Ordinal)) {
        Remove-Item -LiteralPath $resolvedBuild -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "Created: $output"
