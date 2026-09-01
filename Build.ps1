param(
    [switch]$UnsignedDevelopmentBuild,
    [switch]$UnsignedRelease,
    [string]$ReleaseVersion,
    [string]$CertificateThumbprint,
    [string]$SignToolPath,
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'

$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$distDir = Join-Path $projectDir 'dist'
$source = Join-Path $projectDir 'Program.cs'
$manifest = Join-Path $projectDir 'app.manifest'
$officialOutputName = 'AgentSshKeyManager.exe'
$unsignedReleaseOutputName = 'AgentSshKeyManager-UNSIGNED.exe'
$developmentOutputName = 'AgentSshKeyManager-UNSIGNED-DEVELOPMENT.exe'

function Resolve-SignTool {
    param([string]$RequestedPath)

    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        $resolved = Resolve-Path -LiteralPath $RequestedPath -ErrorAction Stop
        if (-not (Test-Path -LiteralPath $resolved.ProviderPath -PathType Leaf)) {
            throw "SignToolPath is not a file: $RequestedPath"
        }
        if (-not [System.IO.Path]::GetFileName($resolved.ProviderPath).Equals('signtool.exe', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'SignToolPath must identify signtool.exe from the Windows SDK.'
        }
        return $resolved.ProviderPath
    }

    $command = Get-Command 'signtool.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $command) {
        throw 'signtool.exe was not found. Install the Windows SDK signing tools, add signtool.exe to PATH, or provide -SignToolPath. See docs/CODE_SIGNING.md.'
    }
    return $command.Source
}

function Test-ValidatedStagingPath {
    param(
        [string]$CandidatePath,
        [string]$ExpectedParent
    )

    $candidateFull = [System.IO.Path]::GetFullPath($CandidatePath)
    $parentFull = [System.IO.Path]::GetFullPath($ExpectedParent)
    $candidateParent = [System.IO.Directory]::GetParent($candidateFull)
    if (-not $candidateParent -or -not $candidateParent.FullName.Equals($parentFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $false
    }

    return [System.IO.Path]::GetFileName($candidateFull) -match '^\.AgentSshKeyManager-staging-[0-9a-f]{32}$'
}

function Remove-ValidatedStagingDirectory {
    param(
        [string]$CandidatePath,
        [string]$ExpectedParent
    )

    if (-not (Test-Path -LiteralPath $CandidatePath)) {
        return
    }
    if (-not (Test-ValidatedStagingPath -CandidatePath $CandidatePath -ExpectedParent $ExpectedParent)) {
        Write-Warning "Refusing to remove an unvalidated staging path: $CandidatePath"
        return
    }

    $item = Get-Item -LiteralPath $CandidatePath -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Write-Warning "Refusing to recursively remove a staging reparse point: $CandidatePath"
        return
    }

    try {
        Remove-Item -LiteralPath $CandidatePath -Recurse -Force -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not remove staging directory '$CandidatePath': $($_.Exception.Message)"
    }
}

function Invoke-StagedSelfTest {
    param(
        [string]$ExecutablePath,
        [string]$ReportPath
    )

    $process = $null
    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $ExecutablePath
        $startInfo.Arguments = '--self-test "' + $ReportPath + '"'
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true

        $process = [System.Diagnostics.Process]::Start($startInfo)
        if (-not $process.WaitForExit(120000)) {
            try {
                $process.Kill()
                $process.WaitForExit()
            }
            catch {
                Write-Warning "Could not stop timed-out self-test process: $($_.Exception.Message)"
            }
            throw 'The staged executable self-test timed out after 120 seconds.'
        }

        $selfTestExitCode = $process.ExitCode
        $selfTestReport = if (Test-Path -LiteralPath $ReportPath -PathType Leaf) {
            Get-Content -LiteralPath $ReportPath -Raw
        }
        else {
            ''
        }
        $selfTestPassed = $selfTestExitCode -eq 0 -and $selfTestReport -match '(?m)^SELF-TEST OK\r?$'
        if (-not $selfTestPassed) {
            $details = if ([string]::IsNullOrWhiteSpace($selfTestReport)) { 'The self-test report was not created.' } else { $selfTestReport.Trim() }
            throw "Staged executable self-test failed (code $selfTestExitCode).`r`n$details"
        }
    }
    finally {
        if ($process) {
            $process.Dispose()
        }
        if (Test-Path -LiteralPath $ReportPath -PathType Leaf) {
            Remove-Item -LiteralPath $ReportPath -Force
        }
    }
}

$signingArgumentNames = @('CertificateThumbprint', 'SignToolPath', 'TimestampUrl')
$suppliedSigningArguments = @($signingArgumentNames | Where-Object { $PSBoundParameters.ContainsKey($_) })

if ($UnsignedDevelopmentBuild) {
    $conflictingArguments = @()
    if ($UnsignedRelease) { $conflictingArguments += 'UnsignedRelease' }
    if ($PSBoundParameters.ContainsKey('ReleaseVersion')) { $conflictingArguments += 'ReleaseVersion' }
    $conflictingArguments += $suppliedSigningArguments
    if ($conflictingArguments.Count -gt 0) {
        throw "-UnsignedDevelopmentBuild cannot be combined with release options: $($conflictingArguments -join ', ')."
    }
    $buildMode = 'UnsignedDevelopment'
}
elseif ($UnsignedRelease) {
    if ($suppliedSigningArguments.Count -gt 0) {
        throw "-UnsignedRelease cannot be combined with signing options: $($suppliedSigningArguments -join ', ')."
    }
    if ([string]::IsNullOrWhiteSpace($ReleaseVersion)) {
        throw 'Unsigned release mode requires -ReleaseVersion.'
    }
    $buildMode = 'UnsignedRelease'
}
else {
    if (-not $PSBoundParameters.ContainsKey('ReleaseVersion') -and -not $PSBoundParameters.ContainsKey('CertificateThumbprint')) {
        throw 'Choose an explicit mode: use -UnsignedDevelopmentBuild; use -UnsignedRelease with -ReleaseVersion; or provide -ReleaseVersion and -CertificateThumbprint for a signed release.'
    }
    if ([string]::IsNullOrWhiteSpace($ReleaseVersion)) {
        throw 'Signed release mode requires -ReleaseVersion.'
    }
    if ([string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
        throw 'Signed release mode requires -CertificateThumbprint.'
    }
    $buildMode = 'SignedRelease'
}

$isSignedRelease = $buildMode -eq 'SignedRelease'
$isUnsignedReleaseMode = $buildMode -eq 'UnsignedRelease'
$isVersionedRelease = $isSignedRelease -or $isUnsignedReleaseMode

$compilerCandidates = @(
    "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe"
)
$compiler = $compilerCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $compiler) {
    throw 'The .NET Framework C# compiler was not found.'
}

$buildId = [Guid]::NewGuid().ToString('N')
$stagingDir = Join-Path $distDir ('.AgentSshKeyManager-staging-' + $buildId)

if (Test-Path -LiteralPath $distDir) {
    $distItem = Get-Item -LiteralPath $distDir -Force
    if (-not $distItem.PSIsContainer) {
        throw "The build output path is not a directory: $distDir"
    }
    if (($distItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to build through a reparse-point output directory: $distDir"
    }
}

if ($isVersionedRelease) {
    $normalizedVersion = $ReleaseVersion.Trim()
    if ($normalizedVersion.StartsWith('v', [System.StringComparison]::OrdinalIgnoreCase)) {
        $normalizedVersion = $normalizedVersion.Substring(1)
    }
    $semanticVersionPattern = '^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$'
    if ($normalizedVersion -notmatch $semanticVersionPattern) {
        throw 'ReleaseVersion must be a semantic version such as 1.1.0 or v1.1.0-beta.1.'
    }

    $versionCore = ($normalizedVersion -split '[-+]')[0]
    $versionComponents = @($versionCore.Split('.'))
    foreach ($component in $versionComponents) {
        $componentValue = [uint16]0
        if (-not [uint16]::TryParse($component, [ref]$componentValue) -or $componentValue -eq [uint16]::MaxValue) {
            throw 'Each numeric ReleaseVersion component must be between 0 and 65534.'
        }
    }
    $assemblyVersion = "$versionCore.0"
    $finalDir = Join-Path $distDir ('v' + $normalizedVersion)

    if ($isSignedRelease) {
        $informationalVersion = $normalizedVersion
        $assemblyConfiguration = 'Release'
        $assemblyDescription = 'Manages temporary SSH access for authorized server administration.'

        $normalizedThumbprint = ($CertificateThumbprint -replace '[\s\p{Cf}]', '').ToUpperInvariant()
        if ($normalizedThumbprint -notmatch '^[0-9A-F]{40}$') {
            throw 'CertificateThumbprint must be the 40-character hexadecimal SHA-1 thumbprint used by SignTool /sha1.'
        }

        $TimestampUrl = $TimestampUrl.Trim()
        $timestampUri = $null
        if (-not [Uri]::TryCreate($TimestampUrl, [UriKind]::Absolute, [ref]$timestampUri) -or
            ($timestampUri.Scheme -ne 'http' -and $timestampUri.Scheme -ne 'https')) {
            throw 'TimestampUrl must be an absolute HTTP or HTTPS URL for an RFC 3161 timestamp service.'
        }

        $resolvedSignTool = Resolve-SignTool -RequestedPath $SignToolPath
        $outputName = $officialOutputName
    }
    else {
        $informationalVersion = $normalizedVersion + '-unsigned'
        $assemblyConfiguration = 'UnsignedRelease'
        $assemblyDescription = 'UNSIGNED RELEASE of Agent SSH Key Manager; no Authenticode publisher signature.'
        $outputName = $unsignedReleaseOutputName
    }
}
else {
    $outputName = $developmentOutputName
    $developmentDirectoryName = 'dev-unsigned-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + $buildId.Substring(0, 8)
    $finalDir = Join-Path $distDir $developmentDirectoryName
    $assemblyVersion = '0.0.0.1'
    $informationalVersion = '0.0.0-dev'
    $assemblyConfiguration = 'UnsignedDevelopment'
    $assemblyDescription = 'UNSIGNED DEVELOPMENT BUILD of Agent SSH Key Manager.'
}

if (Test-Path -LiteralPath $finalDir) {
    throw "Output directory already exists; refusing to overwrite it: $finalDir"
}
if (Test-Path -LiteralPath $stagingDir) {
    throw "Staging directory unexpectedly already exists: $stagingDir"
}

$stagedOutput = Join-Path $stagingDir $outputName
$stagedChecksum = $stagedOutput + '.sha256'
$selfTestReport = Join-Path $stagingDir '.self-test-report.txt'
$generatedAssemblyInfo = Join-Path $stagingDir 'AssemblyInfo.generated.cs'
$generatedManifest = Join-Path $stagingDir 'app.generated.manifest'
$stagingCreated = $false
$published = $false

try {
    [System.IO.Directory]::CreateDirectory($distDir) | Out-Null
    [System.IO.Directory]::CreateDirectory($stagingDir) | Out-Null
    $stagingCreated = $true

    $assemblyInfoSource = @"
using System.Reflection;

[assembly: AssemblyTitle("Agent SSH Key Manager")]
[assembly: AssemblyProduct("Agent SSH Key Manager")]
[assembly: AssemblyDescription("$assemblyDescription")]
[assembly: AssemblyCompany("Sven Reischauer")]
[assembly: AssemblyCopyright("Copyright (c) 2026 Sven Reischauer")]
[assembly: AssemblyConfiguration("$assemblyConfiguration")]
[assembly: AssemblyVersion("$assemblyVersion")]
[assembly: AssemblyFileVersion("$assemblyVersion")]
[assembly: AssemblyInformationalVersion("$informationalVersion")]
"@
    Set-Content -LiteralPath $generatedAssemblyInfo -Value $assemblyInfoSource -Encoding utf8

    $manifestXml = New-Object System.Xml.XmlDocument
    $manifestXml.PreserveWhitespace = $true
    $manifestXml.Load($manifest)
    $manifestIdentity = $manifestXml.SelectSingleNode("/*[local-name()='assembly']/*[local-name()='assemblyIdentity']")
    if (-not $manifestIdentity) {
        throw 'The application manifest does not contain an assemblyIdentity element.'
    }
    $manifestIdentity.SetAttribute('version', $assemblyVersion)
    $manifestWriterSettings = New-Object System.Xml.XmlWriterSettings
    $manifestWriterSettings.Encoding = New-Object System.Text.UTF8Encoding($false)
    $manifestWriterSettings.Indent = $false
    $manifestWriter = [System.Xml.XmlWriter]::Create($generatedManifest, $manifestWriterSettings)
    try {
        $manifestXml.Save($manifestWriter)
    }
    finally {
        $manifestWriter.Dispose()
    }

    Push-Location -LiteralPath $stagingDir
    try {
        & $compiler `
            /nologo `
            /target:winexe `
            /platform:anycpu `
            /optimize+ `
            /warn:4 `
            "/win32manifest:$generatedManifest" `
            "/out:$stagedOutput" `
            /reference:System.dll `
            /reference:System.Core.dll `
            /reference:System.Drawing.dll `
            /reference:System.Windows.Forms.dll `
            /reference:System.Xml.dll `
            $source `
            $generatedAssemblyInfo
        $compilerExitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }

    if ($compilerExitCode -ne 0) {
        throw "Compilation failed (code $compilerExitCode)."
    }

    Remove-Item -LiteralPath $generatedAssemblyInfo -Force
    Remove-Item -LiteralPath $generatedManifest -Force

    if ($isSignedRelease) {
        & $resolvedSignTool sign /sha1 $normalizedThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $stagedOutput
        $signExitCode = $LASTEXITCODE
        if ($signExitCode -ne 0) {
            throw "Code signing or timestamping failed (code $signExitCode)."
        }

        & $resolvedSignTool verify /pa /tw /v $stagedOutput
        $verifyExitCode = $LASTEXITCODE
        if ($verifyExitCode -ne 0) {
            throw "Signature or timestamp verification failed (code $verifyExitCode)."
        }

        $authenticodeSignature = Get-AuthenticodeSignature -LiteralPath $stagedOutput
        if ($authenticodeSignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
            throw "Authenticode verification did not report Valid status: $($authenticodeSignature.Status)."
        }
        if (-not $authenticodeSignature.SignerCertificate) {
            throw 'Authenticode verification did not return a signer certificate.'
        }
        if (-not $authenticodeSignature.TimeStamperCertificate) {
            throw 'Authenticode verification did not return an RFC 3161 timestamp certificate.'
        }
        $verifiedThumbprint = ($authenticodeSignature.SignerCertificate.Thumbprint -replace '[\s\p{Cf}]', '').ToUpperInvariant()
        if (-not $verifiedThumbprint.Equals($normalizedThumbprint, [System.StringComparison]::Ordinal)) {
            throw "The signed artifact thumbprint '$verifiedThumbprint' does not match the requested certificate thumbprint '$normalizedThumbprint'."
        }
    }

    Invoke-StagedSelfTest -ExecutablePath $stagedOutput -ReportPath $selfTestReport

    $hash = (Get-FileHash -LiteralPath $stagedOutput -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath $stagedChecksum -Value ("$hash *$outputName") -Encoding ascii -NoNewline

    [System.IO.Directory]::Move($stagingDir, $finalDir)
    $published = $true
}
finally {
    if ($stagingCreated -and -not $published) {
        Remove-ValidatedStagingDirectory -CandidatePath $stagingDir -ExpectedParent $distDir
    }
}

$finalOutput = Join-Path $finalDir $outputName
$finalChecksum = $finalOutput + '.sha256'
if ($isSignedRelease) {
    Write-Host "Created signed release: $finalOutput"
}
elseif ($isUnsignedReleaseMode) {
    Write-Warning 'Created an UNSIGNED RELEASE. It has no Authenticode publisher identity or signature and may be treated as untrusted.'
    Write-Host "Created unsigned release: $finalOutput"
}
else {
    Write-Warning 'Created an UNSIGNED DEVELOPMENT build. Do not publish it as an official release.'
    Write-Host "Created unsigned development build: $finalOutput"
}
Write-Host "SHA-256: $finalChecksum"
