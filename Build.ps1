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
$sources = @(
    (Join-Path $projectDir 'Program.cs'),
    (Join-Path $projectDir 'EmbeddedDependencyLoader.cs'),
    (Join-Path $projectDir 'ExistingKeyBootstrap.cs'),
    (Join-Path $projectDir 'BootstrapDialogs.cs'),
    (Join-Path $projectDir 'MainFormBootstrap.cs')
)
$dependencyDir = Join-Path $projectDir 'lib\sshnet-2026.0.0'
$dependencyNames = @(
    'Renci.SshNet.dll',
    'BouncyCastle.Cryptography.dll',
    'Microsoft.Bcl.AsyncInterfaces.dll',
    'Microsoft.Bcl.Cryptography.dll',
    'Microsoft.Extensions.DependencyInjection.Abstractions.dll',
    'Microsoft.Extensions.Logging.Abstractions.dll',
    'System.Buffers.dll',
    'System.Formats.Asn1.dll',
    'System.Memory.dll',
    'System.Numerics.Vectors.dll',
    'System.Runtime.CompilerServices.Unsafe.dll',
    'System.Threading.Tasks.Extensions.dll',
    'System.ValueTuple.dll'
)
$dependencyPaths = @($dependencyNames | ForEach-Object { Join-Path $dependencyDir $_ })
$expectedDependencyHashes = @{
    'BouncyCastle.Cryptography.dll' = '4f96977e9c67334742c683410b3a361258219f0d3084a5e0bc10fba96cf23a0d'
    'Microsoft.Bcl.AsyncInterfaces.dll' = '80678203bd0203a6594f4e330b22543c0de5059382bb1c9334b7868b8f31b1bc'
    'Microsoft.Bcl.Cryptography.dll' = '1f9464239423039ae8fe6eca2573de5f498155b15604bdc3740e7cbe8a3e5300'
    'Microsoft.Extensions.DependencyInjection.Abstractions.dll' = '19edd4f5e69a4589dc314909b5854a22f89c4b9ab040591771397b2cb1a17ba6'
    'Microsoft.Extensions.Logging.Abstractions.dll' = 'b4e0e778afdc76403792390b056f68de0ced742d16c5b0347d9cca6930f4761b'
    'Renci.SshNet.dll' = '582581d9d533f05411ec577cdb88dd86b49b35d0d9656c3e0515e02f799191a2'
    'System.Buffers.dll' = '2d78d770c9cb997199154ae8c018b9f1d1efbc86729f7264dde6dbad2a12cac3'
    'System.Formats.Asn1.dll' = '8a83da38d527d78bc66dfbdaf041396c75a0f11acadc558479277ebb7e1ad8ec'
    'System.Memory.dll' = 'd5e8e4866f9cfa66f7765660f84b210198893e55335487afe5ebda342c0e913d'
    'System.Numerics.Vectors.dll' = '20c2fa81b8c70d651099d762954f285fd4f942e63b2d7217c145dab8d4b2f4c9'
    'System.Runtime.CompilerServices.Unsafe.dll' = '08cbd7278b66f1e68425a82d4b97181a4130d93e3dd91831407aba7212ccdacf'
    'System.Threading.Tasks.Extensions.dll' = '4f81ffd0dc7204db75afc35ea4291769b07c440592f28894260eea76626a23c6'
    'System.ValueTuple.dll' = '400e432af60a6a2b3eedec5908be7e7ae0d063ecf0052595f7cd6cffb7e4e98e'
}
$licenseFile = Join-Path $projectDir 'LICENSE'
$thirdPartyNoticesFile = Join-Path $projectDir 'THIRD-PARTY-NOTICES.md'
foreach ($requiredFile in $sources + $dependencyPaths + @($licenseFile, $thirdPartyNoticesFile)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "Required build input is missing: $requiredFile"
    }
}
foreach ($dependencyPath in $dependencyPaths) {
    $dependencyName = [System.IO.Path]::GetFileName($dependencyPath)
    $actualHash = (Get-FileHash -LiteralPath $dependencyPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if (-not $expectedDependencyHashes.ContainsKey($dependencyName) -or
        -not $actualHash.Equals($expectedDependencyHashes[$dependencyName], [System.StringComparison]::Ordinal)) {
        throw "Dependency integrity check failed: $dependencyName"
    }
}
$thirdPartyNoticesText = [System.IO.File]::ReadAllText($thirdPartyNoticesFile)
if (-not $thirdPartyNoticesText.Contains('Copyright (c) 2000-2026 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org).') -or
    -not $thirdPartyNoticesText.Contains('publish, distribute, sublicense, and/or sell') -or
    $thirdPartyNoticesText.Contains('sub license')) {
    throw 'THIRD-PARTY-NOTICES.md does not contain the exact Bouncy Castle 2.7.0 copyright and MIT license notice.'
}
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
        $compilerArguments = @(
            '/nologo',
            '/target:winexe',
            '/platform:anycpu',
            '/optimize+',
            '/warn:4',
            "/win32manifest:$generatedManifest",
            "/out:$stagedOutput",
            '/reference:System.dll',
            '/reference:System.Core.dll',
            '/reference:System.Drawing.dll',
            '/reference:System.Windows.Forms.dll',
            '/reference:System.Xml.dll'
        )
        foreach ($dependencyPath in $dependencyPaths) {
            $compilerArguments += "/reference:$dependencyPath"
            $resourceName = [System.IO.Path]::GetFileNameWithoutExtension($dependencyPath)
            $compilerArguments += "/resource:$dependencyPath,AgentSshKeyManager.Dependencies.$resourceName.dll,private"
        }
        $compilerArguments += @($sources | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
        $compilerArguments += $generatedAssemblyInfo
        & $compiler @compilerArguments
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
    [System.IO.File]::Copy($licenseFile, (Join-Path $stagingDir 'LICENSE'), $false)
    $stagedThirdPartyNotices = Join-Path $stagingDir 'THIRD-PARTY-NOTICES.md'
    [System.IO.File]::Copy($thirdPartyNoticesFile, $stagedThirdPartyNotices, $false)
    $sourceNoticeHash = (Get-FileHash -LiteralPath $thirdPartyNoticesFile -Algorithm SHA256).Hash
    $stagedNoticeHash = (Get-FileHash -LiteralPath $stagedThirdPartyNotices -Algorithm SHA256).Hash
    if (-not $sourceNoticeHash.Equals($stagedNoticeHash, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The staged third-party notice does not match the reviewed source notice.'
    }

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
