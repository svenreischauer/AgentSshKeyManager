# Code signing and releases

Agent SSH Key Manager uses one production-signing backend: Microsoft SignTool with an Authenticode code-signing certificate selected by its SHA-1 certificate thumbprint. The file and timestamp digests are SHA-256; `/sha1` is only SignTool's certificate selector.

Signing establishes publisher identity and shows whether the executable changed after signing. It does not prove that software is harmless, instantly establish SmartScreen reputation, or guarantee that Sophos will allow behavior such as provisioning privileged SSH access.

## Install SignTool

Install the current [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/) from Microsoft. SignTool is normally located in a versioned SDK directory such as:

```text
C:\Program Files (x86)\Windows Kits\10\bin\<SDK-version>\x64\signtool.exe
```

The build finds `signtool.exe` on `PATH`, or you can pass that full path with `-SignToolPath`. The build does not install SDK components or modify `PATH`. See Microsoft's [SignTool reference](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool) for the supported options and exit codes.

## Obtain a suitable certificate

For a public GitHub release, obtain a publicly trusted Authenticode code-signing certificate for the individual or organization that should appear as the publisher. Confirm before purchase that the supplied hardware token, HSM, or cloud client exposes the certificate and private-key provider to Windows SignTool through the current user's certificate store. Token-backed certificates can prompt for a PIN during signing, so run the release interactively unless the provider documents a secure unattended workflow.

Publicly trusted code-signing keys issued under current industry rules normally have to remain in approved hardware or a signing service. Do not expect a newly issued private key to be exportable as a PFX, and do not put a PFX password or token PIN in this script, command history, environment variables, or build logs. See the [CA/Browser Forum Code Signing Baseline Requirements](https://cabforum.org/working-groups/code-signing/requirements/).

A private-CA or self-signed certificate is suitable only when every target computer is configured to trust that root. It does not create public trust for downloads from GitHub.

Managed signing services require their own integration and are not accepted by this build's thumbprint mode unless their provider makes the certificate available through a SignTool-compatible Windows cryptographic provider. In particular:

- Microsoft Artifact Signing uses provider-specific client tools. As of September 2026, Microsoft documents Public Trust availability for EU organizations, while individual developers must be in the United States or Canada. Check the current [Artifact Signing prerequisites](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart) before choosing it.
- [SignPath Foundation](https://signpath.org/) offers a separate signing workflow for eligible open-source projects, with repository, provenance, metadata, and approval requirements. Its certificate identifies SignPath Foundation as the publisher.

After installing the certificate and any token/provider middleware, list usable current-user certificates:

```powershell
Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
    Where-Object HasPrivateKey |
    Select-Object Subject, Thumbprint, NotAfter, HasPrivateKey
```

The thumbprint is not a secret. The private key and any PIN are. Certificate renewal produces a new thumbprint, so update the release command after every renewal. A trusted RFC 3161 timestamp allows an existing signature to remain verifiable after the signing certificate expires.

## Explicit unsigned releases

When no suitable certificate is available and publishing cannot wait, an unsigned release must be requested explicitly:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Build.ps1 `
    -ReleaseVersion 1.0.1 `
    -UnsignedRelease
```

The command creates these files after the staged executable passes its self-test:

```text
dist\v1.0.1\AgentSshKeyManager-UNSIGNED.exe
dist\v1.0.1\AgentSshKeyManager-UNSIGNED.exe.sha256
```

The executable has assembly and manifest version `1.0.1.0`, product version `1.0.1-unsigned`, and an unsigned-release description/configuration. `-UnsignedRelease` is mutually exclusive with the development switch, certificate thumbprint, SignTool path, and timestamp options. The version directory must not already exist.

This mode does not create publisher trust. Windows, SmartScreen, Sophos, or another security product may warn, quarantine, or block the executable. The checksum detects a mismatch only when the expected checksum itself came from a trusted channel; an attacker able to replace both release assets can replace both values. Keep `-UNSIGNED` in the filename and release notes. The basename `AgentSshKeyManager.exe` remains reserved for the signed mode.

You can confirm the expected unsigned state and checksum without interpreting `NotSigned` as a security approval:

```powershell
$executable = '.\dist\v1.0.1\AgentSshKeyManager-UNSIGNED.exe'
$checksum = $executable + '.sha256'
$signature = Get-AuthenticodeSignature -LiteralPath $executable
if ($signature.Status -ne 'NotSigned') { throw "Unexpected signature status: $($signature.Status)" }

$expectedHash = ((Get-Content -LiteralPath $checksum -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
$actualHash = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) { throw 'SHA-256 checksum mismatch.' }
```

## Build a signed release

First create an unsigned development build. The build runs its self-test before publishing the development artifact:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Build.ps1 -UnsignedDevelopmentBuild
```

Then create the signed release. Use a new semantic version; the build refuses to replace an existing version directory:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Build.ps1 `
    -ReleaseVersion 1.1.0 `
    -CertificateThumbprint '40_HEXADECIMAL_CHARACTERS' `
    -SignToolPath 'C:\Program Files (x86)\Windows Kits\10\bin\<SDK-version>\x64\signtool.exe'
```

The build compiles in a staging directory under `dist`, writes matching assembly and application-manifest versions, signs exactly once, requires timestamp and signature verification to return exit code zero, runs the signed executable's self-test, hashes the signed bytes, and then renames the complete staging directory to `dist\v1.1.0`.

On failure, no version directory is published and prior successful directories are preserved. Only the build's validated GUID-named staging directory is eligible for automatic cleanup.

## Verify the artifact

Verify the exact files that will be uploaded:

```powershell
$releaseDirectory = '.\dist\v1.1.0'
$executable = Join-Path $releaseDirectory 'AgentSshKeyManager.exe'
$checksum = $executable + '.sha256'
$signTool = 'C:\Program Files (x86)\Windows Kits\10\bin\<SDK-version>\x64\signtool.exe'

& $signTool verify /pa /tw /v $executable
if ($LASTEXITCODE -ne 0) { throw "SignTool verification failed: $LASTEXITCODE" }

$signature = Get-AuthenticodeSignature -LiteralPath $executable
$signature | Format-List Status, StatusMessage, SignerCertificate, TimeStamperCertificate
if ($signature.Status -ne 'Valid') { throw "Authenticode status: $($signature.Status)" }

$expectedHash = ((Get-Content -LiteralPath $checksum -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
$actualHash = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) { throw 'SHA-256 checksum mismatch.' }
```

Confirm that the signer subject is the publisher identity you expect. A checksum published beside an executable detects corruption or mismatch; the Authenticode signature supplies publisher authentication.

## Release checklist

1. Confirm the intended source commit and release version, and review the working tree.
2. Run the unsigned development build and confirm its automatic self-test succeeds.
3. Prefer a signed release. If an unsigned release is intentional, use `-UnsignedRelease` and retain the `-UNSIGNED` filename; never substitute development output.
4. For a signed artifact, verify the timestamp, signature status, signer identity, and checksum. For an unsigned artifact, confirm the expected `NotSigned` status and checksum without claiming publisher trust.
5. On an authorized disposable Ubuntu host, run Create, automatic key verification, and Remove in both dedicated-account and existing-user modes. Cover server-side expiry enabled and disabled. Verify key rejection after removal and, for dedicated mode, confirm that the temporary account, processes, home directory, key, `/etc/sudoers.d` entry, and `/var/lib/agent-ssh-key-manager/*.owner` marker are gone.
6. Exercise the interactive failure paths: wrong SSH or sudo password, host-key rejection, unreachable host, cancellation/window close, and a remote nonzero exit. Confirm that the main GUI survives, the console keeps detailed output visible until ENTER, and the numeric exit result reaches the GUI.
7. Test the exact release executable on the Sophos-protected endpoint under the intended policy. Run both Create and Remove, then check local events and Sophos Central. If Sophos blocks intended behavior, retain the event details and submit the exact sample/hash for false-positive review. Do not disable protection or add a broad exclusion.
8. Upload the executable and its matching `.sha256` file from the version directory without renaming either. Download them again and repeat the appropriate signed or unsigned verification before announcing the release.
