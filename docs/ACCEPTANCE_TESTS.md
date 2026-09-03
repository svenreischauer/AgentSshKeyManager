# Ubuntu acceptance tests

Last full external run: 2026-09-03

## Environment

- Linux Mint 22.3 KVM host
- disposable Ubuntu Server 24.04 cloud-image guest
- QEMU/KVM with a user-mode TCP forward to guest OpenSSH
- guest SSH baseline:

  ```text
  PasswordAuthentication no
  KbdInteractiveAuthentication no
  PubkeyAuthentication yes
  PermitRootLogin prohibit-password
  ```

- unencrypted Ed25519 PuTTY PPK bootstrap key for `root`
- passphrase-protected Ed25519 OpenSSH bootstrap key for a `bootstrap` sudo user
- random test-only Linux/sudo password, read from an ACL-protected file rather than a process argument

The VM and credential fixtures were created outside the repository. The QEMU lab script validates the target filesystem UUID, refuses an existing guest/service target, verifies the Ubuntu image checksum, and keeps fixture files root-only.

## Results

| Scenario | Result |
| --- | --- |
| Host-key exchange and exact raw-key pinning | Passed |
| Password login disabled and public-key login offered | Passed |
| PuTTY `.ppk` authentication as `root` | Passed |
| Dedicated temporary user with `sudo NOPASSWD` | Passed |
| Encrypted OpenSSH authentication as an existing sudo user | Passed |
| Missing and incorrect key passphrase diagnostics | Passed |
| Incorrect sudo password diagnostic | Passed |
| Existing-user target mode | Passed |
| Optional server-side key expiry | Passed |
| Generated-key login verification before activation | Passed |
| Mismatched raw server host key rejected | Passed |
| Marker-only removal preserving the original `authorized_keys` content | Passed |
| Dedicated user, sudoers file, home, and owner marker removed | Passed |
| Generated key rejected after removal | Passed |
| Manual install, verification, and cleanup | Passed |
| Partial setup failure followed by automatic rollback | Passed |
| SSH password mode temporarily enabled; correct and incorrect password distinguished | Passed |
| Password and keyboard-interactive login restored to disabled after the test | Passed |
| Restoration failure reported, then live password authentication restored and verified | Passed |
| Dedicated account externally removed while its exact session-owned home remains | Passed |
| No temporary account, key marker, sudoers file, or ownership marker remains | Passed |
| Bootstrap secrets absent from process arguments and saved metadata | Passed |
| Runtime C# sources contain no PowerShell or execution-policy launch | Passed |
| Built-in local regression/self-test | Passed |

The automated harness is [`tests/UbuntuAcceptanceHarness.cs`](../tests/UbuntuAcceptanceHarness.cs). It compiles alongside the application sources with an explicit test entry point and is not included in the release EXE. Cleanup targets are registered before installation so a failed assertion still attempts marker/account removal.

The built-in self-test cleans the non-script legacy result fixture without creating a temporary `.ps1` file. The external harness additionally verifies that a broken test-only `sshd` drop-in reports a restoration failure, then restores and verifies the live SSH password-authentication state.

## Manual release checks still required

Automated server tests cannot establish whether a particular organization's endpoint-security policy trusts an unsigned binary. Before publishing a release:

1. verify the rendered GUI and clipboard buttons interactively;
2. run Create and Delete once on the intended Windows/Sophos policy;
3. inspect the local Sophos event and central console;
4. verify the Authenticode signature and published SHA256 checksum; and
5. repeat the test after changing SSH.NET, the compiler, signing configuration, or process-launch behavior.
