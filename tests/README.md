# Acceptance-test lab

These files are maintainer tests. They are not compiled into or invoked by `AgentSshKeyManager.exe`.

Never point the harness at a production server. It deliberately creates and removes users, keys, sudoers files, and temporary SSH configuration in a disposable Ubuntu guest.

## Components

- `ubuntu-lab/create-qemu-lab.sh` creates an Ubuntu 24.04 QEMU/KVM guest on an explicitly selected Linux filesystem.
- `UbuntuAcceptanceHarness.cs` drives the Windows application classes against that guest.

The lab creates two test-only bootstrap credentials: an unencrypted PuTTY PPK for root and a passphrase-protected OpenSSH key for a sudo user. Password and passphrase values are generated randomly and stored in root-only fixture files. They are never command-line arguments.

## Create the guest

The Linux host needs QEMU/KVM, `qemu-img`, `cloud-localds`, `curl`, OpenSSL, and `puttygen`. Inspect the script before running it, then copy it to the Linux host without changing LF line endings.

Run it as root with an exact mount point, the expected filesystem UUID, and an unused non-privileged TCP port:

```bash
sudo ./create-qemu-lab.sh /mnt/ssh-test-lab EXPECTED-FILESYSTEM-UUID 2222
```

The script:

- resolves and validates the mount point;
- checks the filesystem UUID;
- rejects symlinked/redirection targets and an existing guest or service;
- downloads the official Ubuntu cloud image and verifies its SHA256 checksum;
- creates a 32 GiB copy-on-write guest disk; and
- starts a two-vCPU, 4 GiB RAM VM with the selected host port forwarded to guest SSH.

Its fixed service name is `agent-ssh-acceptance`. Do not run two copies on the same host.

## Run the Windows harness

Copy the guest fixture directory to an ACL-protected temporary directory outside the repository. Do not print or paste the private keys, password, or passphrase. Compile `UbuntuAcceptanceHarness.cs` alongside the normal application sources with an explicit entry point:

```text
/main:AgentSshKeyManager.UbuntuAcceptanceTestProgram
```

Reference and embed the same DLL set and resource names used by `Build.ps1`. The harness arguments are:

```text
UbuntuAcceptanceHarness.exe HOST PORT FIXTURE_DIRECTORY WORK_DIRECTORY REPORT_FILE
```

Only paths, host, and port appear on the command line. The harness reads secret values directly from the protected fixture files. It registers server cleanup before each installation and writes a pass/fail report containing no credentials.

The recorded matrix and latest result are in [`docs/ACCEPTANCE_TESTS.md`](../docs/ACCEPTANCE_TESTS.md).

## Cleanup

After testing:

1. confirm the report ends with `ACCEPTANCE TESTS OK`;
2. delete the local fixture and generated-work directory with the same Windows identity that owns its ACL;
3. stop and disable the lab VM if it is no longer needed:

   ```bash
   sudo systemctl disable --now agent-ssh-acceptance.service
   ```

4. retain or remove the VM disk only according to the lab host's own data-retention policy.

The harness also simulates an OpenSSH option that is accepted as file content but rejected during generated-key login. It verifies existing-key, password-style atomic replacement, and manual retry behavior, including session-bound cleanup confirmation. It additionally creates the recovery case where a dedicated test account has already been removed but its exact session-owned home remains, and verifies that the manager removes that residue.

Before it reports success, the harness verifies that no `agentssh_` test user or home directory, `agent-ssh-access:` authorized-key marker, manager sudoers file, ownership marker, or password-login override remains in the guest.
