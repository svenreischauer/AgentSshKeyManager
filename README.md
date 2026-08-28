# Agent SSH Key Manager

Agent SSH Manager is a portable Windows tool for creating, installing, and removing temporary SSH keys for AI agents (e.g., Claude Code) on Ubuntu servers.
Administer remote servers by AI agents is convenient however, you want to do it without sharing your ssh credentials. With Agent SSH Manager, you can generate temporary SSH keys for your agent, granting them sudo access to the server without exposing your personal credentials.


The finished application is `AgentSshKeyManager.exe`. It requires no installer and uses the Windows OpenSSH client.

## What it does

- Generates a separate Ed25519 key for every access session.
- Opens a separate SSH window for entering SSH and sudo passwords. Passwords are never entered into, stored by, or logged by the application.
- Installs the public key either for the existing SSH user or for a dedicated temporary Linux account.
- Creates an SSH configuration that disables password and keyboard-interactive authentication for the agent connection.
- Disables SSH agent, port, and X11 forwarding for the installed key.
- Tests the key before marking the access as active.
- Removes the server-side key and deletes the local private key when access is removed successfully.

The temporary private key grants access to the server while it is active. Do not paste the private key into chat, email, or tickets.

## Recommended mode: temporary account with sudo

The dedicated temporary account option is enabled by default. The tool creates a randomly named Linux account such as `agentssh_a1b2c3d4e5`, installs the public key, and adds a `visudo`-validated passwordless sudo rule for that account.

Removing the access stops processes owned by the temporary account and deletes its key, sudo rule, home directory, and user account.

This mode gives the temporary account full administrator rights. Use it only on systems where you are authorized to do so, and only for the required duration.

## Existing-user mode

If the dedicated-account option is disabled, the tool adds the temporary key to the selected user's `~/.ssh/authorized_keys` file. The user's existing sudo configuration is not changed. If sudo requires a password, unattended administrative commands will not work in this mode.

## Usage

1. Start `AgentSshKeyManager.exe`.
2. Enter the server address, SSH user, port, and planned duration.
3. Click **Create access**.
4. Verify the server fingerprint against a trusted source before accepting it.
5. Enter the SSH and, when requested, sudo passwords in the separate window.
6. Select the active session and click **Copy agent SSH command**.
7. Paste only that command into the agent task.
8. When the work is finished, select the session and click **Remove access**.

The clipboard is used only when **Copy agent SSH command** is clicked. The application never copies anything automatically.

An agent SSH command looks like this:

```text
ssh.exe -F "C:\...\ssh_config" agent-ssh-a1b2c3d4e5
```

## Expiry and removal

The planned duration is a local reminder unless **OpenSSH expiry option** is enabled. The optional server-side expiry blocks new logins after the expiry time, but it does not terminate an already open SSH session. Always remove the access when the work is complete.

If the server rejects the optional expiry setting, the tool can retry without it. The access must then be removed manually.

## Local data

Session data is stored in:

```text
%LOCALAPPDATA%\AgentSshKeyManager\Sessions
```

Private keys have no passphrase so an agent can use them unattended. The application restricts their NTFS permissions to the current Windows user and `SYSTEM`. After confirmed removal, secret local files are deleted; non-secret session metadata remains as a local record.

## Requirements

- Windows 10 or 11
- Windows OpenSSH Client optional feature
- An Ubuntu server with OpenSSH
- An authorized SSH user; sudo rights are required for the dedicated-account mode
- Network access to the SSH port

## Build and self-test

Build with the .NET Framework compiler included with Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Build.ps1
```

Run the local self-test:

```powershell
.\AgentSshKeyManager.exe --self-test "$env:TEMP\AgentSshKeyManager-test.txt"
```

The self-test validates local key generation, SSH configuration, command encoding, expiry generation, and install/remove script construction. It does not connect to a server.
