using System;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AgentSshKeyManager
{
    public partial class MainForm
    {
        private ComboBox _bootstrapMethodCombo;
        private TextBox _bootstrapKeyText;
        private Button _bootstrapKeyBrowseButton;
        private TextBox _expectedFingerprintText;

        private void BuildBootstrapUi(GroupBox setup)
        {
            Label bootstrapMethodLabel = MakeLabel("Bootstrap authentication", 16, 84, 210);
            setup.Controls.Add(bootstrapMethodLabel);
            _bootstrapMethodCombo = new ComboBox();
            _bootstrapMethodCombo.Location = new Point(16, 105);
            _bootstrapMethodCombo.Size = new Size(210, 25);
            _bootstrapMethodCombo.DropDownStyle = ComboBoxStyle.DropDownList;
            _bootstrapMethodCombo.Items.Add(BootstrapMethods.DisplayName(BootstrapMethods.Password));
            _bootstrapMethodCombo.Items.Add(BootstrapMethods.DisplayName(BootstrapMethods.ExistingKey));
            _bootstrapMethodCombo.Items.Add(BootstrapMethods.DisplayName(BootstrapMethods.Manual));
            _bootstrapMethodCombo.SelectedIndex = 0;
            _bootstrapMethodCombo.SelectedIndexChanged += delegate { UpdateBootstrapUi(); };
            setup.Controls.Add(_bootstrapMethodCombo);
            SetFieldHelp("Choose how the tool first connects: password, existing SSH key, or manual installation.",
                bootstrapMethodLabel, _bootstrapMethodCombo);

            Label existingKeyLabel = MakeLabel("Existing private key (OpenSSH or PuTTY .ppk)", 244, 84, 360);
            setup.Controls.Add(existingKeyLabel);
            _bootstrapKeyText = new TextBox();
            _bootstrapKeyText.Location = new Point(244, 105);
            _bootstrapKeyText.Size = new Size(373, 25);
            setup.Controls.Add(_bootstrapKeyText);

            _bootstrapKeyBrowseButton = new Button();
            _bootstrapKeyBrowseButton.Text = "Browse ...";
            _bootstrapKeyBrowseButton.Location = new Point(625, 102);
            _bootstrapKeyBrowseButton.Size = new Size(92, 30);
            _bootstrapKeyBrowseButton.Click += BrowseBootstrapKeyClick;
            setup.Controls.Add(_bootstrapKeyBrowseButton);
            SetFieldHelp("Select an existing private SSH key. It is used only for setup and is never saved or changed.",
                existingKeyLabel, _bootstrapKeyText, _bootstrapKeyBrowseButton);

            Label expectedFingerprintLabel = MakeLabel("Expected server SHA256 fingerprint (optional, recommended)", 16, 140, 410);
            setup.Controls.Add(expectedFingerprintLabel);
            _expectedFingerprintText = new TextBox();
            _expectedFingerprintText.Location = new Point(16, 161);
            _expectedFingerprintText.Size = new Size(701, 25);
            setup.Controls.Add(_expectedFingerprintText);
            SetFieldHelp("Optional: Enter the server's SHA256 fingerprint. Setup stops if it does not match.",
                expectedFingerprintLabel, _expectedFingerprintText);

            var adminWarning = new Label();
            adminWarning.Location = new Point(744, 137);
            adminWarning.Size = new Size(185, 50);
            adminWarning.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            adminWarning.ForeColor = Color.FromArgb(145, 75, 0);
            adminWarning.Text = "Both target modes can grant the agent full administrator access.";
            setup.Controls.Add(adminWarning);
            SetFieldHelp("Both options can give the agent full control of the server.",
                adminWarning);

            UpdateBootstrapUi();
        }

        private void BrowseBootstrapKeyClick(object sender, EventArgs e)
        {
            using (var dialog = new OpenFileDialog())
            {
                dialog.Title = "Select an existing SSH private key";
                dialog.Filter = "SSH private keys (*.ppk;*.pem;*.key;id_*)|*.ppk;*.pem;*.key;id_*|PuTTY keys (*.ppk)|*.ppk|All files (*.*)|*.*";
                dialog.CheckFileExists = true;
                dialog.Multiselect = false;
                if (dialog.ShowDialog(this) == DialogResult.OK) _bootstrapKeyText.Text = dialog.FileName;
            }
        }

        private string SelectedBootstrapMethod()
        {
            if (_bootstrapMethodCombo == null || _bootstrapMethodCombo.SelectedIndex == 0) return BootstrapMethods.Password;
            if (_bootstrapMethodCombo.SelectedIndex == 1) return BootstrapMethods.ExistingKey;
            return BootstrapMethods.Manual;
        }

        private void UpdateBootstrapUi()
        {
            bool existingKey = SelectedBootstrapMethod() == BootstrapMethods.ExistingKey;
            if (_bootstrapKeyText != null) _bootstrapKeyText.Enabled = existingKey && !_busy;
            if (_bootstrapKeyBrowseButton != null) _bootstrapKeyBrowseButton.Enabled = existingKey && !_busy;
        }

        private async Task<BootstrapHostKey> ProbeAndValidateHostKeyAsync(string host, int port, string user)
        {
            BootstrapHostKey hostKey = await Task.Run(delegate
            {
                return ExistingKeyBootstrapper.ProbeHost(host, port, user);
            });

            string expected = (_expectedFingerprintText.Text ?? "").Trim();
            if (expected.Length > 0)
            {
                expected = ExistingKeyBootstrapper.NormalizeFingerprint(expected);
                if (!string.Equals(expected, hostKey.Fingerprint, StringComparison.Ordinal))
                {
                    throw new BootstrapException(BootstrapFailureKind.HostKeyMismatch,
                        "The server host-key fingerprint does not match the expected fingerprint. Connection was stopped.");
                }
            }
            return hostKey;
        }

        private string BuildHostKeyReviewText(string host, int port, BootstrapHostKey hostKey)
        {
            bool expectedFingerprintProvided = !string.IsNullOrWhiteSpace(_expectedFingerprintText.Text);
            return (expectedFingerprintProvided
                    ? "Server identity: the detected fingerprint matches the expected fingerprint."
                    : "Server identity: verify this fingerprint through a trusted channel before continuing.") + "\n" +
                "Server: " + host + ":" + port.ToString(CultureInfo.InvariantCulture) + "\n" +
                "Host-key algorithm: " + hostKey.Algorithm + "\n" +
                "SHA256 fingerprint: " + hostKey.Fingerprint;
        }

        private async Task CreateNonPasswordAccessAsync(string host, string user, int port, int hours,
            string bootstrapMethod)
        {
            bool dedicatedAdmin = _dedicatedAdminCheck.Checked;
            bool enforceServerExpiry = _expiryCheck.Checked;
            SetBusy(true, "Verifying server ...");
            SessionRecord record = null;
            ExistingKeyCredentialsDialog credentials = null;
            string keyPath = "";
            string keyPassphrase = "";
            string sudoPassword = "";
            try
            {
                BootstrapHostKey hostKey = await ProbeAndValidateHostKeyAsync(host, port, user);
                if (bootstrapMethod == BootstrapMethods.ExistingKey && hostKey.AuthenticationMethodsKnown &&
                    !hostKey.SupportsPublicKeyAuthentication)
                {
                    throw new BootstrapException(BootstrapFailureKind.UserLoginDenied,
                        "The server does not offer public-key authentication for this bootstrap user.");
                }

                string modeWarning = dedicatedAdmin
                    ? "A dedicated temporary user with unrestricted passwordless sudo will be created. This grants full administrator access."
                    : "The key will be installed for the existing account. If that account is root or has unrestricted sudo, the temporary access also has full administrator access.";
                string bootstrapNote = bootstrapMethod == BootstrapMethods.ExistingKey
                    ? "The existing bootstrap key is used only for setup and is never copied, stored, or given to the agent."
                    : "The manager will show a public key and a session-specific command for you to run through a trusted console or existing SSH session.";
                SetBusy(false, "");
                DialogResult confirmation = MessageBox.Show(this,
                    BuildHostKeyReviewText(host, port, hostKey) + "\n\n" + modeWarning + "\n\n" + bootstrapNote + "\n\nContinue?",
                    "Create temporary access", MessageBoxButtons.OKCancel, MessageBoxIcon.Warning);
                if (confirmation != DialogResult.OK) return;
                SetBusy(true, "Preparing access ...");

                if (bootstrapMethod == BootstrapMethods.ExistingKey)
                {
                    credentials = new ExistingKeyCredentialsDialog(_bootstrapKeyText.Text, dedicatedAdmin);
                    if (credentials.ShowDialog(this) != DialogResult.OK) return;
                    keyPath = credentials.KeyPath;
                    keyPassphrase = credentials.KeyPassphrase;
                    sudoPassword = credentials.SudoPassword;
                    _bootstrapKeyText.Text = keyPath;
                    SetBusy(true, "Testing bootstrap key ...");
                    await Task.Run(delegate
                    {
                        ExistingKeyBootstrapper.InspectAndValidatePrivateKey(keyPath, keyPassphrase);
                        ExistingKeyBootstrapper.TestAuthentication(host, port, user, keyPath, keyPassphrase, hostKey);
                        if (dedicatedAdmin)
                        {
                            ExistingKeyBootstrapper.TestAdministrativeAccess(host, port, user, keyPath,
                                keyPassphrase, sudoPassword, hostKey);
                        }
                    });
                }

                record = await Task.Run(delegate
                {
                    SessionRecord newRecord = SessionStore.Create(host, user, port, hours,
                        enforceServerExpiry, dedicatedAdmin, bootstrapMethod);
                    try
                    {
                        SshTools.GenerateKeyAndFiles(newRecord, enforceServerExpiry);
                        ExistingKeyBootstrapper.WriteKnownHosts(newRecord, hostKey);
                        SshTools.WriteAgentInstructions(newRecord);
                        SessionStore.Save(newRecord);
                        return newRecord;
                    }
                    catch
                    {
                        SessionStore.DeleteSecretMaterial(newRecord);
                        throw;
                    }
                });
                _records.Add(record);
                RefreshList(record);
                Log("Temporary key " + record.Alias + " was generated locally; server fingerprint confirmed.");

                if (bootstrapMethod == BootstrapMethods.Manual)
                {
                    string publicKey = SshTools.ReadValidatedPublicKey(record);
                    string manualCommand = SshTools.BuildManualInstallCommand(record);
                    using (var dialog = new ManualActionDialog("Manual installation",
                        "Run the command as the selected bootstrap user in the VM console or an already authenticated SSH session. Only this session's marked key or dedicated account is changed.",
                        hostKey.Fingerprint, publicKey, manualCommand, "Verify access"))
                    {
                        if (dialog.ShowDialog(this) != DialogResult.OK)
                        {
                            MarkSetupFailed(record, "Manual installation has not yet been verified. Use 'Test connection' after running the displayed command.");
                            return;
                        }
                    }
                }
                else
                {
                    SetBusy(true, "Installing access ...");
                    BootstrapOperationResult installation = await Task.Run(delegate
                    {
                        return ExistingKeyBootstrapper.Install(record, keyPath, keyPassphrase, sudoPassword, hostKey);
                    });
                    if (!installation.Success && record.EnforceServerExpiry && installation.RollbackSucceeded)
                    {
                        DialogResult retry = MessageBox.Show(this,
                            "The installation with the optional OpenSSH expiry restriction failed and its changes were rolled back. Retry the same access without server-side expiry?\n\nThe planned end time remains visible, but you must delete the access manually afterwards.",
                            "Retry without server-side expiry", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                        if (retry == DialogResult.Yes)
                        {
                            record.EnforceServerExpiry = false;
                            record.LastMessage = "Retrying without server-side expiry.";
                            SshTools.WriteAgentInstructions(record);
                            SessionStore.Save(record);
                            installation = await Task.Run(delegate
                            {
                                return ExistingKeyBootstrapper.Install(record, keyPath, keyPassphrase, sudoPassword, hostKey);
                            });
                        }
                    }
                    if (!installation.Success)
                    {
                        MarkSetupFailed(record, installation.Message);
                        if (!installation.RollbackSucceeded)
                        {
                            ShowManualCleanup(record, "Automatic rollback was not confirmed. Run this command through a trusted console or authenticated session.");
                        }
                        MessageBox.Show(this, installation.Message, "Installation failed",
                            MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }
                }

                SetBusy(true, "Verifying new access ...");
                TemporaryAccessCheck verification = await CheckTemporaryAccessAsync(record);
                if (verification.Outcome != TemporaryAccessOutcome.Accepted && record.EnforceServerExpiry)
                {
                    DialogResult retry = MessageBox.Show(this,
                        "The new key could not log in with the OpenSSH expiry option. The server may not support this option. Retry without automatic expiry?\n\nThe planned end time remains visible, but you must delete the access manually afterwards.",
                        "Retry without server-side expiry", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                    if (retry == DialogResult.Yes)
                    {
                        bool readyToRetry = true;
                        if (bootstrapMethod == BootstrapMethods.ExistingKey)
                        {
                            SetBusy(true, "Removing the first key entry ...");
                            BootstrapOperationResult cleanup = await Task.Run(delegate
                            {
                                return ExistingKeyBootstrapper.Remove(record, keyPath, keyPassphrase, sudoPassword, hostKey);
                            });
                            readyToRetry = cleanup.Success;
                            if (!readyToRetry)
                            {
                                MarkSetupFailed(record, "The first key entry could not be removed safely before retrying without expiry.");
                                ShowManualCleanup(record, "Automatic cleanup was not confirmed. Run this command through a trusted console or authenticated session.");
                                MessageBox.Show(this,
                                    "The retry was stopped because cleanup of the first key entry was not confirmed. The local key was retained.",
                                    "Retry stopped", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                return;
                            }
                        }

                        bool previousExpiry = record.EnforceServerExpiry;
                        record.EnforceServerExpiry = false;
                        record.LastMessage = "Retrying without server-side expiry.";
                        SshTools.WriteAgentInstructions(record);
                        SessionStore.Save(record);

                        if (bootstrapMethod == BootstrapMethods.Manual)
                        {
                            string retryCommand = SshTools.BuildManualCleanupCommand(record) + "; " +
                                SshTools.BuildManualInstallCommand(record);
                            using (var dialog = new ManualActionDialog("Retry without server-side expiry",
                                "Run this command in the same trusted console or SSH session. It removes only this session's first entry and installs it again without automatic expiry.",
                                hostKey.Fingerprint, SshTools.ReadValidatedPublicKey(record), retryCommand, "Verify access"))
                            {
                                if (dialog.ShowDialog(this) != DialogResult.OK)
                                {
                                    record.EnforceServerExpiry = previousExpiry;
                                    record.LastMessage = "Retry without server-side expiry was cancelled.";
                                    SshTools.WriteAgentInstructions(record);
                                    SessionStore.Save(record);
                                    readyToRetry = false;
                                }
                            }
                        }
                        else if (readyToRetry)
                        {
                            SetBusy(true, "Installing access without expiry ...");
                            BootstrapOperationResult retryInstallation = await Task.Run(delegate
                            {
                                return ExistingKeyBootstrapper.Install(record, keyPath, keyPassphrase, sudoPassword, hostKey);
                            });
                            if (!retryInstallation.Success)
                            {
                                MarkSetupFailed(record, retryInstallation.Message);
                                if (!retryInstallation.RollbackSucceeded)
                                {
                                    ShowManualCleanup(record, "The retry failed and automatic cleanup was not confirmed. Run this command through a trusted console or authenticated session.");
                                }
                                MessageBox.Show(this, retryInstallation.Message, "Retry failed",
                                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                return;
                            }
                        }

                        if (readyToRetry)
                        {
                            SetBusy(true, "Verifying access without expiry ...");
                            verification = await CheckTemporaryAccessAsync(record);
                        }
                    }
                }

                if (verification.Outcome != TemporaryAccessOutcome.Accepted)
                {
                    bool rolledBack = false;
                    if (bootstrapMethod == BootstrapMethods.ExistingKey)
                    {
                        BootstrapOperationResult rollback = await Task.Run(delegate
                        {
                            return ExistingKeyBootstrapper.Remove(record, keyPath, keyPassphrase, sudoPassword, hostKey);
                        });
                        rolledBack = rollback.Success;
                    }
                    string verificationDetails = verification.Result == null
                        ? "No further details."
                        : SafeOneLine(verification.Result.Combined);
                    MarkSetupFailed(record, "The newly generated access could not be verified. " + verificationDetails +
                        (rolledBack ? " Changes made by this session were rolled back." : " Automatic rollback was not confirmed."));
                    if (!rolledBack) ShowManualCleanup(record, "The new access failed verification. Run this cleanup command to remove only this session's changes.");
                    MessageBox.Show(this,
                        "Login with the new temporary key failed. The access was not marked ready." +
                        (rolledBack ? " Server changes were rolled back." : " Review and run the displayed cleanup command."),
                        "Verification failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                await ActivateRecordAsync(record);
            }
            catch (BootstrapException ex)
            {
                if (record != null) MarkSetupFailed(record, ex.Message);
                Log("Setup: " + ex.Message);
                MessageBox.Show(this, ex.Message, "Setup failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            catch (Exception ex)
            {
                if (record != null) MarkSetupFailed(record, "Setup could not be completed safely.");
                Log("Setup error: " + SafeOneLine(ex.Message));
                MessageBox.Show(this, "Setup could not be completed safely.\n\n" + SafeOneLine(ex.Message),
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                if (credentials != null)
                {
                    credentials.ClearSecrets();
                    credentials.Dispose();
                }
                keyPassphrase = "";
                sudoPassword = "";
                SetBusy(false, "");
            }
        }

        private async Task<bool> PreparePasswordBootstrapAsync(string host, int port, string user,
            Action<BootstrapHostKey> onConfirmed)
        {
            try
            {
                BootstrapHostKey hostKey = await ProbeAndValidateHostKeyAsync(host, port, user);
                if (hostKey.AuthenticationMethodsKnown && !hostKey.SupportsPasswordAuthentication)
                {
                    MessageBox.Show(this,
                        "SSH password authentication is disabled for this user or server. A valid Linux or sudo password cannot establish the first SSH connection in this configuration.\n\nSelect 'Existing SSH key' or use 'Manual installation' through the VM console. There is no need to weaken the server's SSH configuration.",
                        "Password SSH login unavailable", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return false;
                }
                onConfirmed(hostKey);
                return true;
            }
            catch (BootstrapException ex)
            {
                MessageBox.Show(this, ex.Message, "SSH preflight failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
        }

        private async Task<TemporaryAccessCheck> CheckTemporaryAccessAsync(SessionRecord record)
        {
            return await Task.Run(delegate { return SshTools.CheckTemporaryAccess(record); });
        }

        private async Task ActivateRecordAsync(SessionRecord record)
        {
            record.SudoStatus = await Task.Run(delegate { return SshTools.CheckSudo(record); });
            record.State = "Active";
            record.LastMessage = "Access installed and verified successfully.";
            SshTools.WriteAgentInstructions(record);
            SessionStore.Save(record);
            RefreshList(record);
            Log(record.LastMessage + " Server host key: " + (record.ServerHostKeyFingerprint ?? "not recorded") + ".");

            string privilege = record.SudoStatus == "NoPassword"
                ? "The temporary account has unattended administrator access."
                : "sudo requires a password or is unavailable; the existing account configuration was not changed.";
            MessageBox.Show(this,
                "The temporary SSH access is active and has been tested. Use 'Copy agent connection details' to hand off only the generated access.\n\n" + privilege,
                "Access ready", MessageBoxButtons.OK,
                record.SudoStatus == "NoPassword" ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        }

        private void MarkSetupFailed(SessionRecord record, string message)
        {
            record.State = "SetupFailed";
            record.LastMessage = message;
            SessionStore.Save(record);
            RefreshList(record);
            Log(message);
        }

        private void ShowManualCleanup(SessionRecord record, string introduction)
        {
            using (var dialog = new ManualActionDialog("Manual cleanup", introduction,
                record.ServerHostKeyFingerprint, "", SshTools.BuildManualCleanupCommand(record), "Close"))
            {
                dialog.ShowDialog(this);
            }
        }

        private async Task RemoveNonPasswordAccessAsync(SessionRecord record)
        {
            SetBusy(true, "Removing access ...");
            ExistingKeyCredentialsDialog credentials = null;
            string keyPassphrase = "";
            string sudoPassword = "";
            try
            {
                bool cleanupConfirmed = false;
                if (!record.UsesDedicatedAdminAccount && File.Exists(record.PrivateKeyPath))
                {
                    RunResult direct = await Task.Run(delegate { return SshTools.RemoveUsingTemporaryKey(record); });
                    cleanupConfirmed = SshTools.CleanupWasConfirmed(record, direct);
                    if (!cleanupConfirmed) Log("Removal with the temporary key was not confirmed; bootstrap fallback is required.");
                }

                if (!cleanupConfirmed && record.BootstrapMethod == BootstrapMethods.ExistingKey)
                {
                    BootstrapHostKey currentHostKey = await Task.Run(delegate
                    {
                        return ExistingKeyBootstrapper.ProbeHost(record.Host, record.Port, record.BootstrapUser);
                    });
                    string expected = ExistingKeyBootstrapper.NormalizeFingerprint(record.ServerHostKeyFingerprint);
                    if (!string.Equals(expected, currentHostKey.Fingerprint, StringComparison.Ordinal))
                    {
                        throw new BootstrapException(BootstrapFailureKind.HostKeyMismatch,
                            "The server host key changed. Removal was stopped before the bootstrap key was used.");
                    }

                    credentials = new ExistingKeyCredentialsDialog(_bootstrapKeyText.Text, record.UsesDedicatedAdminAccount);
                    if (credentials.ShowDialog(this) != DialogResult.OK) return;
                    _bootstrapKeyText.Text = credentials.KeyPath;
                    keyPassphrase = credentials.KeyPassphrase;
                    sudoPassword = credentials.SudoPassword;
                    BootstrapOperationResult result = await Task.Run(delegate
                    {
                        return ExistingKeyBootstrapper.Remove(record, credentials.KeyPath,
                            keyPassphrase, sudoPassword, currentHostKey);
                    });
                    cleanupConfirmed = result.Success;
                    if (!cleanupConfirmed) throw new BootstrapException(result.FailureKind, result.Message);
                }

                if (!cleanupConfirmed && record.BootstrapMethod == BootstrapMethods.Manual)
                {
                    using (var dialog = new ManualActionDialog("Manual removal",
                        "Run this command as the original bootstrap user in the VM console or an authenticated SSH session. Paste its cleanup confirmation below before continuing.",
                        record.ServerHostKeyFingerprint, "", SshTools.BuildManualCleanupCommand(record), "Confirm removal",
                        SshTools.CleanupConfirmation(record)))
                    {
                        if (dialog.ShowDialog(this) != DialogResult.OK) return;
                    }
                    cleanupConfirmed = true;
                }

                if (!cleanupConfirmed)
                {
                    throw new InvalidOperationException("The server did not confirm removal of the temporary access.");
                }

                TemporaryAccessCheck postRemoval = await CheckTemporaryAccessAsync(record);
                if (postRemoval.Outcome == TemporaryAccessOutcome.Accepted)
                {
                    throw new InvalidOperationException("The server still accepts the temporary key. Local key material was retained.");
                }
                if (postRemoval.Outcome == TemporaryAccessOutcome.Indeterminate)
                {
                    Log("The follow-up login test was inconclusive, but the pinned cleanup command confirmed that this session's server artifacts were removed.");
                }

                await Task.Run(delegate { SessionStore.DeleteSecretMaterial(record); });
                record.State = "Removed";
                record.LastMessage = "Server access removed and local temporary private key deleted.";
                SessionStore.Save(record);
                RefreshList(record);
                Log(record.LastMessage);
                MessageBox.Show(this, "The temporary access was removed and its local private key was deleted.",
                    "Access removed", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                record.State = "RemovalFailed";
                record.LastMessage = ex is BootstrapException ? ex.Message : "Removal could not be confirmed safely.";
                SessionStore.Save(record);
                RefreshList(record);
                Log("Removal: " + SafeOneLine(ex.Message));
                MessageBox.Show(this, "Removal could not be completed safely. The local key was retained.\n\n" +
                    SafeOneLine(ex.Message), "Removal failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally
            {
                if (credentials != null)
                {
                    credentials.ClearSecrets();
                    credentials.Dispose();
                }
                keyPassphrase = "";
                sudoPassword = "";
                SetBusy(false, "");
            }
        }

        private static string AgentConnectionDetails(SessionRecord record)
        {
            var text = new StringBuilder();
            text.AppendLine(SshTools.AgentTaskInstruction);
            text.AppendLine();
            text.AppendLine("Temporary SSH access");
            text.AppendLine("Server: " + record.Host);
            text.AppendLine("Port: " + record.Port.ToString(CultureInfo.InvariantCulture));
            text.AppendLine("User: " + record.User);
            text.AppendLine("Private key file: " + record.PrivateKeyPath);
            text.AppendLine("Server host-key fingerprint: " + (record.ServerHostKeyFingerprint ?? "not recorded"));
            text.AppendLine("Connect: " + SshTools.ConnectionCommand(record));
            return text.ToString();
        }
    }
}
