using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

using Renci.SshNet;
using Renci.SshNet.Common;

namespace AgentSshKeyManager
{
    internal static class UbuntuAcceptanceTestProgram
    {
        private static readonly List<CleanupTarget> CleanupTargets = new List<CleanupTarget>();
        private static readonly List<string> Report = new List<string>();
        private static string _host;
        private static int _port;
        private static string _fixtureDirectory;
        private static string _workDirectory;
        private static string _rootKey;
        private static string _sudoKey;
        private static string _sudoKeyPassphrase;
        private static string _bootstrapPassword;
        private static BootstrapHostKey _rootHostKey;
        private static BootstrapHostKey _sudoHostKey;
        private static bool _passwordLoginWasEnabled;

        private static int Main(string[] args)
        {
            EmbeddedDependencyLoader.Initialize();
            if (args.Length != 5)
            {
                Console.Error.WriteLine("Usage: UbuntuAcceptanceHarness HOST PORT FIXTURE_DIRECTORY WORK_DIRECTORY REPORT_FILE");
                return 64;
            }

            string reportPath = Path.GetFullPath(args[4]);
            int exitCode = 0;
            try
            {
                _host = args[0];
                if (!int.TryParse(args[1], NumberStyles.None, CultureInfo.InvariantCulture, out _port) ||
                    _port < 1 || _port > 65535) throw new InvalidOperationException("Invalid test port.");
                _fixtureDirectory = Path.GetFullPath(args[2]);
                _workDirectory = Path.GetFullPath(args[3]);
                Directory.CreateDirectory(_workDirectory);
                SessionStore.TrySecureDirectory(_workDirectory);

                _rootKey = Path.Combine(_fixtureDirectory, "root-bootstrap.ppk");
                _sudoKey = Path.Combine(_fixtureDirectory, "sudo-bootstrap");
                _sudoKeyPassphrase = ReadSecret("sudo-key-passphrase.txt");
                _bootstrapPassword = ReadSecret("bootstrap-password.txt");

                AssertNoSecretArguments();
                WaitForGuest();
                TestAuthenticationDiscoveryAndFormats();
                TestRootPpkDedicatedAccess();
                TestEncryptedOpenSshExistingUserAccess();
                TestManualFallback();
                TestExpiryFallbackAndDefinitiveCleanup();
                TestRollbackAfterPartialFailure();
                TestPasswordAuthenticationCompatibility();
                TestNoResidualAccess();
                TestRuntimeArchitecture();

                Report.Add("ACCEPTANCE TESTS OK");
            }
            catch (Exception ex)
            {
                Report.Add("FAILED: " + SafeOneLine(ex.Message));
                exitCode = 1;
            }
            finally
            {
                try
                {
                    RestorePasswordAuthentication();
                }
                catch (Exception ex)
                {
                    Report.Add("FAILED: Password-authentication restoration: " + SafeOneLine(ex.Message));
                    exitCode = 1;
                }
                CleanupServerTargets();
                _sudoKeyPassphrase = null;
                _bootstrapPassword = null;
            }
            WriteReport(reportPath, Report);
            return exitCode;
        }

        private static void WaitForGuest()
        {
            Exception last = null;
            for (int attempt = 0; attempt < 60; attempt++)
            {
                try
                {
                    _rootHostKey = ExistingKeyBootstrapper.ProbeHost(_host, _port, "root");
                    ExistingKeyBootstrapper.TestAuthentication(_host, _port, "root", _rootKey, "", _rootHostKey);
                    string state = RunKeyCommand("root", _rootKey, "", _rootHostKey,
                        "cloud-init status --wait; test -f /etc/ssh/sshd_config.d/90-agent-ssh-acceptance.conf; printf GUEST_READY");
                    Assert(state.Contains("GUEST_READY"), "Guest did not finish cloud-init.");
                    Report.Add("Ubuntu guest and strict host-key handshake: OK");
                    return;
                }
                catch (Exception ex)
                {
                    last = ex;
                    Thread.Sleep(2000);
                }
            }
            throw new InvalidOperationException("Ubuntu guest did not become ready: " + SafeOneLine(last == null ? "unknown error" : last.Message));
        }

        private static void TestAuthenticationDiscoveryAndFormats()
        {
            _sudoHostKey = ExistingKeyBootstrapper.ProbeHost(_host, _port, "bootstrap");
            Assert(!_sudoHostKey.SupportsPasswordAuthentication,
                "Password authentication should initially be disabled.");
            Assert(_sudoHostKey.SupportsPublicKeyAuthentication,
                "Public-key authentication was not offered.");

            KeyFileInspection ppk = ExistingKeyBootstrapper.InspectAndValidatePrivateKey(_rootKey, "");
            Assert(ppk.Format == "PuTTY PPK", "PuTTY PPK format was not recognized.");
            Assert(!ppk.IsEncrypted, "Root PPK fixture should be unencrypted.");

            ExpectBootstrapFailure(delegate
            {
                ExistingKeyBootstrapper.InspectAndValidatePrivateKey(_sudoKey, "");
            }, BootstrapFailureKind.KeyPassphraseRequired, "missing OpenSSH key passphrase");
            ExpectBootstrapFailure(delegate
            {
                ExistingKeyBootstrapper.InspectAndValidatePrivateKey(_sudoKey, "incorrect-test-passphrase");
            }, BootstrapFailureKind.IncorrectKeyPassphrase, "wrong OpenSSH key passphrase");
            KeyFileInspection openSsh = ExistingKeyBootstrapper.InspectAndValidatePrivateKey(
                _sudoKey, _sudoKeyPassphrase);
            Assert(openSsh.Format == "OpenSSH" && openSsh.IsEncrypted,
                "Encrypted OpenSSH format was not recognized.");

            string unsupported = Path.Combine(_workDirectory, "unsupported-key.txt");
            File.WriteAllText(unsupported, "not a private key", new UTF8Encoding(false));
            ExpectBootstrapFailure(delegate
            {
                ExistingKeyBootstrapper.InspectAndValidatePrivateKey(unsupported, "");
            }, BootstrapFailureKind.UnsupportedKeyFormat, "unsupported key format");

            BootstrapHostKey wrongHostKey = CloneHostKey(_rootHostKey);
            wrongHostKey.KeyData[wrongHostKey.KeyData.Length - 1] ^= 1;
            ExpectBootstrapFailure(delegate
            {
                ExistingKeyBootstrapper.TestAuthentication(_host, _port, "root", _rootKey, "", wrongHostKey);
            }, BootstrapFailureKind.HostKeyMismatch, "changed server host key");
            Report.Add("PPK/OpenSSH parsing, passphrase diagnostics, and host-key mismatch: OK");
        }

        private static void TestRootPpkDedicatedAccess()
        {
            ExistingKeyBootstrapper.TestAdministrativeAccess(_host, _port, "root", _rootKey, "", "", _rootHostKey);
            string originalAuthorizedKeys = NormalizeText(RunKeyCommand("root", _rootKey, "", _rootHostKey,
                "cat /root/.ssh/authorized_keys"));

            SessionRecord record = CreateRecord("root", true, true);
            AddCleanup(record, _rootKey, "", "", _rootHostKey);
            PrepareRecord(record, _rootHostKey);
            BootstrapOperationResult installed = ExistingKeyBootstrapper.Install(record, _rootKey, "", "", _rootHostKey);
            Assert(installed.Success, "Root PPK could not install a dedicated temporary account: " + installed.Message);
            Assert(IsTemporaryAccessAccepted(record), "Dedicated temporary key was not accepted.");
            Assert(SshTools.CheckSudo(record) == "NoPassword", "Dedicated account did not receive NOPASSWD sudo.");
            string serverCheck = RunKeyCommand("root", _rootKey, "", _rootHostKey,
                "id -u " + SshTools.ShellQuote(record.User) + " >/dev/null && " +
                "grep -Fqx -- " + SshTools.ShellQuote("# " + record.Marker) + " /etc/sudoers.d/agent-ssh-" + record.Id.Substring(0, 16) +
                " && printf DEDICATED_READY");
            Assert(serverCheck.Contains("DEDICATED_READY"), "Dedicated account ownership or sudoers marker is missing.");

            record.State = "Active";
            SessionStore.Save(record);
            AssertMetadataContainsNoSecrets(record);
            BootstrapOperationResult removed = ExistingKeyBootstrapper.Remove(record, _rootKey, "", "", _rootHostKey);
            Assert(removed.Success, "Dedicated access removal failed: " + removed.Message);
            Assert(!IsTemporaryAccessAccepted(record), "Dedicated temporary key was still accepted after removal.");
            ExistingKeyBootstrapper.TestAuthentication(_host, _port, "root", _rootKey, "", _rootHostKey);
            string finalAuthorizedKeys = NormalizeText(RunKeyCommand("root", _rootKey, "", _rootHostKey,
                "cat /root/.ssh/authorized_keys"));
            Assert(originalAuthorizedKeys == finalAuthorizedKeys, "Existing root authorized_keys content changed.");
            RemoveCleanup(record);
            SessionStore.DeleteSecretMaterial(record);

            SessionRecord orphanedRecord = CreateRecord("root", true, true);
            AddCleanup(orphanedRecord, _rootKey, "", "", _rootHostKey);
            PrepareRecord(orphanedRecord, _rootHostKey);
            BootstrapOperationResult orphanedInstalled = ExistingKeyBootstrapper.Install(orphanedRecord, _rootKey, "", "", _rootHostKey);
            Assert(orphanedInstalled.Success && IsTemporaryAccessAccepted(orphanedRecord),
                "Dedicated temporary account for orphaned-home cleanup could not be installed.");
            string orphanedHome = NormalizeText(RunKeyCommand("root", _rootKey, "", _rootHostKey,
                "getent passwd " + SshTools.ShellQuote(orphanedRecord.User) + " | cut -d: -f6")).Trim();
            Assert(orphanedHome == "/home/" + orphanedRecord.User,
                "Dedicated account did not use its deterministic Ubuntu home directory.");
            string orphanedAccount = RunKeyCommand("root", _rootKey, "", _rootHostKey,
                "pkill -TERM -u " + SshTools.ShellQuote(orphanedRecord.User) + " >/dev/null 2>&1 || true; sleep 1; " +
                "pkill -KILL -u " + SshTools.ShellQuote(orphanedRecord.User) + " >/dev/null 2>&1 || true; " +
                "/usr/sbin/userdel " + SshTools.ShellQuote(orphanedRecord.User) + " && " +
                "! id -u " + SshTools.ShellQuote(orphanedRecord.User) + " >/dev/null 2>&1 && " +
                "install -d -m 700 " + SshTools.ShellQuote(orphanedHome + "/.ssh") + " && " +
                "touch " + SshTools.ShellQuote(orphanedHome + "/.ssh/authorized_keys") + " && " +
                "test -d " + SshTools.ShellQuote(orphanedHome) + " && printf ORPHANED_HOME_READY");
            Assert(orphanedAccount.Contains("ORPHANED_HOME_READY"),
                "The harness could not create the dedicated-account orphaned-home scenario.");
            BootstrapOperationResult orphanedRemoved = ExistingKeyBootstrapper.Remove(orphanedRecord, _rootKey, "", "", _rootHostKey);
            Assert(orphanedRemoved.Success, "Dedicated orphaned-home cleanup was not confirmed: " + orphanedRemoved.Message);
            string orphanedClean = RunKeyCommand("root", _rootKey, "", _rootHostKey,
                "! id -u " + SshTools.ShellQuote(orphanedRecord.User) + " >/dev/null 2>&1 && " +
                "test ! -e " + SshTools.ShellQuote(orphanedHome) + " && " +
                "test ! -e /etc/sudoers.d/agent-ssh-" + orphanedRecord.Id.Substring(0, 16) + " && " +
                "test ! -e /var/lib/agent-ssh-key-manager/" + orphanedRecord.Id + ".owner && printf ORPHANED_HOME_CLEAN");
            Assert(orphanedClean.Contains("ORPHANED_HOME_CLEAN"),
                "Dedicated orphaned-home cleanup left a server artifact.");
            RemoveCleanup(orphanedRecord);
            SessionStore.DeleteSecretMaterial(orphanedRecord);
            Report.Add("Unencrypted PPK/root -> dedicated sudo account -> verified deletion, including orphaned-home cleanup: OK");
        }

        private static void TestEncryptedOpenSshExistingUserAccess()
        {
            ExistingKeyBootstrapper.TestAuthentication(_host, _port, "bootstrap", _sudoKey,
                _sudoKeyPassphrase, _sudoHostKey);
            ExpectBootstrapFailure(delegate
            {
                ExistingKeyBootstrapper.TestAdministrativeAccess(_host, _port, "bootstrap", _sudoKey,
                    _sudoKeyPassphrase, "incorrect-sudo-password", _sudoHostKey);
            }, BootstrapFailureKind.IncorrectSudoPassword, "wrong sudo password");
            ExistingKeyBootstrapper.TestAdministrativeAccess(_host, _port, "bootstrap", _sudoKey,
                _sudoKeyPassphrase, _bootstrapPassword, _sudoHostKey);

            string originalAuthorizedKeys = NormalizeText(RunKeyCommand("bootstrap", _sudoKey,
                _sudoKeyPassphrase, _sudoHostKey, "cat \"$HOME/.ssh/authorized_keys\""));
            SessionRecord record = CreateRecord("bootstrap", false, true);
            AddCleanup(record, _sudoKey, _sudoKeyPassphrase, _bootstrapPassword, _sudoHostKey);
            PrepareRecord(record, _sudoHostKey);
            BootstrapOperationResult installed = ExistingKeyBootstrapper.Install(record, _sudoKey,
                _sudoKeyPassphrase, _bootstrapPassword, _sudoHostKey);
            Assert(installed.Success, "Encrypted OpenSSH bootstrap failed: " + installed.Message);
            Assert(IsTemporaryAccessAccepted(record), "Existing-user temporary key was not accepted.");
            Assert(SshTools.CheckSudo(record) == "PasswordRequired",
                "Existing sudo account privilege status was not preserved accurately.");

            record.State = "Active";
            SessionStore.Save(record);
            AssertMetadataContainsNoSecrets(record);
            RunResult removed = SshTools.RemoveUsingTemporaryKey(record);
            Assert(SshTools.CleanupWasConfirmed(record, removed),
                "Existing-user marker removal did not return its session-bound confirmation.");
            Assert(!IsTemporaryAccessAccepted(record), "Existing-user temporary key was accepted after removal.");
            ExistingKeyBootstrapper.TestAuthentication(_host, _port, "bootstrap", _sudoKey,
                _sudoKeyPassphrase, _sudoHostKey);
            string finalAuthorizedKeys = NormalizeText(RunKeyCommand("bootstrap", _sudoKey,
                _sudoKeyPassphrase, _sudoHostKey, "cat \"$HOME/.ssh/authorized_keys\""));
            Assert(originalAuthorizedKeys == finalAuthorizedKeys, "Existing bootstrap authorized_keys content changed.");
            RemoveCleanup(record);
            SessionStore.DeleteSecretMaterial(record);
            Report.Add("Encrypted OpenSSH/sudo user -> existing account -> marker-only deletion: OK");
        }

        private static void TestManualFallback()
        {
            string originalAuthorizedKeys = NormalizeText(RunKeyCommand("bootstrap", _sudoKey,
                _sudoKeyPassphrase, _sudoHostKey, "cat \"$HOME/.ssh/authorized_keys\""));
            SessionRecord record = CreateRecord("bootstrap", false, false);
            AddCleanup(record, _sudoKey, _sudoKeyPassphrase, _bootstrapPassword, _sudoHostKey);
            PrepareRecord(record, _sudoHostKey);
            string command = SshTools.BuildManualInstallCommand(record);
            Assert(command.Contains(record.Marker), "Manual command does not contain the session marker.");
            RunKeyCommand("bootstrap", _sudoKey, _sudoKeyPassphrase, _sudoHostKey, command);
            Assert(IsTemporaryAccessAccepted(record), "Manually installed temporary key was not accepted.");
            string cleanupOutput = RunKeyCommand("bootstrap", _sudoKey, _sudoKeyPassphrase, _sudoHostKey,
                SshTools.BuildManualCleanupCommand(record));
            Assert(SshTools.CleanupWasConfirmed(record, 0, cleanupOutput),
                "Manual cleanup did not return its session-bound confirmation.");
            Assert(!IsTemporaryAccessAccepted(record), "Manual cleanup did not revoke the temporary key.");
            string finalAuthorizedKeys = NormalizeText(RunKeyCommand("bootstrap", _sudoKey,
                _sudoKeyPassphrase, _sudoHostKey, "cat \"$HOME/.ssh/authorized_keys\""));
            Assert(originalAuthorizedKeys == finalAuthorizedKeys, "Manual fallback changed a pre-existing key.");
            RemoveCleanup(record);
            SessionStore.DeleteSecretMaterial(record);
            Report.Add("Manual install/verify/marker-only cleanup fallback: OK");
        }

        private static void TestExpiryFallbackAndDefinitiveCleanup()
        {
            string originalAuthorizedKeys = NormalizeText(RunKeyCommand("bootstrap", _sudoKey,
                _sudoKeyPassphrase, _sudoHostKey, "cat \"$HOME/.ssh/authorized_keys\""));
            string normalOptions = "no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc";

            // A deliberately unknown authorized_keys option simulates an sshd that accepts
            // the file update but rejects the generated login option during verification.
            SessionRecord replacementRecord = CreateRecord("bootstrap", false, true);
            AddCleanup(replacementRecord, _sudoKey, _sudoKeyPassphrase, _bootstrapPassword, _sudoHostKey);
            PrepareRecord(replacementRecord, _sudoHostKey);
            string replacementPublicKey = SshTools.ReadValidatedPublicKey(replacementRecord);
            string rejectedLine = "agent-ssh-test-unsupported-option " + replacementPublicKey;
            RunKeyCommand("bootstrap", _sudoKey, _sudoKeyPassphrase, _sudoHostKey,
                SshTools.BuildInstallCommand(replacementRecord.Marker, rejectedLine));
            TemporaryAccessCheck rejectedCheck = SshTools.CheckTemporaryAccess(replacementRecord);
            Assert(rejectedCheck.Outcome == TemporaryAccessOutcome.Rejected,
                "An unsupported authorized_keys option was not classified as an authentication rejection.");
            string markerStillPresent = RunKeyCommand("bootstrap", _sudoKey, _sudoKeyPassphrase, _sudoHostKey,
                "grep -Fq -- " + SshTools.ShellQuote(replacementRecord.Marker) +
                " \"$HOME/.ssh/authorized_keys\" && printf MARKER_PRESENT");
            Assert(markerStillPresent.Contains("MARKER_PRESENT"),
                "Authentication rejection was incorrectly treated as proof that the marker was absent.");

            replacementRecord.EnforceServerExpiry = false;
            SshTools.WriteAgentInstructions(replacementRecord);
            RunKeyCommand("bootstrap", _sudoKey, _sudoKeyPassphrase, _sudoHostKey,
                SshTools.BuildInstallCommand(replacementRecord.Marker,
                    normalOptions + " " + replacementPublicKey));
            Assert(IsTemporaryAccessAccepted(replacementRecord),
                "Atomic marker replacement did not recover from an unsupported option.");
            string markerCount = RunKeyCommand("bootstrap", _sudoKey, _sudoKeyPassphrase, _sudoHostKey,
                "awk -v m=" + SshTools.ShellQuote(replacementRecord.Marker) +
                " 'length($0)>=length(m) && substr($0,length($0)-length(m)+1)==m { count++ } END { print count+0 }' " +
                "\"$HOME/.ssh/authorized_keys\"");
            Assert(markerCount.Trim() == "1", "Changing expiry mode left duplicate marked key entries.");
            string handoff = File.ReadAllText(Path.Combine(replacementRecord.SessionDirectory,
                "AGENT-SSH-COMMAND.txt"));
            Assert(handoff.Contains("Planned end:") &&
                handoff.IndexOf("server-side access expires", StringComparison.OrdinalIgnoreCase) < 0,
                "The handoff text still claimed automatic expiry after fallback.");
            string replacementCleanup = RunKeyCommand("bootstrap", _sudoKey, _sudoKeyPassphrase,
                _sudoHostKey, SshTools.BuildRemovalCommand(replacementRecord.Marker, replacementRecord.Id));
            Assert(SshTools.CleanupWasConfirmed(replacementRecord, 0, replacementCleanup),
                "Atomic replacement cleanup was not confirmed.");
            RemoveCleanup(replacementRecord);
            SessionStore.DeleteSecretMaterial(replacementRecord);

            SessionRecord keyRetryRecord = CreateRecord("bootstrap", false, true);
            AddCleanup(keyRetryRecord, _sudoKey, _sudoKeyPassphrase, _bootstrapPassword, _sudoHostKey);
            PrepareRecord(keyRetryRecord, _sudoHostKey);
            string keyRetryPublicKey = SshTools.ReadValidatedPublicKey(keyRetryRecord);
            RunKeyCommand("bootstrap", _sudoKey, _sudoKeyPassphrase, _sudoHostKey,
                SshTools.BuildInstallCommand(keyRetryRecord.Marker,
                    "agent-ssh-test-unsupported-option " + keyRetryPublicKey));
            BootstrapOperationResult firstCleanup = ExistingKeyBootstrapper.Remove(keyRetryRecord,
                _sudoKey, _sudoKeyPassphrase, _bootstrapPassword, _sudoHostKey);
            Assert(firstCleanup.Success,
                "Existing-key fallback did not confirm cleanup before retrying.");
            keyRetryRecord.EnforceServerExpiry = false;
            SshTools.WriteAgentInstructions(keyRetryRecord);
            BootstrapOperationResult keyRetry = ExistingKeyBootstrapper.Install(keyRetryRecord,
                _sudoKey, _sudoKeyPassphrase, _bootstrapPassword, _sudoHostKey);
            Assert(keyRetry.Success && IsTemporaryAccessAccepted(keyRetryRecord),
                "Existing-key setup could not retry after verification rejected the first option.");
            BootstrapOperationResult keyRetryCleanup = ExistingKeyBootstrapper.Remove(keyRetryRecord,
                _sudoKey, _sudoKeyPassphrase, _bootstrapPassword, _sudoHostKey);
            Assert(keyRetryCleanup.Success, "Existing-key retry cleanup was not confirmed.");
            RemoveCleanup(keyRetryRecord);
            SessionStore.DeleteSecretMaterial(keyRetryRecord);

            SessionRecord manualRetryRecord = CreateRecord("bootstrap", false, true);
            manualRetryRecord.BootstrapMethod = BootstrapMethods.Manual;
            AddCleanup(manualRetryRecord, _sudoKey, _sudoKeyPassphrase, _bootstrapPassword, _sudoHostKey);
            PrepareRecord(manualRetryRecord, _sudoHostKey);
            string manualRetryPublicKey = SshTools.ReadValidatedPublicKey(manualRetryRecord);
            RunKeyCommand("bootstrap", _sudoKey, _sudoKeyPassphrase, _sudoHostKey,
                SshTools.BuildInstallCommand(manualRetryRecord.Marker,
                    "agent-ssh-test-unsupported-option " + manualRetryPublicKey));
            manualRetryRecord.EnforceServerExpiry = false;
            SshTools.WriteAgentInstructions(manualRetryRecord);
            string manualRetryOutput = RunKeyCommand("bootstrap", _sudoKey, _sudoKeyPassphrase, _sudoHostKey,
                SshTools.BuildManualCleanupCommand(manualRetryRecord) + "; " +
                SshTools.BuildManualInstallCommand(manualRetryRecord));
            Assert(SshTools.CleanupWasConfirmed(manualRetryRecord, 0, manualRetryOutput),
                "Manual expiry fallback did not expose its cleanup confirmation.");
            Assert(IsTemporaryAccessAccepted(manualRetryRecord),
                "Manual setup could not retry after verification rejected the first option.");
            string manualCleanup = RunKeyCommand("bootstrap", _sudoKey, _sudoKeyPassphrase, _sudoHostKey,
                SshTools.BuildManualCleanupCommand(manualRetryRecord));
            Assert(SshTools.CleanupWasConfirmed(manualRetryRecord, 0, manualCleanup),
                "Manual retry cleanup was not confirmed.");
            RemoveCleanup(manualRetryRecord);
            SessionStore.DeleteSecretMaterial(manualRetryRecord);

            string finalAuthorizedKeys = NormalizeText(RunKeyCommand("bootstrap", _sudoKey,
                _sudoKeyPassphrase, _sudoHostKey, "cat \"$HOME/.ssh/authorized_keys\""));
            Assert(originalAuthorizedKeys == finalAuthorizedKeys,
                "Expiry fallback tests changed pre-existing authorized_keys content.");
            Report.Add("Unsupported expiry fallback, exact marker replacement, and definitive cleanup: OK");
        }

        private static void TestRollbackAfterPartialFailure()
        {
            SessionRecord record = CreateRecord("root", true, false);
            record.User = "invalid:rollback";
            AddCleanup(record, _rootKey, "", "", _rootHostKey);
            PrepareRecord(record, _rootHostKey);
            BootstrapOperationResult result = ExistingKeyBootstrapper.Install(record, _rootKey, "", "", _rootHostKey);
            Assert(!result.Success && result.RollbackAttempted && result.RollbackSucceeded,
                "A partial installation failure was not rolled back automatically " +
                "(success=" + result.Success + ", attempted=" + result.RollbackAttempted +
                ", rolledBack=" + result.RollbackSucceeded + ", kind=" + result.FailureKind + ").");
            string owner = "/var/lib/agent-ssh-key-manager/" + record.Id + ".owner";
            string sudoers = "/etc/sudoers.d/agent-ssh-" + record.Id.Substring(0, 16);
            string check = RunKeyCommand("root", _rootKey, "", _rootHostKey,
                "test ! -e " + SshTools.ShellQuote(owner) + " && test ! -e " + SshTools.ShellQuote(sudoers) +
                " && ! id -u " + SshTools.ShellQuote(record.User) + " >/dev/null 2>&1 && printf ROLLBACK_CLEAN");
            Assert(check.Contains("ROLLBACK_CLEAN"), "Rollback left account metadata on the server.");
            RemoveCleanup(record);
            SessionStore.DeleteSecretMaterial(record);
            Report.Add("Partial installation failure with automatic rollback: OK");
        }

        private static void TestPasswordAuthenticationCompatibility()
        {
            // Register cleanup before changing sshd so any failure in the compound
            // command still causes the finally block to remove the override.
            _passwordLoginWasEnabled = true;
            RunKeyCommand("root", _rootKey, "", _rootHostKey,
                "printf '%s\\n' 'PasswordAuthentication yes' 'KbdInteractiveAuthentication yes' " +
                "> /etc/ssh/sshd_config.d/00-agent-ssh-password-test.conf && " +
                "/usr/sbin/sshd -t && systemctl restart ssh");
            Thread.Sleep(1000);

            BootstrapHostKey enabled = ExistingKeyBootstrapper.ProbeHost(_host, _port, "bootstrap");
            Assert(enabled.SupportsPasswordAuthentication, "Password-capable server was not detected.");
            TestPasswordLogin("bootstrap", _bootstrapPassword, enabled, true);
            TestPasswordLogin("bootstrap", "incorrect-ssh-password", enabled, false);

            bool restoreFailureWasReported = false;
            try
            {
                RunKeyCommand("root", _rootKey, "", _rootHostKey,
                    "printf '%s\\n' 'ThisIsNotAValidSshdDirective yes' > " +
                    "/etc/ssh/sshd_config.d/99-agent-ssh-restore-failure-test.conf");
                try
                {
                    RestorePasswordAuthentication();
                }
                catch (InvalidOperationException)
                {
                    restoreFailureWasReported = true;
                }
            }
            finally
            {
                RunKeyCommand("root", _rootKey, "", _rootHostKey,
                    "rm -f /etc/ssh/sshd_config.d/99-agent-ssh-restore-failure-test.conf");
            }
            Assert(restoreFailureWasReported, "A failed password-authentication restoration was not reported.");
            RestorePasswordAuthentication();
            BootstrapHostKey disabled = ExistingKeyBootstrapper.ProbeHost(_host, _port, "bootstrap");
            Assert(!disabled.SupportsPasswordAuthentication,
                "Disabled password authentication was not detected after restoration.");
            Report.Add("Enabled/disabled SSH password authentication and wrong-password distinction: OK");
        }

        private static void RestorePasswordAuthentication()
        {
            if (!_passwordLoginWasEnabled || _rootHostKey == null) return;
            Exception lastFailure = null;
            for (int attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    RunKeyCommand("root", _rootKey, "", _rootHostKey,
                        "rm -f /etc/ssh/sshd_config.d/00-agent-ssh-password-test.conf && " +
                        "/usr/sbin/sshd -t && systemctl restart ssh");
                    Thread.Sleep(750);
                    BootstrapHostKey observed = ExistingKeyBootstrapper.ProbeHost(_host, _port, "bootstrap");
                    if (!observed.SupportsPasswordAuthentication)
                    {
                        _passwordLoginWasEnabled = false;
                        return;
                    }
                    lastFailure = new InvalidOperationException("The running SSH service still accepts password authentication.");
                }
                catch (Exception ex)
                {
                    lastFailure = ex;
                }

                if (attempt < 2) Thread.Sleep(750);
            }
            throw new InvalidOperationException("Password authentication could not be restored and verified.", lastFailure);
        }

        private static void TestRuntimeArchitecture()
        {
            string repository = Directory.GetCurrentDirectory();
            string[] runtimeSources =
            {
                "Program.cs", "ExistingKeyBootstrap.cs", "MainFormBootstrap.cs",
                "BootstrapDialogs.cs", "EmbeddedDependencyLoader.cs"
            };
            foreach (string name in runtimeSources)
            {
                string text = File.ReadAllText(Path.Combine(repository, name));
                Assert(text.IndexOf("powershell.exe", StringComparison.OrdinalIgnoreCase) < 0,
                    name + " starts powershell.exe.");
                Assert(text.IndexOf("ExecutionPolicy", StringComparison.OrdinalIgnoreCase) < 0,
                    name + " contains an ExecutionPolicy launch.");
            }
            string programSource = File.ReadAllText(Path.Combine(repository, "Program.cs"));
            int selfTestStart = programSource.IndexOf("public static class SelfTest", StringComparison.Ordinal);
            Assert(selfTestStart >= 0 && programSource.Substring(selfTestStart).IndexOf("ssh-action-install.\" + \"ps1", StringComparison.Ordinal) < 0,
                "The built-in self-test creates a legacy PowerShell-script fixture.");
            Report.Add("Runtime C# path has no PowerShell/ExecutionPolicy launch: OK");
            Report.Add("Bootstrap secrets absent from command-line arguments and saved metadata: OK");
        }

        private static void TestNoResidualAccess()
        {
            string check = RunKeyCommand("root", _rootKey, "", _rootHostKey,
                "if getent passwd | cut -d: -f1 | grep -q '^agentssh_'; then exit 1; fi; " +
                "if find /etc/sudoers.d -maxdepth 1 -type f -name 'agent-ssh-*' -print -quit | grep -q .; then exit 1; fi; " +
                "if find /var/lib/agent-ssh-key-manager -maxdepth 1 -type f -name '*.owner' -print -quit 2>/dev/null | grep -q .; then exit 1; fi; " +
                "if find /home -maxdepth 1 -mindepth 1 -type d -name 'agentssh_*' -print -quit 2>/dev/null | grep -q .; then exit 1; fi; " +
                "! grep -Fq 'agent-ssh-access:' /root/.ssh/authorized_keys; " +
                "! grep -Fq 'agent-ssh-access:' /home/bootstrap/.ssh/authorized_keys; " +
                "test ! -e /etc/ssh/sshd_config.d/00-agent-ssh-password-test.conf; " +
                "/usr/sbin/sshd -T -C user=bootstrap,host=localhost,addr=127.0.0.1 | " +
                "grep -Eq '^passwordauthentication no$'; " +
                "/usr/sbin/sshd -T -C user=bootstrap,host=localhost,addr=127.0.0.1 | " +
                "grep -Eq '^kbdinteractiveauthentication no$'; printf NO_RESIDUE");
            Assert(check.Contains("NO_RESIDUE"), "Acceptance tests left temporary server access or enabled password login.");
            Report.Add("No temporary account, key marker, sudoers/owner file, or password-login override remains: OK");
        }

        private static SessionRecord CreateRecord(string bootstrapUser, bool dedicated, bool expiry)
        {
            string id = Guid.NewGuid().ToString("N");
            string shortId = id.Substring(0, 10);
            string directory = Path.Combine(_workDirectory, id);
            var record = new SessionRecord
            {
                Id = id,
                Alias = "agent-ssh-" + shortId,
                Host = _host,
                BootstrapUser = bootstrapUser,
                BootstrapMethod = BootstrapMethods.ExistingKey,
                AccessMode = dedicated ? "DedicatedAdmin" : "ExistingUser",
                User = dedicated ? "agentssh_" + shortId : bootstrapUser,
                Port = _port,
                CreatedUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture),
                ExpiresUtc = DateTime.UtcNow.AddHours(2).ToString("o", CultureInfo.InvariantCulture),
                EnforceServerExpiry = expiry,
                State = "Preparing",
                Marker = "agent-ssh-access:" + id,
                SudoStatus = "Unknown",
                SessionDirectory = directory,
                PrivateKeyPath = Path.Combine(directory, "id_ed25519"),
                KnownHostsPath = Path.Combine(directory, "known_hosts"),
                ConfigPath = Path.Combine(directory, "ssh_config"),
                LastMessage = "Acceptance test"
            };
            record.PublicKeyPath = record.PrivateKeyPath + ".pub";
            return record;
        }

        private static void PrepareRecord(SessionRecord record, BootstrapHostKey hostKey)
        {
            Directory.CreateDirectory(record.SessionDirectory);
            SessionStore.TrySecureDirectory(record.SessionDirectory);
            SshTools.GenerateKeyAndFiles(record, record.EnforceServerExpiry);
            ExistingKeyBootstrapper.WriteKnownHosts(record, hostKey);
            SshTools.WriteAgentInstructions(record);
        }

        private static bool IsTemporaryAccessAccepted(SessionRecord record)
        {
            RunResult result = SshTools.VerifyKey(record);
            return result.ExitCode == 0 &&
                (result.StandardOutput ?? "").Contains("AGENT_SSH_ACCESS_OK");
        }

        private static string RunKeyCommand(string user, string keyPath, string keyPassphrase,
            BootstrapHostKey expectedHostKey, string commandText)
        {
            using (var key = string.IsNullOrEmpty(keyPassphrase)
                ? new PrivateKeyFile(keyPath)
                : new PrivateKeyFile(keyPath, keyPassphrase))
            {
                var connection = new ConnectionInfo(_host, _port, user,
                    new PrivateKeyAuthenticationMethod(user, key));
                connection.Timeout = TimeSpan.FromSeconds(20);
                using (var client = new SshClient(connection))
                {
                    AttachStrictHostKey(client, expectedHostKey);
                    client.Connect();
                    using (SshCommand command = client.CreateCommand(commandText))
                    {
                        command.CommandTimeout = TimeSpan.FromSeconds(120);
                        string output = command.Execute();
                        int exitCode = command.ExitStatus.HasValue ? command.ExitStatus.Value : -1;
                        if (exitCode != 0)
                        {
                            throw new InvalidOperationException("Acceptance guest command failed with exit code " +
                                exitCode.ToString(CultureInfo.InvariantCulture) + ".");
                        }
                        return output ?? "";
                    }
                }
            }
        }

        private static void TestPasswordLogin(string user, string password,
            BootstrapHostKey expectedHostKey, bool shouldSucceed)
        {
            var connection = new ConnectionInfo(_host, _port, user,
                new PasswordAuthenticationMethod(user, password));
            connection.Timeout = TimeSpan.FromSeconds(20);
            using (var client = new SshClient(connection))
            {
                AttachStrictHostKey(client, expectedHostKey);
                try
                {
                    client.Connect();
                    if (!shouldSucceed) throw new InvalidOperationException("An incorrect SSH password was accepted.");
                }
                catch (SshAuthenticationException)
                {
                    if (shouldSucceed) throw new InvalidOperationException("The correct SSH password was rejected.");
                    return;
                }
                finally
                {
                    if (client.IsConnected) client.Disconnect();
                }
            }
        }

        private static void AttachStrictHostKey(SshClient client, BootstrapHostKey expected)
        {
            client.HostKeyReceived += delegate(object sender, HostKeyEventArgs e)
            {
                byte[] actual = e.HostKey ?? new byte[0];
                byte[] wanted = expected == null ? new byte[0] : expected.KeyData ?? new byte[0];
                int difference = actual.Length ^ wanted.Length;
                int count = Math.Min(actual.Length, wanted.Length);
                for (int index = 0; index < count; index++) difference |= actual[index] ^ wanted[index];
                e.CanTrust = difference == 0;
            };
        }

        private static void AssertMetadataContainsNoSecrets(SessionRecord record)
        {
            string privateKeyContents = File.ReadAllText(record.PrivateKeyPath);
            string[] secretValues = { _sudoKeyPassphrase, _bootstrapPassword, privateKeyContents };
            string[] metadataFiles = Directory.GetFiles(record.SessionDirectory, "*", SearchOption.TopDirectoryOnly)
                .Where(path => !string.Equals(path, record.PrivateKeyPath, StringComparison.OrdinalIgnoreCase)).ToArray();
            foreach (string path in metadataFiles)
            {
                string contents = File.ReadAllText(path);
                foreach (string secret in secretValues)
                {
                    Assert(string.IsNullOrEmpty(secret) || contents.IndexOf(secret, StringComparison.Ordinal) < 0,
                        "A secret was written to " + Path.GetFileName(path) + ".");
                }
                Assert(contents.IndexOf(_rootKey, StringComparison.OrdinalIgnoreCase) < 0 &&
                    contents.IndexOf(_sudoKey, StringComparison.OrdinalIgnoreCase) < 0,
                    "A bootstrap private-key path was persisted in " + Path.GetFileName(path) + ".");
            }
        }

        private static void AssertNoSecretArguments()
        {
            string commandLine = string.Join("\n", Environment.GetCommandLineArgs());
            if (!string.IsNullOrEmpty(_sudoKeyPassphrase)) Assert(!commandLine.Contains(_sudoKeyPassphrase),
                "Key passphrase appeared in the test process arguments.");
            if (!string.IsNullOrEmpty(_bootstrapPassword)) Assert(!commandLine.Contains(_bootstrapPassword),
                "Password appeared in the test process arguments.");
        }

        private static void ExpectBootstrapFailure(Action action, BootstrapFailureKind expected, string scenario)
        {
            try
            {
                action();
            }
            catch (BootstrapException ex)
            {
                if (ex.Kind == expected) return;
                throw new InvalidOperationException("Wrong diagnostic for " + scenario + ": " + ex.Kind);
            }
            throw new InvalidOperationException("Expected diagnostic was not raised for " + scenario + ".");
        }

        private static BootstrapHostKey CloneHostKey(BootstrapHostKey source)
        {
            return new BootstrapHostKey
            {
                Algorithm = source.Algorithm,
                Fingerprint = source.Fingerprint,
                KeyData = (source.KeyData ?? new byte[0]).ToArray(),
                AuthenticationMethods = (source.AuthenticationMethods ?? new string[0]).ToArray(),
                AuthenticationMethodsKnown = source.AuthenticationMethodsKnown
            };
        }

        private static void AddCleanup(SessionRecord record, string keyPath, string keyPassphrase,
            string sudoPassword, BootstrapHostKey hostKey)
        {
            CleanupTargets.Add(new CleanupTarget
            {
                Record = record,
                KeyPath = keyPath,
                KeyPassphrase = keyPassphrase,
                SudoPassword = sudoPassword,
                HostKey = hostKey
            });
        }

        private static void RemoveCleanup(SessionRecord record)
        {
            CleanupTargets.RemoveAll(target => object.ReferenceEquals(target.Record, record));
        }

        private static void CleanupServerTargets()
        {
            foreach (CleanupTarget target in CleanupTargets.ToArray())
            {
                try
                {
                    ExistingKeyBootstrapper.Remove(target.Record, target.KeyPath,
                        target.KeyPassphrase, target.SudoPassword, target.HostKey);
                }
                catch { }
                try { SessionStore.DeleteSecretMaterial(target.Record); }
                catch { }
                target.KeyPassphrase = null;
                target.SudoPassword = null;
            }
            CleanupTargets.Clear();
        }

        private static string ReadSecret(string name)
        {
            string path = Path.Combine(_fixtureDirectory, name);
            string value = File.ReadAllText(path).TrimEnd('\r', '\n');
            if (value.Length == 0) throw new InvalidOperationException("A required test secret is empty.");
            return value;
        }

        private static string NormalizeText(string value)
        {
            return (value ?? "").Replace("\r\n", "\n").TrimEnd('\r', '\n');
        }

        private static string SafeOneLine(string value)
        {
            string safe = (value ?? "unknown error").Replace('\r', ' ').Replace('\n', ' ');
            return safe.Length <= 600 ? safe : safe.Substring(0, 600);
        }

        private static void WriteReport(string path, IEnumerable<string> lines)
        {
            try
            {
                string parent = Path.GetDirectoryName(path);
                if (!string.IsNullOrWhiteSpace(parent)) Directory.CreateDirectory(parent);
                File.WriteAllLines(path, lines.ToArray(), new UTF8Encoding(false));
            }
            catch { }
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition) throw new InvalidOperationException(message);
        }

        private sealed class CleanupTarget
        {
            public SessionRecord Record { get; set; }
            public string KeyPath { get; set; }
            public string KeyPassphrase { get; set; }
            public string SudoPassword { get; set; }
            public BootstrapHostKey HostKey { get; set; }
        }
    }
}
