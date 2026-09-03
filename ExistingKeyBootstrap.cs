using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

using Renci.SshNet;
using Renci.SshNet.Common;

namespace AgentSshKeyManager
{
    internal enum BootstrapFailureKind
    {
        None,
        ConnectionFailed,
        HostKeyMismatch,
        UnsupportedKeyFormat,
        KeyPassphraseRequired,
        IncorrectKeyPassphrase,
        KeyAuthenticationFailed,
        UserLoginDenied,
        SudoUnavailable,
        SudoPasswordRequired,
        IncorrectSudoPassword,
        NoSudoRights,
        AuthorizedKeysWriteFailed,
        RemoteCommandFailed,
        RollbackFailed
    }

    internal sealed class BootstrapException : Exception
    {
        public BootstrapFailureKind Kind { get; private set; }

        public BootstrapException(BootstrapFailureKind kind, string message)
            : base(message)
        {
            Kind = kind;
        }
    }

    internal sealed class BootstrapHostKey
    {
        public string Algorithm { get; set; }
        public string Fingerprint { get; set; }
        public byte[] KeyData { get; set; }
        public string[] AuthenticationMethods { get; set; }
        public bool AuthenticationMethodsKnown { get; set; }

        public bool SupportsPasswordAuthentication
        {
            get
            {
                return (AuthenticationMethods ?? new string[0]).Any(method =>
                    string.Equals(method, "password", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(method, "keyboard-interactive", StringComparison.OrdinalIgnoreCase));
            }
        }

        public bool SupportsPublicKeyAuthentication
        {
            get
            {
                return (AuthenticationMethods ?? new string[0]).Any(method =>
                    string.Equals(method, "publickey", StringComparison.OrdinalIgnoreCase));
            }
        }
    }

    internal sealed class BootstrapOperationResult
    {
        public bool Success { get; set; }
        public BootstrapFailureKind FailureKind { get; set; }
        public string Message { get; set; }
        public bool RollbackAttempted { get; set; }
        public bool RollbackSucceeded { get; set; }

        public static BootstrapOperationResult Ok(string message)
        {
            return new BootstrapOperationResult
            {
                Success = true,
                FailureKind = BootstrapFailureKind.None,
                Message = message
            };
        }
    }

    internal sealed class KeyFileInspection
    {
        public string Format { get; set; }
        public bool IsEncrypted { get; set; }
    }

    internal sealed class RemoteCommandResult
    {
        public int ExitCode { get; set; }
        public string StandardOutput { get; set; }
        public string StandardError { get; set; }
    }

    internal sealed class ExistingKeyConnection : IDisposable
    {
        public SshClient Client { get; private set; }
        public PrivateKeyFile PrivateKey { get; private set; }

        public ExistingKeyConnection(SshClient client, PrivateKeyFile privateKey)
        {
            Client = client;
            PrivateKey = privateKey;
        }

        public void Dispose()
        {
            if (Client != null)
            {
                try { if (Client.IsConnected) Client.Disconnect(); }
                catch { }
                Client.Dispose();
                Client = null;
            }
            if (PrivateKey != null)
            {
                PrivateKey.Dispose();
                PrivateKey = null;
            }
        }
    }

    internal static class ExistingKeyBootstrapper
    {
        private const int MaximumPrivateKeyBytes = 16 * 1024 * 1024;
        private static readonly TimeSpan ConnectionTimeout = TimeSpan.FromSeconds(20);
        private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(120);

        public static BootstrapHostKey ProbeHost(string host, int port, string user)
        {
            ValidateEndpoint(host, port, user);
            var authentication = new NoneAuthenticationMethod(user);
            var connection = new ConnectionInfo(host, port, user, authentication);
            connection.Timeout = ConnectionTimeout;
            BootstrapHostKey captured = null;
            string[] reportedAuthenticationMethods = new string[0];

            using (var client = new SshClient(connection))
            {
                client.HostKeyReceived += delegate(object sender, HostKeyEventArgs e)
                {
                    captured = CaptureHostKey(e);
                    // This probe sends no password or key. Trust is temporary only so the
                    // server can report its authentication methods after key exchange.
                    e.CanTrust = true;
                };

                try
                {
                    client.Connect();
                    if (client.IsConnected) client.Disconnect();
                }
                catch (SshAuthenticationException ex)
                {
                    // SSH.NET performs its own initial "none" request before the
                    // configured methods. It exposes that server response only in
                    // this pinned-version exception when no configured method matches.
                    reportedAuthenticationMethods = ParseAuthenticationMethods(ex.Message);
                }
                catch (SocketException)
                {
                    throw new BootstrapException(BootstrapFailureKind.ConnectionFailed,
                        "The server could not be reached on the selected SSH port.");
                }
                catch (SshOperationTimeoutException)
                {
                    throw new BootstrapException(BootstrapFailureKind.ConnectionFailed,
                        "The SSH connection timed out before the server host key was received.");
                }
                catch (SshConnectionException)
                {
                    if (captured == null)
                    {
                        throw new BootstrapException(BootstrapFailureKind.ConnectionFailed,
                            "The server closed the SSH connection before its host key could be verified.");
                    }
                }
            }

            if (captured == null)
            {
                throw new BootstrapException(BootstrapFailureKind.ConnectionFailed,
                    "The server did not provide a verifiable SSH host key.");
            }
            string[] methodResult = (authentication.AllowedAuthentications ?? new string[0]).ToArray();
            if (methodResult.Length == 0) methodResult = reportedAuthenticationMethods;
            captured.AuthenticationMethods = methodResult;
            captured.AuthenticationMethodsKnown = methodResult.Length > 0;
            return captured;
        }

        internal static string[] ParseAuthenticationMethods(string message)
        {
            const string Prefix = "No suitable authentication method found to complete authentication (";
            string value = message ?? "";
            int start = value.IndexOf(Prefix, StringComparison.Ordinal);
            if (start < 0) return new string[0];
            start += Prefix.Length;
            int end = value.IndexOf(')', start);
            if (end <= start) return new string[0];
            string[] methods = value.Substring(start, end - start).Split(',');
            return methods.Select(method => method.Trim())
                .Where(method => Regex.IsMatch(method, "^[A-Za-z0-9@._+-]+$", RegexOptions.CultureInvariant))
                .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }

        public static void TestAuthentication(string host, int port, string user, string keyPath,
            string keyPassphrase, BootstrapHostKey expectedHostKey)
        {
            using (ExistingKeyConnection connection = Connect(host, port, user, keyPath, keyPassphrase, expectedHostKey))
            using (SshCommand command = connection.Client.CreateCommand("printf 'AGENT_BOOTSTRAP_OK'"))
            {
                command.CommandTimeout = TimeSpan.FromSeconds(20);
                string output = command.Execute();
                int exitCode = command.ExitStatus.HasValue ? command.ExitStatus.Value : -1;
                if (exitCode != 0 || !string.Equals(output, "AGENT_BOOTSTRAP_OK", StringComparison.Ordinal))
                {
                    throw new BootstrapException(BootstrapFailureKind.UserLoginDenied,
                        "The key authenticated, but the bootstrap user could not execute an SSH command.");
                }
            }
        }

        public static void TestAdministrativeAccess(string host, int port, string user, string keyPath,
            string keyPassphrase, string sudoPassword, BootstrapHostKey expectedHostKey)
        {
            var record = new SessionRecord
            {
                Host = host,
                Port = port,
                BootstrapUser = user,
                AccessMode = "DedicatedAdmin"
            };
            using (ExistingKeyConnection connection = Connect(host, port, user, keyPath, keyPassphrase, expectedHostKey))
            {
                PrepareSudo(connection.Client, record, sudoPassword);
            }
        }

        public static BootstrapOperationResult Install(SessionRecord record, string keyPath,
            string keyPassphrase, string sudoPassword, BootstrapHostKey expectedHostKey)
        {
            using (ExistingKeyConnection connection = Connect(record.Host, record.Port, record.BootstrapUser,
                keyPath, keyPassphrase, expectedHostKey))
            {
                SudoContext sudo = PrepareSudo(connection.Client, record, sudoPassword);
                string publicKey = SshTools.ReadValidatedPublicKey(record);
                bool useExpiry = record.EnforceServerExpiry;
                string options = "no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc";
                string authorizedLine = options + " " + publicKey;
                long expiryUnixSeconds = SshTools.UnixSecondsForBootstrap(record.ExpiresUtcValue);
                string remote = record.UsesDedicatedAdminAccount
                    ? SshTools.BuildDedicatedSetupCommand(record, authorizedLine, useExpiry, expiryUnixSeconds)
                    : SshTools.BuildInstallCommand(record.Marker, authorizedLine, useExpiry, expiryUnixSeconds);

                RemoteCommandResult result;
                try
                {
                    result = ExecuteRemote(connection.Client,
                        WrapWithSudoValidation(remote, sudo), sudo.ProvidePassword ? sudoPassword : null);
                }
                catch
                {
                    bool rollbackSucceeded = TryRollback(connection.Client, record, sudo, sudoPassword);
                    return new BootstrapOperationResult
                    {
                        Success = false,
                        FailureKind = rollbackSucceeded ? BootstrapFailureKind.RemoteCommandFailed : BootstrapFailureKind.RollbackFailed,
                        Message = rollbackSucceeded
                            ? "The installation command was interrupted. Changes made by this session were rolled back."
                            : "The installation command was interrupted and automatic rollback could not be confirmed; use the displayed manual cleanup command.",
                        RollbackAttempted = true,
                        RollbackSucceeded = rollbackSucceeded
                    };
                }
                if (result.ExitCode == 0)
                {
                    return BootstrapOperationResult.Ok("Bootstrap key installed the temporary access successfully.");
                }

                BootstrapOperationResult failure = new BootstrapOperationResult();
                failure.Success = false;
                failure.FailureKind = ClassifyInstallFailure(result);
                failure.Message = failure.FailureKind == BootstrapFailureKind.AuthorizedKeysWriteFailed
                    ? "The server could not update authorized_keys for the selected account."
                    : "The server rejected or could not complete the temporary-access installation command.";
                failure.RollbackAttempted = true;
                failure.RollbackSucceeded = TryRollback(connection.Client, record, sudo, sudoPassword);
                if (failure.RollbackSucceeded)
                {
                    failure.Message += " Changes made by this session were rolled back.";
                }
                else
                {
                    failure.FailureKind = BootstrapFailureKind.RollbackFailed;
                    failure.Message += " Automatic rollback could not be confirmed; use the displayed manual cleanup command.";
                }
                return failure;
            }
        }

        public static BootstrapOperationResult Remove(SessionRecord record, string keyPath,
            string keyPassphrase, string sudoPassword, BootstrapHostKey expectedHostKey)
        {
            using (ExistingKeyConnection connection = Connect(record.Host, record.Port, record.BootstrapUser,
                keyPath, keyPassphrase, expectedHostKey))
            {
                SudoContext sudo = PrepareSudo(connection.Client, record, sudoPassword);
                string remote = record.UsesDedicatedAdminAccount
                    ? SshTools.BuildDedicatedCleanupCommand(record)
                    : SshTools.BuildRemovalCommand(record.Marker, record.Id);
                RemoteCommandResult result = ExecuteRemote(connection.Client,
                    WrapWithSudoValidation(remote, sudo), sudo.ProvidePassword ? sudoPassword : null);
                if (SshTools.CleanupWasConfirmed(record, result.ExitCode, result.StandardOutput))
                {
                    return BootstrapOperationResult.Ok("The bootstrap key removed the temporary access successfully.");
                }
                return new BootstrapOperationResult
                {
                    Success = false,
                    FailureKind = BootstrapFailureKind.RemoteCommandFailed,
                    Message = "The server did not confirm removal of the temporary access."
                };
            }
        }

        public static KeyFileInspection InspectAndValidatePrivateKey(string keyPath, string keyPassphrase)
        {
            KeyFileInspection inspection = InspectKeyFile(keyPath);
            using (PrivateKeyFile key = LoadPrivateKey(keyPath, keyPassphrase, inspection))
            {
                return inspection;
            }
        }

        public static string NormalizeFingerprint(string value)
        {
            string normalized = (value ?? "").Trim();
            if (normalized.Length == 0) return "";
            if (!normalized.StartsWith("SHA256:", StringComparison.OrdinalIgnoreCase))
            {
                normalized = "SHA256:" + normalized;
            }
            normalized = "SHA256:" + normalized.Substring(7).TrimEnd('=');
            if (!Regex.IsMatch(normalized, "^SHA256:[A-Za-z0-9+/]{43}$", RegexOptions.CultureInvariant))
            {
                throw new BootstrapException(BootstrapFailureKind.HostKeyMismatch,
                    "Enter a valid SHA256 SSH host-key fingerprint.");
            }
            return normalized;
        }

        public static bool HostKeyMatches(BootstrapHostKey expected, BootstrapHostKey actual)
        {
            if (expected == null || actual == null) return false;
            if (!string.Equals(NormalizeFingerprint(expected.Fingerprint), NormalizeFingerprint(actual.Fingerprint),
                StringComparison.Ordinal)) return false;
            byte[] left = expected.KeyData ?? new byte[0];
            byte[] right = actual.KeyData ?? new byte[0];
            if (left.Length != right.Length) return false;
            int difference = 0;
            for (int index = 0; index < left.Length; index++) difference |= left[index] ^ right[index];
            return difference == 0;
        }

        public static void WriteKnownHosts(SessionRecord record, BootstrapHostKey hostKey)
        {
            if (record == null || hostKey == null || hostKey.KeyData == null || hostKey.KeyData.Length == 0)
            {
                throw new InvalidOperationException("The confirmed server host key is unavailable.");
            }
            if (!Regex.IsMatch(hostKey.Algorithm ?? "", "^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521))$",
                RegexOptions.CultureInvariant))
            {
                throw new InvalidOperationException("The server host-key algorithm is not supported for known_hosts.");
            }
            string hostToken = record.Port == 22 ? record.Host : "[" + record.Host + "]:" +
                record.Port.ToString(CultureInfo.InvariantCulture);
            string line = hostToken + " " + hostKey.Algorithm + " " + Convert.ToBase64String(hostKey.KeyData) + Environment.NewLine;
            File.WriteAllText(record.KnownHostsPath, line, new UTF8Encoding(false));
            SessionStore.TrySecurePrivateFile(record.KnownHostsPath);
            record.ServerHostKeyFingerprint = NormalizeFingerprint(hostKey.Fingerprint);
            record.ServerHostKeyAlgorithm = hostKey.Algorithm;
            File.WriteAllText(record.ConfigPath, SshTools.BuildConfig(record), new UTF8Encoding(false));
            SessionStore.TrySecurePrivateFile(record.ConfigPath);
        }

        private static ExistingKeyConnection Connect(string host, int port, string user, string keyPath,
            string keyPassphrase, BootstrapHostKey expectedHostKey)
        {
            ValidateEndpoint(host, port, user);
            if (expectedHostKey == null || expectedHostKey.KeyData == null)
            {
                throw new BootstrapException(BootstrapFailureKind.HostKeyMismatch,
                    "A confirmed server host key is required before using the bootstrap key.");
            }

            KeyFileInspection inspection = InspectKeyFile(keyPath);
            PrivateKeyFile privateKey = LoadPrivateKey(keyPath, keyPassphrase, inspection);
            var authentication = new PrivateKeyAuthenticationMethod(user, privateKey);
            var connectionInfo = new ConnectionInfo(host, port, user, authentication);
            connectionInfo.Timeout = ConnectionTimeout;
            var client = new SshClient(connectionInfo);
            bool hostKeyReceived = false;
            bool hostKeyMatched = false;
            client.HostKeyReceived += delegate(object sender, HostKeyEventArgs e)
            {
                hostKeyReceived = true;
                BootstrapHostKey actual = CaptureHostKey(e);
                hostKeyMatched = HostKeyMatches(expectedHostKey, actual);
                e.CanTrust = hostKeyMatched;
            };

            try
            {
                client.Connect();
                if (!hostKeyReceived || !hostKeyMatched)
                {
                    throw new BootstrapException(BootstrapFailureKind.HostKeyMismatch,
                        "The server host key does not match the fingerprint that was confirmed.");
                }
                return new ExistingKeyConnection(client, privateKey);
            }
            catch (BootstrapException)
            {
                client.Dispose();
                privateKey.Dispose();
                throw;
            }
            catch (SshAuthenticationException)
            {
                client.Dispose();
                privateKey.Dispose();
                if (hostKeyReceived && !hostKeyMatched)
                {
                    throw new BootstrapException(BootstrapFailureKind.HostKeyMismatch,
                        "The server host key changed and the connection was rejected.");
                }
                string[] allowed = authentication.AllowedAuthentications ?? new string[0];
                if (!allowed.Any(method => string.Equals(method, "publickey", StringComparison.OrdinalIgnoreCase)))
                {
                    throw new BootstrapException(BootstrapFailureKind.UserLoginDenied,
                        "This server does not permit public-key login for the selected bootstrap user.");
                }
                throw new BootstrapException(BootstrapFailureKind.KeyAuthenticationFailed,
                    "The server rejected the existing key for the selected bootstrap user. " +
                    "Verify that this key is authorized and that the user is permitted to log in through SSH.");
            }
            catch (SocketException)
            {
                client.Dispose();
                privateKey.Dispose();
                throw new BootstrapException(BootstrapFailureKind.ConnectionFailed,
                    "The server could not be reached on the selected SSH port.");
            }
            catch (SshOperationTimeoutException)
            {
                client.Dispose();
                privateKey.Dispose();
                throw new BootstrapException(BootstrapFailureKind.ConnectionFailed,
                    "The SSH connection timed out.");
            }
            catch (SshConnectionException)
            {
                client.Dispose();
                privateKey.Dispose();
                if (hostKeyReceived && !hostKeyMatched)
                {
                    throw new BootstrapException(BootstrapFailureKind.HostKeyMismatch,
                        "The server host key changed and the connection was rejected.");
                }
                throw new BootstrapException(BootstrapFailureKind.ConnectionFailed,
                    "The server closed the SSH connection unexpectedly.");
            }
            catch
            {
                client.Dispose();
                privateKey.Dispose();
                throw;
            }
        }

        private static PrivateKeyFile LoadPrivateKey(string keyPath, string keyPassphrase, KeyFileInspection inspection)
        {
            string passphrase = string.IsNullOrEmpty(keyPassphrase) ? null : keyPassphrase;
            try
            {
                return new PrivateKeyFile(keyPath, passphrase);
            }
            catch (SshPassPhraseNullOrEmptyException)
            {
                throw new BootstrapException(BootstrapFailureKind.KeyPassphraseRequired,
                    "This private key is encrypted. Enter its key passphrase.");
            }
            catch (NotSupportedException)
            {
                throw new BootstrapException(BootstrapFailureKind.UnsupportedKeyFormat,
                    "The private-key format, version, encryption, or algorithm is not supported.");
            }
            catch (SshException)
            {
                if (inspection != null && inspection.IsEncrypted)
                {
                    throw new BootstrapException(BootstrapFailureKind.IncorrectKeyPassphrase,
                        "The private-key passphrase is incorrect.");
                }
                throw new BootstrapException(BootstrapFailureKind.UnsupportedKeyFormat,
                    "The private-key file is invalid or uses an unsupported format.");
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                if (inspection != null && inspection.IsEncrypted)
                {
                    throw new BootstrapException(BootstrapFailureKind.IncorrectKeyPassphrase,
                        "The private-key passphrase is incorrect.");
                }
                throw new BootstrapException(BootstrapFailureKind.UnsupportedKeyFormat,
                    "The private-key file could not be parsed securely.");
            }
            catch (Org.BouncyCastle.Crypto.InvalidCipherTextException)
            {
                if (inspection != null && inspection.IsEncrypted)
                {
                    throw new BootstrapException(BootstrapFailureKind.IncorrectKeyPassphrase,
                        "The private-key passphrase is incorrect.");
                }
                throw new BootstrapException(BootstrapFailureKind.UnsupportedKeyFormat,
                    "The private-key file could not be decrypted securely.");
            }
        }

        private static KeyFileInspection InspectKeyFile(string keyPath)
        {
            if (string.IsNullOrWhiteSpace(keyPath))
            {
                throw new BootstrapException(BootstrapFailureKind.UnsupportedKeyFormat,
                    "Select an existing OpenSSH or PuTTY private-key file.");
            }
            FileInfo file;
            try { file = new FileInfo(Path.GetFullPath(keyPath)); }
            catch
            {
                throw new BootstrapException(BootstrapFailureKind.UnsupportedKeyFormat,
                    "The selected private-key path is invalid.");
            }
            if (!file.Exists || file.Length <= 0 || file.Length > MaximumPrivateKeyBytes)
            {
                throw new BootstrapException(BootstrapFailureKind.UnsupportedKeyFormat,
                    "The selected private-key file is missing, empty, or unexpectedly large.");
            }

            byte[] prefixBytes = new byte[(int)Math.Min(file.Length, 128 * 1024)];
            using (var stream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                int offset = 0;
                while (offset < prefixBytes.Length)
                {
                    int read = stream.Read(prefixBytes, offset, prefixBytes.Length - offset);
                    if (read <= 0) break;
                    offset += read;
                }
            }
            string prefix = Encoding.ASCII.GetString(prefixBytes);
            if (prefix.StartsWith("PuTTY-User-Key-File-", StringComparison.Ordinal))
            {
                Match encryption = Regex.Match(prefix, "(?m)^Encryption: (?<value>[^\\r\\n]+)\\r?$",
                    RegexOptions.CultureInvariant);
                return new KeyFileInspection
                {
                    Format = "PuTTY PPK",
                    IsEncrypted = encryption.Success && !string.Equals(encryption.Groups["value"].Value,
                        "none", StringComparison.OrdinalIgnoreCase)
                };
            }
            if (prefix.IndexOf("-----BEGIN OPENSSH PRIVATE KEY-----", StringComparison.Ordinal) >= 0)
            {
                return new KeyFileInspection { Format = "OpenSSH", IsEncrypted = IsEncryptedOpenSshKey(prefix) };
            }
            if (prefix.IndexOf("-----BEGIN ENCRYPTED PRIVATE KEY-----", StringComparison.Ordinal) >= 0 ||
                prefix.IndexOf("Proc-Type: 4,ENCRYPTED", StringComparison.Ordinal) >= 0)
            {
                return new KeyFileInspection { Format = "OpenSSH/PEM", IsEncrypted = true };
            }
            if (prefix.IndexOf("-----BEGIN PRIVATE KEY-----", StringComparison.Ordinal) >= 0 ||
                prefix.IndexOf("-----BEGIN RSA PRIVATE KEY-----", StringComparison.Ordinal) >= 0 ||
                prefix.IndexOf("-----BEGIN EC PRIVATE KEY-----", StringComparison.Ordinal) >= 0 ||
                prefix.IndexOf("-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----", StringComparison.Ordinal) >= 0)
            {
                return new KeyFileInspection { Format = "OpenSSH/PEM", IsEncrypted = false };
            }
            throw new BootstrapException(BootstrapFailureKind.UnsupportedKeyFormat,
                "The selected file is not a supported OpenSSH or PuTTY private key.");
        }

        private static bool IsEncryptedOpenSshKey(string text)
        {
            try
            {
                int begin = text.IndexOf("-----BEGIN OPENSSH PRIVATE KEY-----", StringComparison.Ordinal);
                int dataStart = text.IndexOf('\n', begin) + 1;
                int end = text.IndexOf("-----END OPENSSH PRIVATE KEY-----", dataStart, StringComparison.Ordinal);
                if (begin < 0 || dataStart <= 0 || end <= dataStart) return true;
                string base64 = Regex.Replace(text.Substring(dataStart, end - dataStart), "\\s+", "");
                byte[] data = Convert.FromBase64String(base64);
                byte[] magic = Encoding.ASCII.GetBytes("openssh-key-v1\0");
                if (data.Length < magic.Length + 4) return true;
                for (int index = 0; index < magic.Length; index++) if (data[index] != magic[index]) return true;
                int offset = magic.Length;
                int length = ReadNetworkInt32(data, offset);
                offset += 4;
                if (length < 0 || length > 128 || offset + length > data.Length) return true;
                string cipher = Encoding.ASCII.GetString(data, offset, length);
                return !string.Equals(cipher, "none", StringComparison.Ordinal);
            }
            catch { return true; }
        }

        private static BootstrapHostKey CaptureHostKey(HostKeyEventArgs e)
        {
            byte[] key = (e.HostKey ?? new byte[0]).ToArray();
            string algorithm = ReadHostKeyAlgorithm(key);
            string fingerprint = NormalizeFingerprint("SHA256:" + (e.FingerPrintSHA256 ?? ""));
            return new BootstrapHostKey
            {
                Algorithm = algorithm,
                Fingerprint = fingerprint,
                KeyData = key,
                AuthenticationMethods = new string[0],
                AuthenticationMethodsKnown = false
            };
        }

        private static string ReadHostKeyAlgorithm(byte[] key)
        {
            if (key == null || key.Length < 8) throw new InvalidOperationException("The SSH host key is malformed.");
            int length = ReadNetworkInt32(key, 0);
            if (length <= 0 || length > 128 || 4 + length > key.Length)
            {
                throw new InvalidOperationException("The SSH host-key algorithm is malformed.");
            }
            return Encoding.ASCII.GetString(key, 4, length);
        }

        private static int ReadNetworkInt32(byte[] value, int offset)
        {
            if (value == null || offset < 0 || offset + 4 > value.Length) return -1;
            return (value[offset] << 24) | (value[offset + 1] << 16) |
                (value[offset + 2] << 8) | value[offset + 3];
        }

        private static SudoContext PrepareSudo(SshClient client, SessionRecord record, string sudoPassword)
        {
            if (!record.UsesDedicatedAdminAccount) return new SudoContext();

            if (string.Equals(record.BootstrapUser, "root", StringComparison.Ordinal))
            {
                RemoteCommandResult rootCheck = ExecuteRemote(client, "test \"$(id -u)\" = 0", null);
                if (rootCheck.ExitCode != 0)
                {
                    throw new BootstrapException(BootstrapFailureKind.UserLoginDenied,
                        "The selected root bootstrap login does not have UID 0.");
                }
                RemoteCommandResult rootSudo = ExecuteRemote(client,
                    "command -v sudo >/dev/null 2>&1 && sudo -n -v", null);
                return new SudoContext { DirectRoot = rootSudo.ExitCode != 0 };
            }

            RemoteCommandResult available = ExecuteRemote(client, "command -v sudo >/dev/null 2>&1", null);
            if (available.ExitCode != 0)
            {
                throw new BootstrapException(BootstrapFailureKind.SudoUnavailable,
                    "sudo is not installed or is unavailable for the bootstrap account.");
            }

            RemoteCommandResult passwordless = ExecuteRemote(client, "sudo -n -v", null);
            if (passwordless.ExitCode == 0) return new SudoContext { ProvidePassword = false };
            if (string.IsNullOrEmpty(sudoPassword))
            {
                throw new BootstrapException(BootstrapFailureKind.SudoPasswordRequired,
                    "This bootstrap user requires a sudo password.");
            }
            if (sudoPassword.IndexOf('\r') >= 0 || sudoPassword.IndexOf('\n') >= 0)
            {
                throw new BootstrapException(BootstrapFailureKind.IncorrectSudoPassword,
                    "The sudo password contains an unsupported line break.");
            }

            RemoteCommandResult validation = ExecuteRemote(client,
                "sudo -S -p '[agent-ssh-key-manager sudo] ' -v", sudoPassword);
            if (validation.ExitCode != 0)
            {
                string error = (validation.StandardError ?? "").ToLowerInvariant();
                if (error.Contains("not in the sudoers") || error.Contains("not allowed to run sudo") ||
                    error.Contains("may not run sudo"))
                {
                    throw new BootstrapException(BootstrapFailureKind.NoSudoRights,
                        "The bootstrap user does not have sudo rights.");
                }
                throw new BootstrapException(BootstrapFailureKind.IncorrectSudoPassword,
                    "The sudo password was rejected.");
            }
            return new SudoContext { ProvidePassword = true };
        }

        private static string WrapWithSudoValidation(string remote, SudoContext sudo)
        {
            if (sudo != null && sudo.DirectRoot)
            {
                return SshTools.RootSudoCompatibilityPrefix + remote;
            }
            return sudo != null && sudo.ProvidePassword
                ? "sudo -S -p '' -v && " + remote
                : remote;
        }

        private static RemoteCommandResult ExecuteRemote(SshClient client, string commandText, string inputSecret)
        {
            using (SshCommand command = client.CreateCommand(commandText))
            {
                command.CommandTimeout = CommandTimeout;
                string output;
                if (inputSecret == null)
                {
                    output = command.Execute();
                }
                else
                {
                    IAsyncResult execution = command.BeginExecute();
                    byte[] input = new UTF8Encoding(false).GetBytes(inputSecret + "\n");
                    try
                    {
                        using (Stream stream = command.CreateInputStream())
                        {
                            stream.Write(input, 0, input.Length);
                            stream.Flush();
                        }
                        output = command.EndExecute(execution);
                    }
                    finally
                    {
                        Array.Clear(input, 0, input.Length);
                    }
                }
                return new RemoteCommandResult
                {
                    ExitCode = command.ExitStatus.HasValue ? command.ExitStatus.Value : -1,
                    StandardOutput = Limit(command.Result ?? output),
                    StandardError = Limit(command.Error)
                };
            }
        }

        private static bool TryRollback(SshClient client, SessionRecord record, SudoContext sudo, string sudoPassword)
        {
            try
            {
                string cleanup = record.UsesDedicatedAdminAccount
                    ? SshTools.BuildDedicatedCleanupCommand(record)
                    : SshTools.BuildRemovalCommand(record.Marker, record.Id);
                RemoteCommandResult result = ExecuteRemote(client, WrapWithSudoValidation(cleanup, sudo),
                    sudo != null && sudo.ProvidePassword ? sudoPassword : null);
                return SshTools.CleanupWasConfirmed(record, result.ExitCode, result.StandardOutput);
            }
            catch { return false; }
        }

        private static BootstrapFailureKind ClassifyInstallFailure(RemoteCommandResult result)
        {
            string text = ((result.StandardOutput ?? "") + " " + (result.StandardError ?? "")).ToLowerInvariant();
            if (text.Contains("authorized_keys") || text.Contains("permission denied") || text.Contains("read-only file system"))
            {
                return BootstrapFailureKind.AuthorizedKeysWriteFailed;
            }
            return BootstrapFailureKind.RemoteCommandFailed;
        }

        private static string Limit(string value)
        {
            string safe = value ?? "";
            return safe.Length <= 8192 ? safe : safe.Substring(0, 8192);
        }

        private static void ValidateEndpoint(string host, int port, string user)
        {
            if (string.IsNullOrWhiteSpace(host) || host.Length > 253 ||
                !Regex.IsMatch(host, "^[A-Za-z0-9._:-]+$") || !Regex.IsMatch(host, "[A-Za-z0-9]"))
            {
                throw new BootstrapException(BootstrapFailureKind.ConnectionFailed, "The server address is invalid.");
            }
            if (port < 1 || port > 65535)
            {
                throw new BootstrapException(BootstrapFailureKind.ConnectionFailed, "The SSH port is invalid.");
            }
            if (string.IsNullOrWhiteSpace(user) || user.Length > 64 ||
                !Regex.IsMatch(user, "^[A-Za-z0-9_][A-Za-z0-9._-]*$"))
            {
                throw new BootstrapException(BootstrapFailureKind.UserLoginDenied, "The bootstrap username is invalid.");
            }
        }

        private sealed class SudoContext
        {
            public bool ProvidePassword { get; set; }
            public bool DirectRoot { get; set; }
        }
    }
}
