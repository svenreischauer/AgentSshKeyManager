using System;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AgentSshKeyManager
{
    internal static class BootstrapMethods
    {
        public const string Password = "Password";
        public const string ExistingKey = "ExistingKey";
        public const string Manual = "Manual";

        public static string DisplayName(string value)
        {
            if (value == ExistingKey) return "Existing SSH key";
            if (value == Manual) return "Manual installation";
            return "Username and password";
        }
    }

    internal static class ClipboardHelper
    {
        public static async Task<bool> TryCopyTextAsync(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return false;
            const int attempts = 8;
            for (int attempt = 0; attempt < attempts; attempt++)
            {
                try
                {
                    Clipboard.SetDataObject(text, true, 2, 50);
                    await Task.Delay(40);
                    if (Clipboard.ContainsText(TextDataFormat.UnicodeText) &&
                        string.Equals(Clipboard.GetText(TextDataFormat.UnicodeText), text, StringComparison.Ordinal))
                    {
                        return true;
                    }
                }
                catch (ExternalException)
                {
                    // Another application temporarily owns the clipboard. Retry below.
                }
                catch
                {
                    // Clipboard providers can fail without an ExternalException. Retry safely.
                }

                if (attempt + 1 < attempts)
                {
                    await Task.Delay(100 + (attempt * 75));
                }
            }
            return false;
        }
    }

    internal sealed class ExistingKeyCredentialsDialog : Form
    {
        private readonly TextBox _keyPath;
        private readonly TextBox _keyPassphrase;
        private readonly TextBox _sudoPassword;

        public string KeyPath { get { return (_keyPath.Text ?? "").Trim(); } }
        public string KeyPassphrase { get { return _keyPassphrase.Text ?? ""; } }
        public string SudoPassword { get { return _sudoPassword.Text ?? ""; } }

        public ExistingKeyCredentialsDialog(string initialKeyPath, bool sudoMayBeRequired)
        {
            Text = "Existing SSH key credentials";
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            ClientSize = new Size(660, 264);
            Font = new Font("Segoe UI", 9F, FontStyle.Regular, GraphicsUnit.Point);
            Icon = SystemIcons.Shield;

            var explanation = new Label();
            explanation.Location = new Point(18, 14);
            explanation.Size = new Size(624, 40);
            explanation.Text = "The existing key is opened read-only for this operation and is never copied into manager storage. " +
                "Passphrases and passwords are not written to files, logs, or process arguments.";
            Controls.Add(explanation);

            Controls.Add(MakeLabel("Private key file (OpenSSH or PuTTY .ppk)", 18, 62, 300));
            _keyPath = new TextBox();
            _keyPath.Location = new Point(18, 84);
            _keyPath.Size = new Size(516, 25);
            _keyPath.Text = initialKeyPath ?? "";
            Controls.Add(_keyPath);

            var browse = new Button();
            browse.Text = "Browse ...";
            browse.Location = new Point(544, 81);
            browse.Size = new Size(98, 30);
            browse.Click += BrowseClick;
            Controls.Add(browse);

            Controls.Add(MakeLabel("Key passphrase (optional)", 18, 122, 250));
            _keyPassphrase = new TextBox();
            _keyPassphrase.Location = new Point(18, 144);
            _keyPassphrase.Size = new Size(294, 25);
            _keyPassphrase.UseSystemPasswordChar = true;
            Controls.Add(_keyPassphrase);

            Controls.Add(MakeLabel(sudoMayBeRequired ? "Sudo password (if required)" : "Sudo password (not normally required)", 330, 122, 285));
            _sudoPassword = new TextBox();
            _sudoPassword.Location = new Point(330, 144);
            _sudoPassword.Size = new Size(312, 25);
            _sudoPassword.UseSystemPasswordChar = true;
            Controls.Add(_sudoPassword);

            var warning = new Label();
            warning.Location = new Point(18, 178);
            warning.Size = new Size(390, 45);
            warning.ForeColor = Color.FromArgb(120, 70, 0);
            warning.Text = "Secrets are never written to logs, session files, generated files, or process arguments.";
            Controls.Add(warning);

            var ok = new Button();
            ok.Text = "Continue";
            ok.Location = new Point(436, 202);
            ok.Size = new Size(98, 34);
            ok.DialogResult = DialogResult.OK;
            Controls.Add(ok);

            var cancel = new Button();
            cancel.Text = "Cancel";
            cancel.Location = new Point(544, 202);
            cancel.Size = new Size(98, 34);
            cancel.DialogResult = DialogResult.Cancel;
            Controls.Add(cancel);

            AcceptButton = ok;
            CancelButton = cancel;
        }

        public void ClearSecrets()
        {
            _keyPassphrase.Clear();
            _sudoPassword.Clear();
        }

        private void BrowseClick(object sender, EventArgs e)
        {
            using (var dialog = new OpenFileDialog())
            {
                dialog.Title = "Select an existing SSH private key";
                dialog.Filter = "SSH private keys (*.ppk;*.pem;*.key;id_*)|*.ppk;*.pem;*.key;id_*|PuTTY keys (*.ppk)|*.ppk|All files (*.*)|*.*";
                dialog.CheckFileExists = true;
                dialog.Multiselect = false;
                if (dialog.ShowDialog(this) == DialogResult.OK) _keyPath.Text = dialog.FileName;
            }
        }

        private static Label MakeLabel(string text, int x, int y, int width)
        {
            var label = new Label();
            label.Text = text;
            label.Location = new Point(x, y);
            label.Size = new Size(width, 20);
            return label;
        }
    }

    internal sealed class ManualActionDialog : Form
    {
        private readonly string _publicKey;
        private readonly string _command;

        public ManualActionDialog(string title, string introduction, string fingerprint,
            string publicKey, string command, string confirmText, string requiredConfirmation = null)
        {
            _publicKey = publicKey ?? "";
            _command = command ?? "";
            Text = title;
            StartPosition = FormStartPosition.CenterParent;
            MinimumSize = new Size(760, 610);
            Size = new Size(820, 660);
            Font = new Font("Segoe UI", 9F, FontStyle.Regular, GraphicsUnit.Point);
            Icon = SystemIcons.Shield;

            var intro = new Label();
            intro.Location = new Point(16, 14);
            intro.Size = new Size(770, 48);
            intro.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            intro.Text = introduction;
            Controls.Add(intro);

            var fingerprintLabel = new Label();
            fingerprintLabel.Location = new Point(16, 66);
            fingerprintLabel.Size = new Size(770, 42);
            fingerprintLabel.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            fingerprintLabel.Font = new Font(Font, FontStyle.Bold);
            fingerprintLabel.Text = "Confirmed server host-key fingerprint:\r\n" + (fingerprint ?? "-");
            Controls.Add(fingerprintLabel);

            int commandTop;
            if (_publicKey.Length > 0)
            {
                var publicLabel = new Label();
                publicLabel.Location = new Point(16, 116);
                publicLabel.Size = new Size(180, 20);
                publicLabel.Text = "Temporary public key";
                Controls.Add(publicLabel);

                var publicBox = MakeReadOnlyBox(16, 138, 770, 82);
                publicBox.Text = _publicKey;
                Controls.Add(publicBox);

                var copyPublic = new Button();
                copyPublic.Text = "Copy public key";
                copyPublic.Location = new Point(16, 228);
                copyPublic.Size = new Size(150, 32);
                copyPublic.Click += async delegate { await CopyTextAsync(_publicKey, "public key", copyPublic); };
                Controls.Add(copyPublic);
                commandTop = 272;
            }
            else
            {
                commandTop = 116;
            }

            var commandLabel = new Label();
            commandLabel.Location = new Point(16, commandTop);
            commandLabel.Size = new Size(300, 20);
            commandLabel.Text = "Command to run in the VM console or an existing SSH session";
            Controls.Add(commandLabel);

            var commandBox = MakeReadOnlyBox(16, commandTop + 22, 770, _publicKey.Length > 0 ? 220 : 350);
            commandBox.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            commandBox.Text = _command;
            Controls.Add(commandBox);

            var copyCommand = new Button();
            copyCommand.Text = "Copy command";
            copyCommand.Location = new Point(16, 570);
            copyCommand.Size = new Size(150, 34);
            copyCommand.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            copyCommand.Click += async delegate { await CopyTextAsync(_command, "command", copyCommand); };
            Controls.Add(copyCommand);

            var verify = new Button();
            verify.Text = confirmText;
            verify.Location = new Point(506, 570);
            verify.Size = new Size(170, 34);
            verify.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
            verify.DialogResult = DialogResult.OK;
            Controls.Add(verify);

            if (!string.IsNullOrWhiteSpace(requiredConfirmation))
            {
                var confirmationLabel = new Label();
                confirmationLabel.Location = new Point(186, 512);
                confirmationLabel.Size = new Size(600, 20);
                confirmationLabel.Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
                confirmationLabel.Text = "After running the command, paste its AGENT_SSH_CLEANUP_OK line here:";
                Controls.Add(confirmationLabel);

                var confirmationBox = new TextBox();
                confirmationBox.Location = new Point(186, 535);
                confirmationBox.Size = new Size(600, 25);
                confirmationBox.Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
                Controls.Add(confirmationBox);
                verify.Enabled = false;
                confirmationBox.TextChanged += delegate
                {
                    verify.Enabled = ContainsConfirmationLine(confirmationBox.Text, requiredConfirmation);
                };
            }

            var close = new Button();
            close.Text = "Close";
            close.Location = new Point(686, 570);
            close.Size = new Size(100, 34);
            close.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
            close.DialogResult = DialogResult.Cancel;
            Controls.Add(close);

            AcceptButton = verify;
            CancelButton = close;
        }

        private TextBox MakeReadOnlyBox(int x, int y, int width, int height)
        {
            var box = new TextBox();
            box.Location = new Point(x, y);
            box.Size = new Size(width, height);
            box.Multiline = true;
            box.ReadOnly = true;
            box.ScrollBars = ScrollBars.Both;
            box.WordWrap = false;
            box.BackColor = SystemColors.Window;
            box.Font = new Font("Consolas", 9F, FontStyle.Regular, GraphicsUnit.Point);
            return box;
        }

        internal static bool ContainsConfirmationLine(string text, string requiredConfirmation)
        {
            if (string.IsNullOrWhiteSpace(text) || string.IsNullOrWhiteSpace(requiredConfirmation)) return false;
            string[] lines = text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
            foreach (string line in lines)
            {
                if (string.Equals(line.Trim(), requiredConfirmation, StringComparison.Ordinal)) return true;
            }
            return false;
        }

        private async Task CopyTextAsync(string text, string description, Button button)
        {
            string originalText = button.Text;
            button.Enabled = false;
            button.Text = "Copying ...";
            try
            {
                bool copied = await ClipboardHelper.TryCopyTextAsync(text);
                if (IsDisposed) return;
                if (copied)
                {
                    MessageBox.Show(this, "The " + description + " was copied.", "Copied",
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    MessageBox.Show(this, "Windows could not open the clipboard after several attempts. Close any application that may be using it, then try again.",
                        "Clipboard unavailable", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
            finally
            {
                if (!button.IsDisposed)
                {
                    button.Text = originalText;
                    button.Enabled = true;
                }
            }
        }
    }
}
