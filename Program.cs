using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Xml.Serialization;

namespace AgentSshKeyManager
{
    [Serializable]
    public class SessionRecord
    {
        public string Id { get; set; }
        public string Alias { get; set; }
        public string Host { get; set; }
        public string BootstrapUser { get; set; }
        public string AccessMode { get; set; }
        public string User { get; set; }
        public int Port { get; set; }
        public string CreatedUtc { get; set; }
        public string ExpiresUtc { get; set; }
        public bool EnforceServerExpiry { get; set; }
        public string State { get; set; }
        public string Fingerprint { get; set; }
        public string Marker { get; set; }
        public string SudoStatus { get; set; }
        public string SessionDirectory { get; set; }
        public string PrivateKeyPath { get; set; }
        public string PublicKeyPath { get; set; }
        public string KnownHostsPath { get; set; }
        public string ConfigPath { get; set; }
        public string LastMessage { get; set; }

        public bool UsesDedicatedAdminAccount
        {
            get { return string.Equals(AccessMode, "DedicatedAdmin", StringComparison.Ordinal); }
        }

        public DateTime ExpiresUtcValue
        {
            get
            {
                DateTime value;
                if (DateTime.TryParse(ExpiresUtc, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out value))
                {
                    return value;
                }
                return DateTime.MinValue;
            }
        }

        public string DisplayState
        {
            get
            {
                if (State == "Active" && ExpiresUtcValue != DateTime.MinValue && DateTime.UtcNow >= ExpiresUtcValue)
                {
                    return "Expired";
                }
                if (State == "Active") return "Active";
                if (State == "Removed") return "Removed";
                if (State == "SetupFailed") return "Setup uncertain";
                if (State == "RemovalFailed") return "Removal uncertain";
                return State ?? "Unknown";
            }
        }
    }

    public class RunResult
    {
        public int ExitCode { get; set; }
        public string StandardOutput { get; set; }
        public string StandardError { get; set; }
        public bool TimedOut { get; set; }

        public string Combined
        {
            get
            {
                string text = ((StandardOutput ?? "") + Environment.NewLine + (StandardError ?? "")).Trim();
                return text;
            }
        }
    }

    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            if (args != null && args.Length >= 2 && args[0] == "--self-test")
            {
                return SelfTest.Run(args[1]);
            }

            if (args != null && args.Length >= 2 && args[0] == "--render-ui")
            {
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                using (var form = new MainForm())
                using (var image = new Bitmap(form.Width, form.Height))
                {
                    form.StartPosition = FormStartPosition.Manual;
                    form.Location = new Point(-32000, -32000);
                    form.ShowInTaskbar = false;
                    form.Show();
                    Application.DoEvents();
                    form.DrawToBitmap(image, new Rectangle(0, 0, image.Width, image.Height));
                    image.Save(args[1], ImageFormat.Png);
                    form.Hide();
                }
                return 0;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
            return 0;
        }
    }

    public class MainForm : Form
    {
        private TextBox _hostText;
        private TextBox _userText;
        private NumericUpDown _portNumber;
        private NumericUpDown _hoursNumber;
        private CheckBox _expiryCheck;
        private CheckBox _dedicatedAdminCheck;
        private Button _createButton;
        private Button _copyButton;
        private Button _testButton;
        private Button _removeButton;
        private Button _folderButton;
        private ListView _sessionsList;
        private TextBox _detailsText;
        private TextBox _logText;
        private Label _busyLabel;
        private readonly List<SessionRecord> _records = new List<SessionRecord>();
        private bool _busy;

        public MainForm()
        {
            Text = "Agent SSH Key Manager";
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(900, 700);
            Size = new Size(980, 780);
            Font = new Font("Segoe UI", 9F, FontStyle.Regular, GraphicsUnit.Point);
            Icon = SystemIcons.Shield;

            BuildUi();
            LoadSessions();
            UpdateSelection();
            Log("Ready. This tool does not store SSH or sudo passwords.");
        }

        private void BuildUi()
        {
            var intro = new Label();
            intro.AutoSize = false;
            intro.Location = new Point(18, 14);
            intro.Size = new Size(930, 52);
            intro.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            intro.Text = "This tool creates and installs a temporary SSH key for an agent, then removes it when it is no longer needed. Enter server passwords only in the separate SSH window.";
            intro.ForeColor = Color.FromArgb(30, 65, 110);
            intro.Font = new Font(Font, FontStyle.Bold);
            Controls.Add(intro);

            var setup = new GroupBox();
            setup.Text = "Create a temporary access";
            setup.Location = new Point(18, 72);
            setup.Size = new Size(930, 126);
            setup.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(setup);

            setup.Controls.Add(MakeLabel("Server (IP or hostname)", 16, 27, 180));
            _hostText = new TextBox();
            _hostText.Location = new Point(16, 49);
            _hostText.Size = new Size(275, 25);
            setup.Controls.Add(_hostText);

            setup.Controls.Add(MakeLabel("SSH user", 309, 27, 160));
            _userText = new TextBox();
            _userText.Location = new Point(309, 49);
            _userText.Size = new Size(170, 25);
            setup.Controls.Add(_userText);

            setup.Controls.Add(MakeLabel("Port", 497, 27, 70));
            _portNumber = new NumericUpDown();
            _portNumber.Location = new Point(497, 49);
            _portNumber.Size = new Size(74, 25);
            _portNumber.Minimum = 1;
            _portNumber.Maximum = 65535;
            _portNumber.Value = 22;
            setup.Controls.Add(_portNumber);

            setup.Controls.Add(MakeLabel("Duration", 589, 27, 90));
            _hoursNumber = new NumericUpDown();
            _hoursNumber.Location = new Point(589, 49);
            _hoursNumber.Size = new Size(64, 25);
            _hoursNumber.Minimum = 1;
            _hoursNumber.Maximum = 168;
            _hoursNumber.Value = 8;
            setup.Controls.Add(_hoursNumber);
            setup.Controls.Add(MakeLabel("hours", 658, 52, 60));

            _createButton = new Button();
            _createButton.Text = "Create access";
            _createButton.Location = new Point(744, 43);
            _createButton.Size = new Size(165, 36);
            _createButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _createButton.Click += CreateButtonClick;
            setup.Controls.Add(_createButton);

            _expiryCheck = new CheckBox();
            _expiryCheck.Location = new Point(500, 88);
            _expiryCheck.Size = new Size(238, 23);
            _expiryCheck.Checked = false;
            _expiryCheck.Text = "OpenSSH expiry option (optional)";
            setup.Controls.Add(_expiryCheck);

            _dedicatedAdminCheck = new CheckBox();
            _dedicatedAdminCheck.Location = new Point(16, 88);
            _dedicatedAdminCheck.Size = new Size(475, 23);
            _dedicatedAdminCheck.Checked = true;
            _dedicatedAdminCheck.Text = "Create a dedicated temporary maintenance account with sudo (recommended)";
            setup.Controls.Add(_dedicatedAdminCheck);

            _busyLabel = new Label();
            _busyLabel.Location = new Point(744, 88);
            _busyLabel.Size = new Size(165, 22);
            _busyLabel.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _busyLabel.TextAlign = ContentAlignment.MiddleCenter;
            _busyLabel.ForeColor = Color.DarkOrange;
            setup.Controls.Add(_busyLabel);

            var sessionsGroup = new GroupBox();
            sessionsGroup.Text = "Access sessions";
            sessionsGroup.Location = new Point(18, 208);
            sessionsGroup.Size = new Size(930, 285);
            sessionsGroup.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(sessionsGroup);

            _sessionsList = new ListView();
            _sessionsList.Location = new Point(14, 25);
            _sessionsList.Size = new Size(902, 186);
            _sessionsList.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            _sessionsList.View = View.Details;
            _sessionsList.FullRowSelect = true;
            _sessionsList.HideSelection = false;
            _sessionsList.MultiSelect = false;
            _sessionsList.Columns.Add("Status", 105);
            _sessionsList.Columns.Add("Alias", 150);
            _sessionsList.Columns.Add("Server", 185);
            _sessionsList.Columns.Add("User", 125);
            _sessionsList.Columns.Add("Planned until", 150);
            _sessionsList.Columns.Add("sudo", 145);
            _sessionsList.SelectedIndexChanged += delegate { UpdateSelection(); };
            sessionsGroup.Controls.Add(_sessionsList);

            _copyButton = MakeButton("Copy agent SSH command", 14, 225, 190);
            _copyButton.Click += CopyButtonClick;
            sessionsGroup.Controls.Add(_copyButton);

            _testButton = MakeButton("Test connection", 214, 225, 155);
            _testButton.Click += TestButtonClick;
            sessionsGroup.Controls.Add(_testButton);

            _removeButton = MakeButton("Remove access", 379, 225, 165);
            _removeButton.Click += RemoveButtonClick;
            sessionsGroup.Controls.Add(_removeButton);

            _folderButton = MakeButton("Open folder", 554, 225, 135);
            _folderButton.Click += FolderButtonClick;
            sessionsGroup.Controls.Add(_folderButton);

            var detailGroup = new GroupBox();
            detailGroup.Text = "Selected access";
            detailGroup.Location = new Point(18, 503);
            detailGroup.Size = new Size(930, 95);
            detailGroup.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(detailGroup);

            _detailsText = new TextBox();
            _detailsText.Location = new Point(14, 24);
            _detailsText.Size = new Size(902, 56);
            _detailsText.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            _detailsText.Multiline = true;
            _detailsText.ReadOnly = true;
            _detailsText.BackColor = SystemColors.Window;
            detailGroup.Controls.Add(_detailsText);

            var logGroup = new GroupBox();
            logGroup.Text = "Log (contains no passwords or private keys)";
            logGroup.Location = new Point(18, 608);
            logGroup.Size = new Size(930, 120);
            logGroup.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(logGroup);

            _logText = new TextBox();
            _logText.Location = new Point(14, 24);
            _logText.Size = new Size(902, 82);
            _logText.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            _logText.Multiline = true;
            _logText.ReadOnly = true;
            _logText.ScrollBars = ScrollBars.Vertical;
            _logText.BackColor = SystemColors.Window;
            logGroup.Controls.Add(_logText);
        }

        private static Label MakeLabel(string text, int x, int y, int width)
        {
            var label = new Label();
            label.Text = text;
            label.Location = new Point(x, y);
            label.Size = new Size(width, 20);
            return label;
        }

        private static Button MakeButton(string text, int x, int y, int width)
        {
            var button = new Button();
            button.Text = text;
            button.Location = new Point(x, y);
            button.Size = new Size(width, 34);
            return button;
        }

        private void LoadSessions()
        {
            _records.Clear();
            _records.AddRange(SessionStore.LoadAll());
            RefreshList(null);
        }

        private void RefreshList(SessionRecord select)
        {
            _sessionsList.BeginUpdate();
            _sessionsList.Items.Clear();
            foreach (SessionRecord record in _records.OrderByDescending(r => r.CreatedUtc))
            {
                string expires = FormatLocalDate(record.ExpiresUtcValue);
                var item = new ListViewItem(record.DisplayState);
                item.SubItems.Add(record.Alias ?? "");
                item.SubItems.Add((record.Host ?? "") + ":" + record.Port.ToString(CultureInfo.InvariantCulture));
                item.SubItems.Add(record.User ?? "");
                item.SubItems.Add(expires);
                item.SubItems.Add(SudoDisplay(record.SudoStatus));
                item.Tag = record;
                if (record.DisplayState == "Active") item.ForeColor = Color.DarkGreen;
                if (record.DisplayState == "Expired") item.ForeColor = Color.DarkOrange;
                if (record.State == "Removed") item.ForeColor = Color.Gray;
                _sessionsList.Items.Add(item);
                if (select != null && record.Id == select.Id)
                {
                    item.Selected = true;
                    item.EnsureVisible();
                }
            }
            _sessionsList.EndUpdate();
        }

        private static string SudoDisplay(string status)
        {
            if (status == "NoPassword") return "no password";
            if (status == "PasswordRequired") return "password required";
            if (status == "Unavailable") return "unavailable";
            return "not checked";
        }

        private static string FormatLocalDate(DateTime utc)
        {
            if (utc == DateTime.MinValue) return "-";
            return utc.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
        }

        private SessionRecord SelectedRecord()
        {
            if (_sessionsList.SelectedItems.Count != 1) return null;
            return _sessionsList.SelectedItems[0].Tag as SessionRecord;
        }

        private void UpdateSelection()
        {
            SessionRecord record = SelectedRecord();
            bool hasRecord = record != null;
            bool usable = hasRecord && record.State == "Active" && File.Exists(record.PrivateKeyPath);
            _copyButton.Enabled = !_busy && usable;
            _testButton.Enabled = !_busy && usable;
            _removeButton.Enabled = !_busy && hasRecord && record.State != "Removed";
            _folderButton.Enabled = !_busy && hasRecord && Directory.Exists(record.SessionDirectory);

            if (!hasRecord)
            {
                _detailsText.Text = "Select an access session from the list.";
                return;
            }

            string command = usable ? SshTools.ConnectionCommand(record) : "(no active key is available)";
            string users = record.UsesDedicatedAdminAccount
                ? "Setup login: " + (record.BootstrapUser ?? "-") + " | Temporary agent account: " + (record.User ?? "-") + " | "
                : "SSH user: " + (record.User ?? "-") + " | ";
            _detailsText.Text = users + "Fingerprint: " + (record.Fingerprint ?? "-") + Environment.NewLine +
                                "Agent SSH command: " + command;
        }

        private void SetBusy(bool busy, string text)
        {
            _busy = busy;
            _busyLabel.Text = busy ? text : "";
            _createButton.Enabled = !busy;
            UpdateSelection();
            UseWaitCursor = busy;
        }

        private void Log(string message)
        {
            if (string.IsNullOrWhiteSpace(message)) return;
            _logText.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + message.Trim() + Environment.NewLine);
        }

        private bool ValidateInputs(out string host, out string user, out int port, out int hours)
        {
            host = (_hostText.Text ?? "").Trim();
            user = (_userText.Text ?? "").Trim();
            port = Decimal.ToInt32(_portNumber.Value);
            hours = Decimal.ToInt32(_hoursNumber.Value);

            if (host.Length == 0 || host.Length > 253 || !Regex.IsMatch(host, "^[A-Za-z0-9._:-]+$") || !Regex.IsMatch(host, "[A-Za-z0-9]"))
            {
                MessageBox.Show(this, "Enter a valid IP address or server hostname.", "Check input", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
            if (user.Length == 0 || user.Length > 64 || !Regex.IsMatch(user, "^[A-Za-z0-9._-]+$"))
            {
                MessageBox.Show(this, "Enter a valid Linux username.", "Check input", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
            return true;
        }

        private async void CreateButtonClick(object sender, EventArgs e)
        {
            string host;
            string user;
            int port;
            int hours;
            if (!ValidateInputs(out host, out user, out port, out hours)) return;

            DialogResult confirmation = MessageBox.Show(this,
                "A new temporary key will be generated, then a separate SSH window will open.\n\n" +
                "1. On first contact, compare the displayed server fingerprint with a trusted fingerprint for the server.\n" +
                "2. Enter the SSH password and, if requested, the sudo password only in that separate window.\n" +
                (_dedicatedAdminCheck.Checked
                    ? "3. The tool creates a dedicated temporary account with full passwordless sudo access. These privileges apply only to that maintenance account.\n\n"
                    : "3. The key is installed for the existing user; that user's sudo configuration remains unchanged.\n\n") +
                (_expiryCheck.Checked
                    ? "The optional OpenSSH expiry setting will be tested first. If the server rejects it, the tool can retry the same access without that option.\n\n"
                    : "The server will not expire this access automatically. You must remove it with this tool after the work is complete.\n\n") +
                "Continue?",
                "Create temporary access", MessageBoxButtons.OKCancel,
                _dedicatedAdminCheck.Checked ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
            if (confirmation != DialogResult.OK) return;

            SetBusy(true, "Creating access …");
            SessionRecord record = null;
            try
            {
                record = await Task.Run(delegate
                {
                    SessionRecord newRecord = SessionStore.Create(host, user, port, hours, _expiryCheck.Checked, _dedicatedAdminCheck.Checked);
                    SshTools.GenerateKeyAndFiles(newRecord, _expiryCheck.Checked);
                    SessionStore.Save(newRecord);
                    return newRecord;
                });

                _records.Add(record);
                RefreshList(record);
                Log("Temporary key " + record.Alias + " was generated locally.");

                int installExit = await Task.Run(delegate { return SshTools.RunInteractiveInstall(record); });
                if (installExit != 0)
                {
                    Log(installExit == -1073741510
                        ? "The separate SSH window was interrupted or closed. The key will still be tested automatically."
                        : "The SSH operation returned exit code " + installExit + ". The key will still be tested for safety.");
                }

                RunResult verification = await Task.Run(delegate { return SshTools.VerifyKey(record); });
                if ((verification.ExitCode != 0 || verification.StandardOutput.IndexOf("AGENT_SSH_ACCESS_OK", StringComparison.Ordinal) < 0) &&
                    record.EnforceServerExpiry)
                {
                    DialogResult retryWithoutExpiry = MessageBox.Show(this,
                        "The server rejected the key with the optional OpenSSH expiry setting. Retry the same access without that option?\n\nThe separate password window will open again. You must then remove the access manually with this tool.",
                        "Retry without expiry option", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                    if (retryWithoutExpiry == DialogResult.Yes)
                    {
                        record.EnforceServerExpiry = false;
                        record.LastMessage = "Retrying without a server-side expiry setting.";
                        SessionStore.Save(record);
                        Log("The server rejected the optional expiry setting. Retrying without that option.");
                        installExit = await Task.Run(delegate { return SshTools.RunInteractiveInstall(record); });
                        verification = await Task.Run(delegate { return SshTools.VerifyKey(record); });
                    }
                }
                if (verification.ExitCode != 0 || verification.StandardOutput.IndexOf("AGENT_SSH_ACCESS_OK", StringComparison.Ordinal) < 0)
                {
                    record.State = "SetupFailed";
                    record.LastMessage = (installExit == -1073741510
                        ? "The SSH window was interrupted before completion. "
                        : "SSH setup failed (exit code " + installExit + "). ") +
                        "The new key could not be verified. " + SafeOneLine(verification.Combined);
                    SessionStore.Save(record);
                    RefreshList(record);
                    Log(record.LastMessage);
                    string expiryHint = record.EnforceServerExpiry
                        ? "\n\nIf the server uses an incompatible OpenSSH configuration, create a new access without the server-side expiry option."
                        : "";
                    MessageBox.Show(this,
                        "Login with the temporary key failed. Clean up this entry with 'Remove access', then create a new one. Close the SSH window only when it explicitly asks you to press ENTER." + expiryHint,
                        "Key test failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (installExit != 0)
                {
                    Log("The key was verified despite the window exit code; setup is considered successful.");
                }

                string sudoStatus = await Task.Run(delegate { return SshTools.CheckSudo(record); });
                record.SudoStatus = sudoStatus;
                record.State = "Active";
                record.LastMessage = "Access installed and verified successfully.";
                SessionStore.Save(record);
                RefreshList(record);
                Log(record.LastMessage + (record.EnforceServerExpiry
                    ? " Server-side expiry: " + FormatLocalDate(record.ExpiresUtcValue) + "."
                    : " Planned until " + FormatLocalDate(record.ExpiresUtcValue) + "; remove it manually afterwards."));

                string sudoMessage;
                MessageBoxIcon icon;
                if (sudoStatus == "NoPassword")
                {
                    sudoMessage = "sudo works without a password for this account, so the agent can perform administrative tasks.";
                    icon = MessageBoxIcon.Information;
                }
                else
                {
                    sudoMessage = "Important: sudo still requires a password. The agent can connect through SSH but cannot run unattended administrative commands. The existing sudo configuration was left unchanged.";
                    icon = MessageBoxIcon.Warning;
                }
                MessageBox.Show(this,
                    "The temporary SSH access is active. Select it and click 'Copy agent SSH command' when you are ready to use it.\n\n" + sudoMessage,
                    "Access ready", MessageBoxButtons.OK, icon);
            }
            catch (Exception ex)
            {
                Log("Setup error: " + SafeOneLine(ex.Message));
                if (record != null && record.State != "Active")
                {
                    record.State = "SetupFailed";
                    record.LastMessage = ex.Message;
                    SessionStore.Save(record);
                    RefreshList(record);
                }
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetBusy(false, "");
            }
        }

        private void CopyButtonClick(object sender, EventArgs e)
        {
            SessionRecord record = SelectedRecord();
            if (record == null || record.State != "Active") return;
            string command = SshTools.ConnectionCommand(record);
            if (!TryCopyText(command))
            {
                Log("Windows could not open the clipboard. The access remains active.");
                MessageBox.Show(this,
                    "Windows could not open the clipboard. Close any application that may be using it, then try again.",
                    "Clipboard unavailable", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            Log("Copied the agent SSH command for " + record.Alias + ".");
            MessageBox.Show(this,
                "The command was copied. Paste it into the agent task. Never paste the private key itself into chat.",
                "Command copied", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private async void TestButtonClick(object sender, EventArgs e)
        {
            SessionRecord record = SelectedRecord();
            if (record == null) return;
            SetBusy(true, "Testing connection …");
            try
            {
                RunResult result = await Task.Run(delegate { return SshTools.VerifyKey(record); });
                if (result.ExitCode == 0 && result.StandardOutput.IndexOf("AGENT_SSH_ACCESS_OK", StringComparison.Ordinal) >= 0)
                {
                    record.SudoStatus = await Task.Run(delegate { return SshTools.CheckSudo(record); });
                    record.State = "Active";
                    record.LastMessage = "Connection test successful.";
                    SessionStore.Save(record);
                    RefreshList(record);
                    Log(record.LastMessage);
                    MessageBox.Show(this, "SSH connection successful. sudo: " + SudoDisplay(record.SudoStatus), "Test successful", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    Log("Connection test failed: " + SafeOneLine(result.Combined));
                    MessageBox.Show(this, "Login with the temporary key failed. It may have expired or already been removed.", "Test failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
            catch (Exception ex)
            {
                Log("Connection test: " + SafeOneLine(ex.Message));
                MessageBox.Show(this, ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetBusy(false, "");
            }
        }

        private async void RemoveButtonClick(object sender, EventArgs e)
        {
            SessionRecord record = SelectedRecord();
            if (record == null || record.State == "Removed") return;

            DialogResult confirm = MessageBox.Show(this,
                (record.UsesDedicatedAdminAccount
                    ? "All processes owned by the temporary maintenance account will be stopped. Its key, sudo rule, home directory, and user account will then be deleted."
                    : "The marked key will be removed from the existing user's authorized_keys file.") +
                " The local private key will then be deleted and cannot be recovered.\n\nRemove access " + record.Alias + " now?",
                "Remove access", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (confirm != DialogResult.Yes) return;

            SetBusy(true, "Removing access …");
            try
            {
                bool removedByKey = false;
                if (!record.UsesDedicatedAdminAccount && File.Exists(record.PrivateKeyPath))
                {
                    RunResult removal = await Task.Run(delegate { return SshTools.RemoveUsingTemporaryKey(record); });
                    removedByKey = removal.ExitCode == 0;
                    if (!removedByKey)
                    {
                        Log("Automatic removal was not possible: " + SafeOneLine(removal.Combined));
                    }
                }

                if (!removedByKey)
                {
                    DialogResult fallback = MessageBox.Show(this,
                        record.UsesDedicatedAdminAccount
                            ? "The setup login is required to remove the temporary account completely. All processes owned by that account will be stopped, then the account, key, and sudo rule will be deleted.\n\nOpen the separate SSH window now?"
                            : "The temporary key could not perform the removal. This can happen after it has expired.\n\nOpen a separate SSH window for entering the SSH password now?",
                        "Password login required", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                    if (fallback != DialogResult.Yes)
                    {
                        record.State = "RemovalFailed";
                        record.LastMessage = "Removal cancelled; the local key was not deleted.";
                        SessionStore.Save(record);
                        RefreshList(record);
                        Log(record.LastMessage);
                        return;
                    }

                    int fallbackExit = await Task.Run(delegate { return SshTools.RunInteractiveRemoval(record); });
                    if (fallbackExit != 0)
                    {
                        record.State = "RemovalFailed";
                        record.LastMessage = "Removal through password login failed or was cancelled.";
                        SessionStore.Save(record);
                        RefreshList(record);
                        Log(record.LastMessage);
                        MessageBox.Show(this, "The server entry was not removed safely. The local key is retained so you can try again.", "Removal not confirmed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }
                }

                bool keyStillWorks = false;
                if (File.Exists(record.PrivateKeyPath))
                {
                    RunResult verify = await Task.Run(delegate { return SshTools.VerifyKey(record); });
                    keyStillWorks = verify.ExitCode == 0 && verify.StandardOutput.IndexOf("AGENT_SSH_ACCESS_OK", StringComparison.Ordinal) >= 0;
                }
                if (keyStillWorks)
                {
                    record.State = "RemovalFailed";
                    record.LastMessage = "The server still accepts the key; local data was not deleted.";
                    SessionStore.Save(record);
                    RefreshList(record);
                    Log(record.LastMessage);
                    MessageBox.Show(this, record.LastMessage, "Removal not confirmed", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                await Task.Run(delegate { SessionStore.DeleteSecretMaterial(record); });
                record.State = "Removed";
                record.LastMessage = "Server entry removed and local private key deleted.";
                SessionStore.Save(record);
                RefreshList(record);
                Log(record.LastMessage);
                MessageBox.Show(this, "The temporary access was removed. The local private key was deleted and cannot be recovered.", "Access removed", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                record.State = "RemovalFailed";
                record.LastMessage = ex.Message;
                SessionStore.Save(record);
                RefreshList(record);
                Log("Removal: " + SafeOneLine(ex.Message));
                MessageBox.Show(this, "Removal could not be completed safely. The local key was not deleted.\n\n" + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetBusy(false, "");
            }
        }

        private void FolderButtonClick(object sender, EventArgs e)
        {
            SessionRecord record = SelectedRecord();
            if (record == null || !Directory.Exists(record.SessionDirectory)) return;
            Process.Start(new ProcessStartInfo("explorer.exe", SshTools.QuoteWindowsArgument(record.SessionDirectory)) { UseShellExecute = true });
        }

        private static string SafeOneLine(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return "No further details.";
            string value = Regex.Replace(text, "\\s+", " ").Trim();
            if (value.Length > 320) value = value.Substring(0, 320) + "…";
            return value;
        }

        private static bool TryCopyText(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return false;
            try
            {
                Clipboard.SetDataObject(text, true, 10, 100);
                return true;
            }
            catch (ExternalException)
            {
                return false;
            }
            catch
            {
                return false;
            }
        }
    }

    public static class SessionStore
    {
        public static readonly string Root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AgentSshKeyManager");
        public static readonly string SessionsRoot = Path.Combine(Root, "Sessions");
        public static readonly string LegacySessionsRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "CodexSshAccessManager", "Sessions");

        public static SessionRecord Create(string host, string user, int port, int hours, bool serverExpiry, bool dedicatedAdmin)
        {
            Directory.CreateDirectory(SessionsRoot);
            string id = Guid.NewGuid().ToString("N");
            string shortId = id.Substring(0, 10);
            string directory = Path.Combine(SessionsRoot, id);
            Directory.CreateDirectory(directory);
            TrySecureDirectory(directory);

            DateTime expires = DateTime.UtcNow.AddHours(hours);
            var record = new SessionRecord();
            record.Id = id;
            record.Alias = "agent-ssh-" + shortId;
            record.Host = host;
            record.BootstrapUser = user;
            record.AccessMode = dedicatedAdmin ? "DedicatedAdmin" : "ExistingUser";
            record.User = dedicatedAdmin ? "agentssh_" + shortId : user;
            record.Port = port;
            record.CreatedUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
            record.ExpiresUtc = expires.ToString("o", CultureInfo.InvariantCulture);
            record.EnforceServerExpiry = serverExpiry;
            record.State = "Preparing";
            record.Marker = "agent-ssh-access:" + id;
            record.SudoStatus = "Unknown";
            record.SessionDirectory = directory;
            record.PrivateKeyPath = Path.Combine(directory, "id_ed25519");
            record.PublicKeyPath = record.PrivateKeyPath + ".pub";
            record.KnownHostsPath = Path.Combine(directory, "known_hosts");
            record.ConfigPath = Path.Combine(directory, "ssh_config");
            string mode = dedicatedAdmin ? "Dedicated temporary maintenance account; " : "Existing user; ";
            record.LastMessage = mode + (serverExpiry ? "with server-side expiry." : "without server-side expiry.");
            return record;
        }

        public static void Save(SessionRecord record)
        {
            if (record == null || string.IsNullOrWhiteSpace(record.SessionDirectory)) return;
            Directory.CreateDirectory(record.SessionDirectory);
            string path = Path.Combine(record.SessionDirectory, "session.xml");
            string temp = path + ".tmp";
            var serializer = new XmlSerializer(typeof(SessionRecord));
            using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                serializer.Serialize(stream, record);
            }
            if (File.Exists(path))
            {
                File.Replace(temp, path, null);
            }
            else
            {
                File.Move(temp, path);
            }
        }

        public static List<SessionRecord> LoadAll()
        {
            var result = new List<SessionRecord>();
            try
            {
                Directory.CreateDirectory(SessionsRoot);
                var serializer = new XmlSerializer(typeof(SessionRecord));
                string[] roots = new[] { SessionsRoot, LegacySessionsRoot }
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                foreach (string root in roots)
                {
                    if (!Directory.Exists(root)) continue;
                    bool legacy = string.Equals(root, LegacySessionsRoot, StringComparison.OrdinalIgnoreCase);
                    foreach (string file in Directory.GetFiles(root, "session.xml", SearchOption.AllDirectories))
                    {
                        try
                        {
                            using (var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
                            {
                                var record = serializer.Deserialize(stream) as SessionRecord;
                                // Removed records from older versions are not useful in the new list.
                                // Unfinished records remain visible so their server access can be removed safely.
                                if (record != null && !(legacy && record.State == "Removed")) result.Add(record);
                            }
                        }
                        catch
                        {
                            // One damaged metadata file must not block the remaining sessions.
                        }
                    }
                }
            }
            catch
            {
                // The GUI shows an empty list; the underlying error appears on the first write attempt.
            }
            return result;
        }

        public static void DeleteSecretMaterial(SessionRecord record)
        {
            DeleteIfPresent(record.PrivateKeyPath);
            DeleteIfPresent(record.PublicKeyPath);
            DeleteIfPresent(record.ConfigPath);
            foreach (string helper in Directory.GetFiles(record.SessionDirectory, "ssh-action-*.ps1", SearchOption.TopDirectoryOnly))
            {
                DeleteIfPresent(helper);
            }
        }

        private static void DeleteIfPresent(string path)
        {
            if (!string.IsNullOrWhiteSpace(path) && File.Exists(path)) File.Delete(path);
        }

        public static void TrySecureDirectory(string path)
        {
            try
            {
                SecurityIdentifier userSid = WindowsIdentity.GetCurrent().User;
                SecurityIdentifier systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                var security = new DirectorySecurity();
                security.SetOwner(userSid);
                security.SetAccessRuleProtection(true, false);
                var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
                security.AddAccessRule(new FileSystemAccessRule(userSid, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
                security.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
                Directory.SetAccessControl(path, security);
            }
            catch
            {
                // Best effort. The private-key file is protected separately as well.
            }
        }

        public static void TrySecurePrivateFile(string path)
        {
            try
            {
                SecurityIdentifier userSid = WindowsIdentity.GetCurrent().User;
                SecurityIdentifier systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                var security = new FileSecurity();
                security.SetOwner(userSid);
                security.SetAccessRuleProtection(true, false);
                security.AddAccessRule(new FileSystemAccessRule(userSid, FileSystemRights.FullControl, AccessControlType.Allow));
                security.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, AccessControlType.Allow));
                File.SetAccessControl(path, security);
            }
            catch
            {
                // OpenSSH also validates the file when establishing a connection.
            }
        }
    }

    public static class SshTools
    {
        private static readonly string SshPath = FindTool("ssh.exe");
        private static readonly string SshKeygenPath = FindTool("ssh-keygen.exe");
        private static readonly string PowerShellPath = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");

        public static void GenerateKeyAndFiles(SessionRecord record, bool serverExpiry)
        {
            if (string.IsNullOrWhiteSpace(SshPath) || string.IsNullOrWhiteSpace(SshKeygenPath))
            {
                throw new InvalidOperationException("Windows OpenSSH was not found. Install the optional Windows component 'OpenSSH Client'.");
            }

            var keyArgs = new List<string>();
            keyArgs.Add("-q");
            keyArgs.Add("-t");
            keyArgs.Add("ed25519");
            keyArgs.Add("-N");
            keyArgs.Add("");
            keyArgs.Add("-C");
            keyArgs.Add(record.Marker);
            keyArgs.Add("-f");
            keyArgs.Add(record.PrivateKeyPath);
            RunResult generated = RunHidden(SshKeygenPath, keyArgs, 30000);
            if (generated.ExitCode != 0 || !File.Exists(record.PrivateKeyPath) || !File.Exists(record.PublicKeyPath))
            {
                throw new InvalidOperationException("The temporary SSH key could not be generated. " + generated.Combined);
            }
            SessionStore.TrySecurePrivateFile(record.PrivateKeyPath);

            var fingerprintArgs = new List<string>();
            fingerprintArgs.Add("-lf");
            fingerprintArgs.Add(record.PublicKeyPath);
            RunResult fingerprint = RunHidden(SshKeygenPath, fingerprintArgs, 10000);
            if (fingerprint.ExitCode != 0) throw new InvalidOperationException("The key fingerprint could not be determined.");
            record.Fingerprint = fingerprint.StandardOutput.Trim();

            File.WriteAllText(record.ConfigPath, BuildConfig(record), new UTF8Encoding(false));
            string validityText = serverExpiry
                ? "The server-side access expires on " + record.ExpiresUtcValue.ToLocalTime().ToString("yyyy-MM-dd 'at' HH:mm") + ".\r\n"
                : "Planned end: " + record.ExpiresUtcValue.ToLocalTime().ToString("yyyy-MM-dd 'at' HH:mm") + ". Remove the access with this tool afterwards.\r\n";
            File.WriteAllText(Path.Combine(record.SessionDirectory, "AGENT-SSH-COMMAND.txt"),
                "Agent SSH command:\r\n\r\n" + ConnectionCommand(record) + "\r\n\r\n" +
                "Never paste the contents of the private key file into chat.\r\n" +
                validityText,
                new UTF8Encoding(true));
        }

        public static int RunInteractiveInstall(SessionRecord record)
        {
            string publicKey = File.ReadAllText(record.PublicKeyPath).Trim();
            if (!publicKey.StartsWith("ssh-ed25519 ", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("The generated public-key format is unexpected.");
            }
            bool useExpiry = record.EnforceServerExpiry ||
                (record.LastMessage ?? "").IndexOf("with server-side expiry", StringComparison.OrdinalIgnoreCase) >= 0 ||
                (record.LastMessage ?? "").IndexOf("mit serverseitigem", StringComparison.OrdinalIgnoreCase) >= 0;
            string options = "no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc";
            string authorizedLine = options + " " + publicKey;
            long expiryUnixSeconds = UnixSeconds(record.ExpiresUtcValue);
            string remote = record.UsesDedicatedAdminAccount
                ? BuildDedicatedSetupCommand(record, authorizedLine, useExpiry, expiryUnixSeconds)
                : BuildInstallCommand(record.Marker, authorizedLine, useExpiry, expiryUnixSeconds);

            var args = BaseInteractiveArguments(record);
            args.Add((record.UsesDedicatedAdminAccount ? record.BootstrapUser : record.User) + "@" + record.Host);
            args.Add(EncodeRemoteCommand(remote));
            return RunVisiblePowerShell(record, "install", args,
                "INSTALL TEMPORARY SSH ACCESS",
                record.UsesDedicatedAdminAccount
                    ? "Verify the server fingerprint first. Then enter the SSH and sudo passwords. They are not stored."
                    : "Verify the server fingerprint first. Then enter the SSH password. It is not stored.");
        }

        public static int RunInteractiveRemoval(SessionRecord record)
        {
            string remote = record.UsesDedicatedAdminAccount
                ? BuildDedicatedCleanupCommand(record)
                : BuildRemovalCommand(record.Marker, record.Id);
            var args = BaseInteractiveArguments(record);
            args.Add((record.UsesDedicatedAdminAccount ? record.BootstrapUser : record.User) + "@" + record.Host);
            args.Add(EncodeRemoteCommand(remote));
            return RunVisiblePowerShell(record, "remove", args,
                "REMOVE TEMPORARY SSH ACCESS",
                record.UsesDedicatedAdminAccount
                    ? "Enter the SSH and sudo passwords. The temporary account, its processes, key, and sudo rule will be removed."
                    : "Enter the SSH password. It is processed only by ssh.exe and is not stored.");
        }

        public static RunResult RemoveUsingTemporaryKey(SessionRecord record)
        {
            var args = BaseKeyArguments(record, 12);
            args.Add(record.User + "@" + record.Host);
            args.Add(BuildRemovalCommand(record.Marker, record.Id));
            return RunHidden(SshPath, args, 30000);
        }

        public static RunResult VerifyKey(SessionRecord record)
        {
            var args = BaseKeyArguments(record, 10);
            args.Add(record.User + "@" + record.Host);
            args.Add("printf 'AGENT_SSH_ACCESS_OK'");
            return RunHidden(SshPath, args, 25000);
        }

        public static string CheckSudo(SessionRecord record)
        {
            var args = BaseKeyArguments(record, 10);
            args.Add(record.User + "@" + record.Host);
            args.Add("if command -v sudo >/dev/null 2>&1; then if sudo -n true >/dev/null 2>&1; then printf 'AGENT_SUDO_NOPASSWD'; else printf 'AGENT_SUDO_PASSWORD_REQUIRED'; fi; else printf 'AGENT_SUDO_UNAVAILABLE'; fi");
            RunResult result = RunHidden(SshPath, args, 25000);
            if (result.StandardOutput.IndexOf("AGENT_SUDO_NOPASSWD", StringComparison.Ordinal) >= 0) return "NoPassword";
            if (result.StandardOutput.IndexOf("AGENT_SUDO_PASSWORD_REQUIRED", StringComparison.Ordinal) >= 0) return "PasswordRequired";
            return "Unavailable";
        }

        private static List<string> BaseInteractiveArguments(SessionRecord record)
        {
            var args = new List<string>();
            args.Add("-tt");
            args.Add("-p");
            args.Add(record.Port.ToString(CultureInfo.InvariantCulture));
            args.Add("-o");
            args.Add("StrictHostKeyChecking=ask");
            args.Add("-o");
            args.Add("UserKnownHostsFile=" + record.KnownHostsPath);
            args.Add("-o");
            args.Add("ConnectTimeout=20");
            args.Add("-o");
            args.Add("ConnectionAttempts=1");
            return args;
        }

        private static List<string> BaseKeyArguments(SessionRecord record, int timeoutSeconds)
        {
            var args = new List<string>();
            args.Add("-i");
            args.Add(record.PrivateKeyPath);
            args.Add("-p");
            args.Add(record.Port.ToString(CultureInfo.InvariantCulture));
            args.Add("-o");
            args.Add("BatchMode=yes");
            args.Add("-o");
            args.Add("PasswordAuthentication=no");
            args.Add("-o");
            args.Add("KbdInteractiveAuthentication=no");
            args.Add("-o");
            args.Add("PreferredAuthentications=publickey");
            args.Add("-o");
            args.Add("IdentitiesOnly=yes");
            args.Add("-o");
            args.Add("StrictHostKeyChecking=yes");
            args.Add("-o");
            args.Add("UserKnownHostsFile=" + record.KnownHostsPath);
            args.Add("-o");
            args.Add("ConnectTimeout=" + timeoutSeconds.ToString(CultureInfo.InvariantCulture));
            args.Add("-o");
            args.Add("ConnectionAttempts=1");
            return args;
        }

        public static string BuildInstallCommand(string marker, string authorizedLine)
        {
            return BuildInstallCommand(marker, authorizedLine, false, 0);
        }

        public static string BuildInstallCommand(string marker, string authorizedLine, bool useExpiry, long expiryUnixSeconds)
        {
            return "set -eu; " + BuildAuthorizedLineAssignment(authorizedLine, useExpiry, expiryUnixSeconds) +
                   "d=\"$HOME/.ssh\"; f=\"$d/authorized_keys\"; umask 077; " +
                   "mkdir -p \"$d\"; chmod 700 \"$d\"; touch \"$f\"; chmod 600 \"$f\"; " +
                   "if ! grep -Fq -- " + ShellQuote(marker) + " \"$f\"; then printf '%s\\n' \"$authorized_line\" >> \"$f\"; fi";
        }

        public static string BuildDedicatedSetupCommand(SessionRecord record, string authorizedLine)
        {
            return BuildDedicatedSetupCommand(record, authorizedLine, false, 0);
        }

        public static string BuildDedicatedSetupCommand(SessionRecord record, string authorizedLine, bool useExpiry, long expiryUnixSeconds)
        {
            string sudoers = SudoersPath(record);
            string sudoRule = record.User + " ALL=(ALL:ALL) NOPASSWD: ALL";
            return "set -eu; " + BuildAuthorizedLineAssignment(authorizedLine, useExpiry, expiryUnixSeconds) +
                   "u=" + ShellQuote(record.User) + "; rule=" + ShellQuote(sudoers) + "; " +
                   "sudo -v; " +
                   "if ! id -u \"$u\" >/dev/null 2>&1; then sudo /usr/sbin/useradd --create-home --user-group --shell /bin/bash \"$u\"; fi; " +
                   "p=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \\n'); [ -n \"$p\" ]; " +
                   "printf '%s:%s\\n' \"$u\" \"$p\" | sudo /usr/sbin/chpasswd; unset p; " +
                   "h=$(getent passwd \"$u\" | cut -d: -f6); [ -n \"$h\" ]; " +
                   "sudo install -d -m 700 -o \"$u\" -g \"$u\" \"$h/.ssh\"; " +
                   "tmp=$(sudo mktemp /etc/sudoers.d/.agent-ssh-XXXXXXXXXX); " +
                   "trap 'sudo rm -f \"$tmp\"' EXIT HUP INT TERM; " +
                   "printf '%s\\n' " + ShellQuote("# " + record.Marker) + " " + ShellQuote(sudoRule) + " | sudo tee \"$tmp\" >/dev/null; " +
                   "sudo chmod 440 \"$tmp\"; sudo /usr/sbin/visudo -cf \"$tmp\" >/dev/null; sudo mv \"$tmp\" \"$rule\"; trap - EXIT HUP INT TERM; " +
                   "printf '%s\\n' \"$authorized_line\" | sudo tee \"$h/.ssh/authorized_keys\" >/dev/null; " +
                   "sudo chown \"$u:$u\" \"$h/.ssh/authorized_keys\"; sudo chmod 600 \"$h/.ssh/authorized_keys\"";
        }

        private static string BuildAuthorizedLineAssignment(string authorizedLine, bool useExpiry, long expiryUnixSeconds)
        {
            if (!useExpiry)
            {
                return "authorized_line=" + ShellQuote(authorizedLine) + "; ";
            }
            if (expiryUnixSeconds <= 0)
            {
                throw new InvalidOperationException("The temporary key expiry date is invalid.");
            }

            // OpenSSH 9.6 on Ubuntu interprets expiry-time without a timezone suffix in
            // the server's local timezone. Convert the absolute UTC instant on the
            // Ubuntu host so client and server timezone differences cannot shift it.
            return "expiry_local=$(date -d @" + expiryUnixSeconds.ToString(CultureInfo.InvariantCulture) + " +%Y%m%d%H%M%S); " +
                   "authorized_line=$(printf 'expiry-time=\"%s\",%s' \"$expiry_local\" " + ShellQuote(authorizedLine) + "); ";
        }

        private static long UnixSeconds(DateTime value)
        {
            if (value == DateTime.MinValue) return 0;
            DateTime utc = value.Kind == DateTimeKind.Utc ? value : value.ToUniversalTime();
            DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            return (long)Math.Floor((utc - epoch).TotalSeconds);
        }

        public static string BuildDedicatedCleanupCommand(SessionRecord record)
        {
            string sudoers = SudoersPath(record);
            return "set -eu; u=" + ShellQuote(record.User) + "; rule=" + ShellQuote(sudoers) + "; sudo -v; " +
                   "h=$(getent passwd \"$u\" | cut -d: -f6 || true); " +
                   "if [ -n \"$h\" ]; then sudo rm -f \"$h/.ssh/authorized_keys\"; fi; " +
                   "sudo rm -f \"$rule\"; " +
                   "if id -u \"$u\" >/dev/null 2>&1; then " +
                   "sudo pkill -TERM -u \"$u\" >/dev/null 2>&1 || true; sleep 1; " +
                   "sudo pkill -KILL -u \"$u\" >/dev/null 2>&1 || true; " +
                   "sudo /usr/sbin/userdel --remove \"$u\"; fi";
        }

        public static string BuildRemovalCommand(string marker, string id)
        {
            string suffix = Regex.Replace(id ?? "session", "[^A-Za-z0-9]", "");
            if (suffix.Length > 16) suffix = suffix.Substring(0, 16);
            return "set -eu; f=\"$HOME/.ssh/authorized_keys\"; " +
                   "if [ -f \"$f\" ]; then t=\"${f}.agent-ssh-" + suffix + ".tmp\"; " +
                   "trap 'rm -f \"$t\"' EXIT HUP INT TERM; " +
                   "awk -v m=" + ShellQuote(marker) + " 'index($0,m)==0 { print }' \"$f\" > \"$t\"; " +
                   "chmod 600 \"$t\"; mv \"$t\" \"$f\"; trap - EXIT HUP INT TERM; fi";
        }

        private static string SudoersPath(SessionRecord record)
        {
            bool legacy = (record.Marker ?? "").StartsWith("codex-access:", StringComparison.Ordinal);
            string prefix = legacy ? "codex-access-" : "agent-ssh-";
            return "/etc/sudoers.d/" + prefix + record.Id.Substring(0, 16);
        }

        public static string ConnectionCommand(SessionRecord record)
        {
            return "ssh.exe -F " + QuoteWindowsArgument(record.ConfigPath) + " " + record.Alias;
        }

        public static string BuildConfig(SessionRecord record)
        {
            string keyPath = record.PrivateKeyPath.Replace('\\', '/');
            string knownHosts = record.KnownHostsPath.Replace('\\', '/');
            var text = new StringBuilder();
            text.AppendLine("Host " + record.Alias);
            text.AppendLine("    HostName " + record.Host);
            text.AppendLine("    User " + record.User);
            text.AppendLine("    Port " + record.Port.ToString(CultureInfo.InvariantCulture));
            text.AppendLine("    IdentityFile \"" + keyPath.Replace("\"", "\\\"") + "\"");
            text.AppendLine("    IdentitiesOnly yes");
            text.AppendLine("    BatchMode yes");
            text.AppendLine("    PasswordAuthentication no");
            text.AppendLine("    KbdInteractiveAuthentication no");
            text.AppendLine("    StrictHostKeyChecking yes");
            text.AppendLine("    UserKnownHostsFile \"" + knownHosts.Replace("\"", "\\\"") + "\"");
            text.AppendLine("    ForwardAgent no");
            text.AppendLine("    ForwardX11 no");
            text.AppendLine("    PermitLocalCommand no");
            text.AppendLine("    ConnectTimeout 15");
            return text.ToString();
        }

        public static string ShellQuote(string value)
        {
            return "'" + (value ?? "").Replace("'", "'\"'\"'") + "'";
        }

        public static string EncodeRemoteCommand(string command)
        {
            if (string.IsNullOrWhiteSpace(command))
            {
                throw new ArgumentException("The remote command must not be empty.", "command");
            }
            string payload = Convert.ToBase64String(new UTF8Encoding(false).GetBytes(command));
            return "printf %s " + payload + " | /usr/bin/base64 --decode | /bin/sh";
        }

        public static string QuoteWindowsArgument(string value)
        {
            if (value == null) return "\"\"";
            if (value.Length > 0 && !Regex.IsMatch(value, "[\\s\"]")) return value;
            var result = new StringBuilder();
            result.Append('"');
            int backslashes = 0;
            foreach (char c in value)
            {
                if (c == '\\')
                {
                    backslashes++;
                }
                else if (c == '"')
                {
                    result.Append('\\', backslashes * 2 + 1);
                    result.Append('"');
                    backslashes = 0;
                }
                else
                {
                    result.Append('\\', backslashes);
                    backslashes = 0;
                    result.Append(c);
                }
            }
            result.Append('\\', backslashes * 2);
            result.Append('"');
            return result.ToString();
        }

        private static string BuildArgumentString(IEnumerable<string> arguments)
        {
            return string.Join(" ", arguments.Select(QuoteWindowsArgument).ToArray());
        }

        private static RunResult RunHidden(string fileName, IEnumerable<string> arguments, int timeoutMilliseconds)
        {
            var info = new ProcessStartInfo();
            info.FileName = fileName;
            info.Arguments = BuildArgumentString(arguments);
            info.UseShellExecute = false;
            info.CreateNoWindow = true;
            info.RedirectStandardOutput = true;
            info.RedirectStandardError = true;
            info.StandardOutputEncoding = Encoding.UTF8;
            info.StandardErrorEncoding = Encoding.UTF8;
            using (var process = new Process())
            {
                process.StartInfo = info;
                process.Start();
                string stdout = process.StandardOutput.ReadToEnd();
                string stderr = process.StandardError.ReadToEnd();
                bool exited = process.WaitForExit(timeoutMilliseconds);
                if (!exited)
                {
                    try { process.Kill(); } catch { }
                    return new RunResult { ExitCode = -1, StandardOutput = stdout, StandardError = stderr, TimedOut = true };
                }
                return new RunResult { ExitCode = process.ExitCode, StandardOutput = stdout, StandardError = stderr, TimedOut = false };
            }
        }

        private static int RunVisiblePowerShell(SessionRecord record, string action, List<string> sshArguments, string title, string explanation)
        {
            string scriptPath = Path.Combine(record.SessionDirectory, "ssh-action-" + action + ".ps1");
            string resultPath = Path.Combine(record.SessionDirectory, "ssh-action-" + action + ".result");
            try { if (File.Exists(resultPath)) File.Delete(resultPath); } catch { }
            var script = new StringBuilder();
            script.AppendLine("$Host.UI.RawUI.WindowTitle = " + PsQuote("Agent SSH Key Manager"));
            script.AppendLine("Write-Host ''");
            script.AppendLine("Write-Host " + PsQuote(title) + " -ForegroundColor Cyan");
            script.AppendLine("Write-Host " + PsQuote(explanation));
            script.AppendLine("Write-Host ''");
            script.AppendLine("$sshArgs = @(");
            for (int i = 0; i < sshArguments.Count; i++)
            {
                string comma = i + 1 < sshArguments.Count ? "," : "";
                script.AppendLine("    " + PsQuote(sshArguments[i]) + comma);
            }
            script.AppendLine(")");
            script.AppendLine("& " + PsQuote(SshPath) + " @sshArgs");
            script.AppendLine("$sshExit = $LASTEXITCODE");
            script.AppendLine("Set-Content -LiteralPath " + PsQuote(resultPath) + " -Value ([string]$sshExit) -Encoding ASCII");
            script.AppendLine("Write-Host ''");
            script.AppendLine("if ($sshExit -eq 0) { Write-Host 'SSH operation successful.' -ForegroundColor Green } else { Write-Host ('SSH operation failed (code ' + $sshExit + ').') -ForegroundColor Red }");
            script.AppendLine("[void](Read-Host 'Press ENTER to close')");
            script.AppendLine("exit $sshExit");
            File.WriteAllText(scriptPath, script.ToString(), new UTF8Encoding(true));

            var info = new ProcessStartInfo();
            info.FileName = PowerShellPath;
            info.Arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -File " + QuoteWindowsArgument(scriptPath);
            info.UseShellExecute = true;
            info.WindowStyle = ProcessWindowStyle.Normal;
            using (var process = Process.Start(info))
            {
                process.WaitForExit();
                int code = process.ExitCode;
                try
                {
                    int recordedCode;
                    if (File.Exists(resultPath) && int.TryParse(File.ReadAllText(resultPath).Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out recordedCode))
                    {
                        code = recordedCode;
                    }
                }
                catch { }
                try { File.Delete(scriptPath); } catch { }
                try { File.Delete(resultPath); } catch { }
                return code;
            }
        }

        private static string PsQuote(string value)
        {
            return "'" + (value ?? "").Replace("'", "''") + "'";
        }

        private static string FindTool(string name)
        {
            string systemOpenSsh = Path.Combine(Environment.SystemDirectory, "OpenSSH", name);
            if (File.Exists(systemOpenSsh)) return systemOpenSsh;
            string path = Environment.GetEnvironmentVariable("PATH") ?? "";
            foreach (string item in path.Split(Path.PathSeparator))
            {
                try
                {
                    string candidate = Path.Combine(item.Trim(), name);
                    if (File.Exists(candidate)) return candidate;
                }
                catch { }
            }
            return null;
        }
    }

    public static class SelfTest
    {
        public static int Run(string outputPath)
        {
            var report = new StringBuilder();
            string testRoot = Path.Combine(Path.GetTempPath(), "AgentSshKeyManager-Test-" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(testRoot);
                var record = new SessionRecord();
                record.Id = Guid.NewGuid().ToString("N");
                record.Alias = "agent-ssh-test";
                record.Host = "192.0.2.10";
                record.BootstrapUser = "ubuntu";
                record.AccessMode = "DedicatedAdmin";
                record.User = "agentssh_test123456";
                record.Port = 22;
                record.Marker = "agent-ssh-access:" + record.Id;
                record.CreatedUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
                record.ExpiresUtc = DateTime.UtcNow.AddHours(2).ToString("o", CultureInfo.InvariantCulture);
                record.EnforceServerExpiry = true;
                record.SessionDirectory = testRoot;
                record.PrivateKeyPath = Path.Combine(testRoot, "id_ed25519");
                record.PublicKeyPath = record.PrivateKeyPath + ".pub";
                record.KnownHostsPath = Path.Combine(testRoot, "known_hosts");
                record.ConfigPath = Path.Combine(testRoot, "ssh_config");
                record.LastMessage = "Preparing with server-side expiry.";

                SshTools.GenerateKeyAndFiles(record, true);
                Assert(File.Exists(record.PrivateKeyPath), "private key missing");
                Assert(File.Exists(record.PublicKeyPath), "public key missing");
                Assert((record.Fingerprint ?? "").IndexOf("SHA256:", StringComparison.Ordinal) >= 0, "fingerprint missing");
                string config = File.ReadAllText(record.ConfigPath);
                Assert(config.IndexOf("BatchMode yes", StringComparison.Ordinal) >= 0, "BatchMode missing");
                Assert(config.IndexOf("PasswordAuthentication no", StringComparison.Ordinal) >= 0, "password auth not disabled");
                string install = SshTools.BuildInstallCommand(record.Marker, "ssh-ed25519 AAAATEST " + record.Marker);
                string expiryInstall = SshTools.BuildInstallCommand(record.Marker, "ssh-ed25519 AAAATEST " + record.Marker, true, 4102444799L);
                string removal = SshTools.BuildRemovalCommand(record.Marker, record.Id);
                string dedicatedSetup = SshTools.BuildDedicatedSetupCommand(record, "ssh-ed25519 AAAATEST " + record.Marker);
                string dedicatedCleanup = SshTools.BuildDedicatedCleanupCommand(record);
                string encodedSetup = SshTools.EncodeRemoteCommand(dedicatedSetup);
                Assert(install.IndexOf(record.Marker, StringComparison.Ordinal) >= 0, "install marker missing");
                Assert(expiryInstall.IndexOf("date -d @4102444799", StringComparison.Ordinal) >= 0, "server-local expiry conversion missing");
                Assert(expiryInstall.IndexOf("expiry-time=", StringComparison.Ordinal) >= 0, "expiry key option missing");
                Assert(removal.IndexOf(record.Marker, StringComparison.Ordinal) >= 0, "removal marker missing");
                Assert(dedicatedSetup.IndexOf("useradd", StringComparison.Ordinal) >= 0, "dedicated user creation missing");
                Assert(dedicatedSetup.IndexOf("chpasswd", StringComparison.Ordinal) >= 0, "random account password setup missing");
                Assert(dedicatedSetup.IndexOf("visudo", StringComparison.Ordinal) >= 0, "sudoers validation missing");
                Assert(dedicatedSetup.IndexOf("visudo", StringComparison.Ordinal) < dedicatedSetup.IndexOf("authorized_keys", StringComparison.Ordinal), "public key exposed before sudoers validation");
                Assert(dedicatedCleanup.IndexOf("userdel", StringComparison.Ordinal) >= 0, "dedicated cleanup missing");
                Assert(encodedSetup.StartsWith("printf %s ", StringComparison.Ordinal), "encoded remote command prefix missing");
                Assert(encodedSetup.IndexOf("/usr/bin/base64 --decode | /bin/sh", StringComparison.Ordinal) >= 0, "encoded remote command decoder missing");
                Assert(encodedSetup.IndexOf(record.Marker, StringComparison.Ordinal) < 0, "remote command was not encoded");
                Assert(SshTools.ConnectionCommand(record).IndexOf(record.ConfigPath, StringComparison.Ordinal) >= 0, "agent command missing config");
                report.AppendLine("SELF-TEST OK");
                report.AppendLine("Fingerprint: " + record.Fingerprint);
                report.AppendLine("Config safeguards: OK");
                report.AppendLine("Install/remove marker logic: OK");
                report.AppendLine("Optional expiry command generation: OK");
                report.AppendLine("PowerShell-safe remote command transport: OK");
                report.AppendLine("Dedicated maintenance account lifecycle: OK");
                File.WriteAllText(outputPath, report.ToString(), new UTF8Encoding(true));
                return 0;
            }
            catch (Exception ex)
            {
                report.AppendLine("SELF-TEST FAILED");
                report.AppendLine(ex.ToString());
                try { File.WriteAllText(outputPath, report.ToString(), new UTF8Encoding(true)); } catch { }
                return 1;
            }
            finally
            {
                try
                {
                    string fullTemp = Path.GetFullPath(Path.GetTempPath());
                    string fullTest = Path.GetFullPath(testRoot);
                    if (fullTest.StartsWith(fullTemp, StringComparison.OrdinalIgnoreCase) && Directory.Exists(fullTest))
                    {
                        Directory.Delete(fullTest, true);
                    }
                }
                catch { }
            }
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition) throw new InvalidOperationException(message);
        }
    }
}
