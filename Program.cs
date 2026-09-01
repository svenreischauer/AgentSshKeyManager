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
using System.Security.Cryptography;
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
            if (args != null && args.Length == 1 && args[0] == "--self-test-child-exit-probe")
            {
                return 37;
            }

            if (args != null && args.Length == 2 &&
                (args[0] == "--interactive-install" || args[0] == "--interactive-remove"))
            {
                string action = args[0] == "--interactive-install" ? "install" : "remove";
                return InteractiveConsoleHost.Run(action, args[1]);
            }

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

    internal static class InteractiveConsoleLauncher
    {
        public static int Run(SessionRecord record, string action)
        {
            ProcessStartInfo info = CreateStartInfo(record, action);
            return WaitForExit(info);
        }

        internal static ProcessStartInfo CreateStartInfo(SessionRecord record, string action)
        {
            if (record == null || !Regex.IsMatch(record.Id ?? "", "^[a-fA-F0-9]{32}$"))
            {
                throw new InvalidOperationException("The access session identifier is invalid.");
            }
            if (action != "install" && action != "remove")
            {
                throw new InvalidOperationException("The interactive SSH action is invalid.");
            }

            var info = new ProcessStartInfo();
            info.FileName = Application.ExecutablePath;
            info.Arguments = (action == "install" ? "--interactive-install " : "--interactive-remove ") + record.Id;
            info.UseShellExecute = false;
            info.CreateNoWindow = true;
            return info;
        }

        internal static int WaitForExit(ProcessStartInfo info)
        {
            using (var process = Process.Start(info))
            {
                process.WaitForExit();
                return process.ExitCode;
            }
        }
    }

    internal static class InteractiveConsoleHost
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AllocConsole();

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool SetConsoleTitle(string title);

        public static int Run(string action, string sessionId)
        {
            bool consoleReady = AllocConsole();
            if (consoleReady)
            {
                Console.SetOut(new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true });
                Console.SetError(new StreamWriter(Console.OpenStandardError(), new UTF8Encoding(false)) { AutoFlush = true });
                Console.SetIn(new StreamReader(Console.OpenStandardInput(), Encoding.UTF8));
                SetConsoleTitle("Agent SSH Key Manager");
            }

            SessionRecord record = null;
            string auditPath = null;
            bool auditWarning = false;
            try
            {
                if ((action != "install" && action != "remove") || !Regex.IsMatch(sessionId ?? "", "^[a-fA-F0-9]{32}$"))
                {
                    throw new InvalidOperationException("The interactive SSH request is invalid.");
                }

                record = SessionStore.LoadById(sessionId);
                if (record == null)
                {
                    throw new InvalidOperationException("The requested access session was not found.");
                }
                if (!SessionStore.IsActionAllowed(record, action))
                {
                    throw new InvalidOperationException("The requested SSH action is not valid for this session state.");
                }
                auditPath = InteractiveAudit.PathFor(record);

                List<string> sshArguments = SshTools.BuildInteractiveArguments(record, action);
                string remotePayload = sshArguments[sshArguments.Count - 1];
                string startupDetails = InteractiveAudit.BuildStartupDetails(remotePayload);
                auditWarning = !InteractiveAudit.TryAppend(record, action, "console_started", null, startupDetails);

                WriteHeader(record, action);
                var info = SshTools.CreateInteractiveSshStartInfo(sshArguments);
                using (var process = Process.Start(info))
                {
                    if (!InteractiveAudit.TryAppend(record, action, "ssh_started", process.Id, null)) auditWarning = true;
                    process.WaitForExit();
                    int exitCode = process.ExitCode;
                    if (!InteractiveAudit.TryAppend(record, action, "ssh_exited", process.Id,
                        "exit_code=" + exitCode.ToString(CultureInfo.InvariantCulture))) auditWarning = true;

                    Console.WriteLine();
                    if (exitCode == 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("SSH operation completed successfully.");
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("SSH operation failed with exit code " + exitCode.ToString(CultureInfo.InvariantCulture) + ".");
                        Console.WriteLine("Review the SSH output above for the detailed error.");
                    }
                    Console.ResetColor();
                    WriteAuditStatus(auditPath, auditWarning);
                    Pause();
                    return exitCode;
                }
            }
            catch (Exception ex)
            {
                if (record != null)
                {
                    if (!InteractiveAudit.TryAppend(record, action, "host_error", null,
                        ex.GetType().Name + ": " + InteractiveAudit.SafeField(ex.Message))) auditWarning = true;
                }
                if (consoleReady)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine();
                    Console.WriteLine("The SSH operation could not be started.");
                    Console.WriteLine(ex.Message);
                    Console.ResetColor();
                    WriteAuditStatus(auditPath, auditWarning);
                    Pause();
                }
                return 1;
            }
        }

        private static void WriteHeader(SessionRecord record, string action)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine();
            Console.WriteLine(action == "install" ? "INSTALL TEMPORARY SSH ACCESS" : "REMOVE TEMPORARY SSH ACCESS");
            Console.ResetColor();
            Console.WriteLine("Server: " + record.Host + ":" + record.Port.ToString(CultureInfo.InvariantCulture));
            Console.WriteLine(action == "install"
                ? "Verify the server fingerprint, then enter SSH and sudo passwords when requested. Passwords are handled only by ssh.exe and the remote sudo command."
                : "Enter SSH and sudo passwords when requested. The temporary access will be removed from the server.");
            Console.WriteLine();
        }

        private static void Pause()
        {
            Console.WriteLine();
            Console.Write("Press ENTER to close this window ... ");
            Console.ReadLine();
        }

        private static void WriteAuditStatus(string auditPath, bool warning)
        {
            if (warning)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Warning: the local audit log could not be updated.");
                Console.ResetColor();
            }
            else if (!string.IsNullOrWhiteSpace(auditPath))
            {
                Console.WriteLine("Audit log: " + auditPath);
            }
        }
    }

    internal static class InteractiveAudit
    {
        public static string PathFor(SessionRecord record)
        {
            return System.IO.Path.Combine(record.SessionDirectory, "interactive-actions.log");
        }

        public static bool TryAppend(SessionRecord record, string action, string stage, int? childPid, string details)
        {
            try
            {
                string path = PathFor(record);
                string line = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture) +
                    " action=" + SafeField(action) +
                    " session=" + SafeField(record.Id) +
                    " stage=" + SafeField(stage) +
                    (childPid.HasValue ? " child_pid=" + childPid.Value.ToString(CultureInfo.InvariantCulture) : "") +
                    (string.IsNullOrWhiteSpace(details) ? "" : " " + SafeField(details)) + Environment.NewLine;
                File.AppendAllText(path, line, new UTF8Encoding(false));
                SessionStore.TrySecurePrivateFile(path);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static string BuildStartupDetails(string remotePayload)
        {
            var fields = new List<string>();
            try { fields.Add("app_sha256=" + HashFile(Application.ExecutablePath)); }
            catch { fields.Add("app_sha256=unavailable"); }
            fields.Add("ssh_path=" + SafeField(SshTools.SshExecutablePath));
            try { fields.Add("ssh_version=" + SafeField(SshTools.GetSshVersion())); }
            catch { fields.Add("ssh_version=unavailable"); }
            fields.Add("payload_sha256=" + HashText(remotePayload));
            fields.Add("payload_length=" + (remotePayload ?? "").Length.ToString(CultureInfo.InvariantCulture));
            return string.Join("; ", fields.ToArray());
        }

        public static string SafeField(string value)
        {
            string safe = Regex.Replace(value ?? "", "[\r\n\t]+", " ").Trim();
            return safe.Length <= 512 ? safe : safe.Substring(0, 512);
        }

        public static string HashText(string value)
        {
            return HashBytes(new UTF8Encoding(false).GetBytes(value ?? ""));
        }

        public static string HashFile(string path)
        {
            using (var stream = File.OpenRead(path))
            using (var algorithm = SHA256.Create())
            {
                return ToHex(algorithm.ComputeHash(stream));
            }
        }

        private static string HashBytes(byte[] value)
        {
            using (var algorithm = SHA256.Create())
            {
                return ToHex(algorithm.ComputeHash(value));
            }
        }

        private static string ToHex(byte[] value)
        {
            return string.Concat(value.Select(b => b.ToString("x2", CultureInfo.InvariantCulture)).ToArray());
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
            if (user.Length == 0 || user.Length > 64 || !Regex.IsMatch(user, "^[A-Za-z0-9_][A-Za-z0-9._-]*$"))
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
                "   The window remains open after SSH finishes; press ENTER after reviewing the result.\n" +
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
                        "The new key could not be verified. " + SafeOneLine(verification.Combined) +
                        " Audit log, if available: " + InteractiveAudit.PathFor(record);
                    SessionStore.Save(record);
                    RefreshList(record);
                    Log(record.LastMessage);
                    string expiryHint = record.EnforceServerExpiry
                        ? "\n\nIf the server uses an incompatible OpenSSH configuration, create a new access without the server-side expiry option."
                        : "";
                    MessageBox.Show(this,
                        "Login with the temporary key failed. Clean up this entry with 'Remove access', then create a new one. " +
                        "The separate SSH window showed the detailed setup output before it closed.\n\n" +
                        "Audit log, if available (timestamps and exit codes):\n" + InteractiveAudit.PathFor(record) + expiryHint,
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
                        record.LastMessage = "Removal through password login failed or was cancelled. Audit log, if available: " + InteractiveAudit.PathFor(record);
                        SessionStore.Save(record);
                        RefreshList(record);
                        Log(record.LastMessage);
                        MessageBox.Show(this, "The server entry was not removed safely. The local key is retained so you can try again. " +
                            "The separate SSH window showed the detailed error before it closed.\n\n" +
                            "Audit log, if available (timestamps and exit codes):\n" + InteractiveAudit.PathFor(record),
                            "Removal not confirmed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
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
                string[] roots = new[] { SessionsRoot, LegacySessionsRoot }
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                foreach (string root in roots)
                {
                    if (!Directory.Exists(root)) continue;
                    bool legacy = string.Equals(root, LegacySessionsRoot, StringComparison.OrdinalIgnoreCase);
                    foreach (string file in Directory.GetFiles(root, "session.xml", SearchOption.AllDirectories))
                    {
                        SessionRecord record = LoadStoredRecord(file);
                        // Removed records from older versions are not useful in the new list.
                        // Unfinished records remain visible so their server access can be removed safely.
                        if (record != null && !(legacy && record.State == "Removed")) result.Add(record);
                    }
                }
            }
            catch
            {
                // The GUI shows an empty list; the underlying error appears on the first write attempt.
            }
            return result;
        }

        public static SessionRecord LoadById(string id)
        {
            if (!Regex.IsMatch(id ?? "", "^[a-fA-F0-9]{32}$")) return null;
            return LoadAll().FirstOrDefault(record =>
                record != null && string.Equals(record.Id, id, StringComparison.OrdinalIgnoreCase));
        }

        internal static SessionRecord LoadStoredRecord(string file)
        {
            try
            {
                var serializer = new XmlSerializer(typeof(SessionRecord));
                using (var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    var record = serializer.Deserialize(stream) as SessionRecord;
                    NormalizeLoadedRecord(record, Path.GetDirectoryName(file));
                    return IsValidStoredRecord(record) ? record : null;
                }
            }
            catch
            {
                // One damaged or untrusted metadata file must not block other sessions.
                return null;
            }
        }

        private static void NormalizeLoadedRecord(SessionRecord record, string directory)
        {
            if (record == null || string.IsNullOrWhiteSpace(directory)) return;
            record.SessionDirectory = Path.GetFullPath(directory);
            record.PrivateKeyPath = Path.Combine(record.SessionDirectory, "id_ed25519");
            record.PublicKeyPath = record.PrivateKeyPath + ".pub";
            record.KnownHostsPath = Path.Combine(record.SessionDirectory, "known_hosts");
            record.ConfigPath = Path.Combine(record.SessionDirectory, "ssh_config");
            if (string.IsNullOrWhiteSpace(record.BootstrapUser) && !record.UsesDedicatedAdminAccount)
            {
                record.BootstrapUser = record.User;
            }
        }

        private static bool IsValidStoredRecord(SessionRecord record)
        {
            if (record == null || !Regex.IsMatch(record.Id ?? "", "^[a-f0-9]{32}$")) return false;
            if (string.IsNullOrWhiteSpace(record.Host) || record.Host.Length > 253 ||
                !Regex.IsMatch(record.Host, "^[A-Za-z0-9._:-]+$") || !Regex.IsMatch(record.Host, "[A-Za-z0-9]")) return false;
            if (!IsSafeLogin(record.User) || !IsSafeLogin(record.BootstrapUser)) return false;
            if (record.Port < 1 || record.Port > 65535) return false;
            if (string.IsNullOrWhiteSpace(record.SessionDirectory) ||
                !string.Equals(Path.GetFileName(record.SessionDirectory), record.Id, StringComparison.Ordinal)) return false;

            string marker = record.Marker ?? "";
            bool currentMarker = marker == "agent-ssh-access:" + record.Id;
            bool legacyMarker = marker == "codex-access:" + record.Id;
            if (!currentMarker && !legacyMarker) return false;

            string shortId = record.Id.Substring(0, 10);
            string currentAlias = "agent-ssh-" + shortId;
            string legacyAlias = "codex-ssh-" + shortId;
            if (record.Alias != currentAlias && !(legacyMarker && record.Alias == legacyAlias)) return false;

            if (record.AccessMode == "DedicatedAdmin")
            {
                if (record.User != "agentssh_" + shortId) return false;
            }
            else if (record.AccessMode == "ExistingUser")
            {
                if (!string.Equals(record.User, record.BootstrapUser, StringComparison.Ordinal)) return false;
            }
            else
            {
                return false;
            }

            if (record.State != "Preparing" && record.State != "SetupFailed" && record.State != "Active" &&
                record.State != "RemovalFailed" && record.State != "Removed") return false;
            return true;
        }

        internal static bool IsActionAllowed(SessionRecord record, string action)
        {
            if (record == null) return false;
            if (action == "install") return record.State == "Preparing";
            if (action == "remove")
            {
                return record.State == "Preparing" || record.State == "SetupFailed" ||
                    record.State == "Active" || record.State == "RemovalFailed";
            }
            return false;
        }

        private static bool IsSafeLogin(string value)
        {
            return !string.IsNullOrWhiteSpace(value) && value.Length <= 64 &&
                Regex.IsMatch(value, "^[A-Za-z0-9_][A-Za-z0-9._-]*$");
        }

        public static void DeleteSecretMaterial(SessionRecord record)
        {
            DeleteIfPresent(record.PrivateKeyPath);
            DeleteIfPresent(record.PublicKeyPath);
            DeleteIfPresent(record.ConfigPath);
            if (!string.IsNullOrWhiteSpace(record.SessionDirectory) && Directory.Exists(record.SessionDirectory))
            {
                foreach (string pattern in new[] { "ssh-action-*." + "ps1", "ssh-action-*." + "result" })
                {
                    foreach (string helper in Directory.GetFiles(record.SessionDirectory, pattern, SearchOption.TopDirectoryOnly))
                    {
                        DeleteIfPresent(helper);
                    }
                }
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
        private static readonly string SshPath = FindWindowsOpenSshTool("ssh.exe");
        private static readonly string SshKeygenPath = FindWindowsOpenSshTool("ssh-keygen.exe");

        internal static string SshExecutablePath
        {
            get { return SshPath; }
        }

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
            return InteractiveConsoleLauncher.Run(record, "install");
        }

        public static int RunInteractiveRemoval(SessionRecord record)
        {
            return InteractiveConsoleLauncher.Run(record, "remove");
        }

        internal static List<string> BuildInteractiveArguments(SessionRecord record, string action)
        {
            if (record == null) throw new ArgumentNullException("record");
            if (action != "install" && action != "remove")
            {
                throw new ArgumentException("The interactive SSH action is invalid.", "action");
            }

            string remote;
            string loginUser;
            if (action == "install")
            {
                string publicKey = ReadValidatedPublicKey(record);
                bool useExpiry = record.EnforceServerExpiry ||
                    (record.LastMessage ?? "").IndexOf("with server-side expiry", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    (record.LastMessage ?? "").IndexOf("mit serverseitigem", StringComparison.OrdinalIgnoreCase) >= 0;
                string options = "no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc";
                string authorizedLine = options + " " + publicKey;
                long expiryUnixSeconds = UnixSeconds(record.ExpiresUtcValue);
                remote = record.UsesDedicatedAdminAccount
                    ? BuildDedicatedSetupCommand(record, authorizedLine, useExpiry, expiryUnixSeconds)
                    : BuildInstallCommand(record.Marker, authorizedLine, useExpiry, expiryUnixSeconds);
                loginUser = record.UsesDedicatedAdminAccount ? record.BootstrapUser : record.User;
            }
            else
            {
                remote = record.UsesDedicatedAdminAccount
                    ? BuildDedicatedCleanupCommand(record)
                    : BuildRemovalCommand(record.Marker, record.Id);
                loginUser = record.UsesDedicatedAdminAccount ? record.BootstrapUser : record.User;
            }

            var args = BaseInteractiveArguments(record);
            args.Add(loginUser + "@" + record.Host);
            // ProcessStartInfo launches ssh.exe directly, so this is passed as one
            // argv value without a local shell or an encoded decoder pipeline.
            args.Add(remote);
            return args;
        }

        private static string ReadValidatedPublicKey(SessionRecord record)
        {
            if (new FileInfo(record.PublicKeyPath).Length > 1024)
            {
                throw new InvalidOperationException("The public-key file is unexpectedly large.");
            }
            string contents = File.ReadAllText(record.PublicKeyPath);
            string pattern = "\\Assh-ed25519 (?<key>[A-Za-z0-9+/]+={0,2}) " +
                Regex.Escape(record.Marker) + "(?:\\r?\\n)?\\z";
            Match match = Regex.Match(contents, pattern, RegexOptions.CultureInvariant);
            if (!match.Success)
            {
                throw new InvalidOperationException("The public-key file must contain exactly the generated Ed25519 key and session marker.");
            }

            string keyWithoutComment = "ssh-ed25519 " + match.Groups["key"].Value;
            RunResult derived = RunHidden(SshKeygenPath,
                new[] { "-y", "-P", "", "-f", record.PrivateKeyPath }, 10000);
            string derivedKey = derived.StandardOutput.Trim();
            if (derived.ExitCode != 0 ||
                (!string.Equals(derivedKey, keyWithoutComment, StringComparison.Ordinal) &&
                 !string.Equals(derivedKey, keyWithoutComment + " " + record.Marker, StringComparison.Ordinal)))
            {
                throw new InvalidOperationException("The public key does not match the session private key.");
            }
            return keyWithoutComment + " " + record.Marker;
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
            string owner = OwnershipPath(record);
            string sudoRule = record.User + " ALL=(ALL:ALL) NOPASSWD: ALL";
            string markerLine = "# " + record.Marker;
            string ownerValue = record.Marker + " user=" + record.User;
            return "set -eu; " + BuildAuthorizedLineAssignment(authorizedLine, useExpiry, expiryUnixSeconds) +
                   "u=" + ShellQuote(record.User) + "; rule=" + ShellQuote(sudoers) + "; owner=" + ShellQuote(owner) + "; " +
                   "owner_value=" + ShellQuote(ownerValue) + "; sudo -v; " +
                   "sudo install -d -m 700 -o root -g root /var/lib/agent-ssh-key-manager; " +
                   "if id -u \"$u\" >/dev/null 2>&1; then " +
                   "if sudo test -f \"$owner\"; then sudo grep -Fqx -- \"$owner_value\" \"$owner\"; " +
                   "else sudo test -f \"$rule\"; sudo grep -Fqx -- " + ShellQuote(markerLine) + " \"$rule\"; " +
                   "sudo grep -Fqx -- " + ShellQuote(sudoRule) + " \"$rule\"; " +
                   "printf '%s\\n' \"$owner_value\" | sudo tee \"$owner\" >/dev/null; fi; " +
                   "else if sudo test -e \"$owner\"; then sudo grep -Fqx -- \"$owner_value\" \"$owner\"; " +
                   "else printf '%s\\n' \"$owner_value\" | sudo tee \"$owner\" >/dev/null; fi; " +
                   "sudo /usr/sbin/useradd --create-home --user-group --shell /bin/bash \"$u\"; fi; " +
                   "sudo chmod 600 \"$owner\"; " +
                   "p=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \\n'); [ -n \"$p\" ]; " +
                   "printf '%s:%s\\n' \"$u\" \"$p\" | sudo /usr/sbin/chpasswd; unset p; " +
                   "h=$(getent passwd \"$u\" | cut -d: -f6); [ -n \"$h\" ]; " +
                   "sudo install -d -m 700 -o \"$u\" -g \"$u\" \"$h/.ssh\"; " +
                   "tmp=$(sudo mktemp /etc/sudoers.d/.agent-ssh-XXXXXXXXXX); " +
                   "trap 'sudo rm -f \"$tmp\"' EXIT HUP INT TERM; " +
                   "printf '%s\\n' " + ShellQuote(markerLine) + " " + ShellQuote(sudoRule) + " | sudo tee \"$tmp\" >/dev/null; " +
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
            string owner = OwnershipPath(record);
            string sudoRule = record.User + " ALL=(ALL:ALL) NOPASSWD: ALL";
            string markerLine = "# " + record.Marker;
            string ownerValue = record.Marker + " user=" + record.User;
            return "set -eu; u=" + ShellQuote(record.User) + "; rule=" + ShellQuote(sudoers) + "; owner=" + ShellQuote(owner) + "; " +
                   "owner_value=" + ShellQuote(ownerValue) + "; sudo -v; " +
                   "if sudo test -f \"$owner\"; then sudo grep -Fqx -- \"$owner_value\" \"$owner\"; " +
                   "elif sudo test -f \"$rule\"; then sudo grep -Fqx -- " + ShellQuote(markerLine) + " \"$rule\"; " +
                   "sudo grep -Fqx -- " + ShellQuote(sudoRule) + " \"$rule\"; " +
                   "elif id -u \"$u\" >/dev/null 2>&1; then printf '%s\\n' 'Refusing to remove an unowned account.' >&2; exit 1; fi; " +
                   "if sudo test -e \"$rule\"; then sudo grep -Fqx -- " + ShellQuote(markerLine) + " \"$rule\"; " +
                   "sudo grep -Fqx -- " + ShellQuote(sudoRule) + " \"$rule\"; fi; " +
                   "if id -u \"$u\" >/dev/null 2>&1; then " +
                   "h=$(getent passwd \"$u\" | cut -d: -f6); [ -n \"$h\" ]; sudo rm -f \"$h/.ssh/authorized_keys\"; " +
                   "sudo pkill -TERM -u \"$u\" >/dev/null 2>&1 || true; sleep 1; " +
                   "sudo pkill -KILL -u \"$u\" >/dev/null 2>&1 || true; " +
                   "sudo /usr/sbin/userdel --remove \"$u\"; fi; " +
                   "sudo rm -f \"$rule\" \"$owner\"";
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

        private static string OwnershipPath(SessionRecord record)
        {
            return "/var/lib/agent-ssh-key-manager/" + record.Id + ".owner";
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

        internal static string BuildArgumentString(IEnumerable<string> arguments)
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
            info.RedirectStandardInput = true;
            info.RedirectStandardOutput = true;
            info.RedirectStandardError = true;
            info.StandardOutputEncoding = Encoding.UTF8;
            info.StandardErrorEncoding = Encoding.UTF8;
            using (var process = new Process())
            {
                process.StartInfo = info;
                process.Start();
                process.StandardInput.Close();
                Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
                Task<string> stderrTask = process.StandardError.ReadToEndAsync();
                bool exited = process.WaitForExit(timeoutMilliseconds);
                if (!exited)
                {
                    try { process.Kill(); } catch { }
                    try { process.WaitForExit(5000); } catch { }
                }
                bool outputCompleted = false;
                try { outputCompleted = Task.WaitAll(new Task[] { stdoutTask, stderrTask }, 5000); }
                catch { }
                string stdout = stdoutTask.Status == TaskStatus.RanToCompletion ? stdoutTask.Result : "";
                string stderr = stderrTask.Status == TaskStatus.RanToCompletion ? stderrTask.Result : "";
                if (!exited || !outputCompleted)
                {
                    return new RunResult { ExitCode = -1, StandardOutput = stdout, StandardError = stderr, TimedOut = true };
                }
                return new RunResult { ExitCode = process.ExitCode, StandardOutput = stdout, StandardError = stderr, TimedOut = false };
            }
        }

        internal static ProcessStartInfo CreateInteractiveSshStartInfo(IEnumerable<string> sshArguments)
        {
            var info = new ProcessStartInfo();
            info.FileName = SshPath;
            info.Arguments = BuildArgumentString(sshArguments);
            info.UseShellExecute = false;
            info.CreateNoWindow = false;
            info.WindowStyle = ProcessWindowStyle.Normal;
            return info;
        }

        internal static int ProbeInteractiveSshLauncher()
        {
            return ProbeInteractiveSshLauncher(new[] { "-V" });
        }

        internal static int ProbeInteractiveSshLauncherFailure()
        {
            return ProbeInteractiveSshLauncher(new[] { "-o", "AgentSshKeyManagerInvalidOption=yes", "-V" });
        }

        private static int ProbeInteractiveSshLauncher(IEnumerable<string> arguments)
        {
            var info = CreateInteractiveSshStartInfo(arguments);
            using (var process = Process.Start(info))
            {
                process.WaitForExit();
                return process.ExitCode;
            }
        }

        internal static string GetSshVersion()
        {
            if (string.IsNullOrWhiteSpace(SshPath)) return "unavailable";
            RunResult result = RunHidden(SshPath, new[] { "-V" }, 10000);
            return string.IsNullOrWhiteSpace(result.Combined) ? "unknown" : result.Combined;
        }

        private static string FindWindowsOpenSshTool(string name)
        {
            string systemOpenSsh = Path.Combine(Environment.SystemDirectory, "OpenSSH", name);
            if (File.Exists(systemOpenSsh)) return systemOpenSsh;
            return null;
        }
    }

    public static class SelfTest
    {
        [DllImport("shell32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CommandLineToArgvW(string commandLine, out int argumentCount);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        public static int Run(string outputPath)
        {
            var report = new StringBuilder();
            string testRoot = Path.Combine(Path.GetTempPath(), "AgentSshKeyManager-Test-" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(testRoot);
                var record = new SessionRecord();
                record.Id = Guid.NewGuid().ToString("N");
                string shortId = record.Id.Substring(0, 10);
                record.Alias = "agent-ssh-" + shortId;
                record.Host = "192.0.2.10";
                record.BootstrapUser = "ubuntu";
                record.AccessMode = "DedicatedAdmin";
                record.User = "agentssh_" + shortId;
                record.Port = 22;
                record.Marker = "agent-ssh-access:" + record.Id;
                record.CreatedUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
                record.ExpiresUtc = DateTime.UtcNow.AddHours(2).ToString("o", CultureInfo.InvariantCulture);
                record.EnforceServerExpiry = true;
                record.State = "Preparing";
                record.SessionDirectory = Path.Combine(testRoot, record.Id);
                Directory.CreateDirectory(record.SessionDirectory);
                record.PrivateKeyPath = Path.Combine(record.SessionDirectory, "id_ed25519");
                record.PublicKeyPath = record.PrivateKeyPath + ".pub";
                record.KnownHostsPath = Path.Combine(record.SessionDirectory, "known_hosts");
                record.ConfigPath = Path.Combine(record.SessionDirectory, "ssh_config");
                record.LastMessage = "Preparing with server-side expiry.";

                SshTools.GenerateKeyAndFiles(record, true);
                Assert(File.Exists(record.PrivateKeyPath), "private key missing");
                Assert(File.Exists(record.PublicKeyPath), "public key missing");
                Assert((record.Fingerprint ?? "").IndexOf("SHA256:", StringComparison.Ordinal) >= 0, "fingerprint missing");
                string config = File.ReadAllText(record.ConfigPath);
                Assert(config.IndexOf("BatchMode yes", StringComparison.Ordinal) >= 0, "BatchMode missing");
                Assert(config.IndexOf("PasswordAuthentication no", StringComparison.Ordinal) >= 0, "password auth not disabled");

                string actualPrivatePath = record.PrivateKeyPath;
                string actualPublicPath = record.PublicKeyPath;
                string actualKnownHostsPath = record.KnownHostsPath;
                string actualConfigPath = record.ConfigPath;
                record.PrivateKeyPath = "C:\\untrusted-private-path";
                record.PublicKeyPath = "C:\\untrusted-public-path";
                record.KnownHostsPath = "C:\\untrusted-known-hosts";
                record.ConfigPath = "C:\\untrusted-config";
                SessionStore.Save(record);
                record.PrivateKeyPath = actualPrivatePath;
                record.PublicKeyPath = actualPublicPath;
                record.KnownHostsPath = actualKnownHostsPath;
                record.ConfigPath = actualConfigPath;
                SessionRecord reloaded = SessionStore.LoadStoredRecord(Path.Combine(record.SessionDirectory, "session.xml"));
                Assert(reloaded != null && reloaded.Id == record.Id, "stored session reload failed");
                Assert(reloaded.PrivateKeyPath == actualPrivatePath && reloaded.ConfigPath == actualConfigPath, "stored paths were not normalized");
                Assert(SessionStore.IsActionAllowed(reloaded, "install"), "preparing session cannot install");
                reloaded.State = "Removed";
                Assert(!SessionStore.IsActionAllowed(reloaded, "install") && !SessionStore.IsActionAllowed(reloaded, "remove"), "removed session action was accepted");
                string actualUser = record.User;
                record.User = "root";
                SessionStore.Save(record);
                Assert(SessionStore.LoadStoredRecord(Path.Combine(record.SessionDirectory, "session.xml")) == null, "unbound dedicated account was accepted");
                record.User = actualUser;
                SessionStore.Save(record);

                string install = SshTools.BuildInstallCommand(record.Marker, "ssh-ed25519 AAAATEST " + record.Marker);
                string expiryInstall = SshTools.BuildInstallCommand(record.Marker, "ssh-ed25519 AAAATEST " + record.Marker, true, 4102444799L);
                string removal = SshTools.BuildRemovalCommand(record.Marker, record.Id);
                string dedicatedSetup = SshTools.BuildDedicatedSetupCommand(record, "ssh-ed25519 AAAATEST " + record.Marker);
                string dedicatedCleanup = SshTools.BuildDedicatedCleanupCommand(record);
                List<string> interactiveInstall = SshTools.BuildInteractiveArguments(record, "install");
                string directSetup = interactiveInstall[interactiveInstall.Count - 1];
                Assert(install.IndexOf(record.Marker, StringComparison.Ordinal) >= 0, "install marker missing");
                Assert(expiryInstall.IndexOf("date -d @4102444799", StringComparison.Ordinal) >= 0, "server-local expiry conversion missing");
                Assert(expiryInstall.IndexOf("expiry-time=", StringComparison.Ordinal) >= 0, "expiry key option missing");
                Assert(removal.IndexOf(record.Marker, StringComparison.Ordinal) >= 0, "removal marker missing");
                Assert(dedicatedSetup.IndexOf("useradd", StringComparison.Ordinal) >= 0, "dedicated user creation missing");
                Assert(dedicatedSetup.IndexOf("chpasswd", StringComparison.Ordinal) >= 0, "random account password setup missing");
                Assert(dedicatedSetup.IndexOf("visudo", StringComparison.Ordinal) >= 0, "sudoers validation missing");
                Assert(dedicatedSetup.IndexOf("grep -Fqx", StringComparison.Ordinal) >= 0, "existing dedicated account ownership proof missing");
                Assert(dedicatedSetup.IndexOf("/var/lib/agent-ssh-key-manager/", StringComparison.Ordinal) >= 0, "durable dedicated account ownership marker missing");
                Assert(dedicatedSetup.IndexOf("visudo", StringComparison.Ordinal) < dedicatedSetup.IndexOf("authorized_keys", StringComparison.Ordinal), "public key exposed before sudoers validation");
                Assert(dedicatedCleanup.IndexOf("userdel", StringComparison.Ordinal) >= 0, "dedicated cleanup missing");
                Assert(dedicatedCleanup.IndexOf("grep -Fqx", StringComparison.Ordinal) >= 0, "dedicated cleanup ownership proof missing");
                Assert(dedicatedCleanup.IndexOf("/var/lib/agent-ssh-key-manager/", StringComparison.Ordinal) >= 0, "dedicated cleanup ownership marker missing");
                Assert(directSetup.StartsWith("set -eu; ", StringComparison.Ordinal), "direct remote command prefix missing");
                Assert(directSetup.IndexOf(record.Marker, StringComparison.Ordinal) >= 0, "direct remote command marker missing");
                var startInfo = SshTools.CreateInteractiveSshStartInfo(interactiveInstall);
                Assert(string.Equals(startInfo.FileName, Path.Combine(Environment.SystemDirectory, "OpenSSH", "ssh.exe"), StringComparison.OrdinalIgnoreCase), "interactive launcher is not the system OpenSSH client");
                Assert(!startInfo.UseShellExecute, "interactive launcher uses the Windows shell");
                Assert(!startInfo.CreateNoWindow, "interactive launcher suppresses the inherited console");
                var managerChild = InteractiveConsoleLauncher.CreateStartInfo(record, "install");
                Assert(string.Equals(managerChild.FileName, Application.ExecutablePath, StringComparison.OrdinalIgnoreCase), "interactive console host is not the same executable");
                Assert(!managerChild.UseShellExecute, "interactive console host uses the Windows shell");
                Assert(managerChild.CreateNoWindow, "interactive console host creates an unwanted inherited window");
                Assert(string.Equals(managerChild.Arguments, "--interactive-install " + record.Id, StringComparison.Ordinal), "interactive console host arguments changed");
                AssertArgumentRoundTrip(interactiveInstall);
                AssertArgumentRoundTrip(new[] { "plain", "space value", "Unicode-ä", "a&b|c", "quote\"value", "C:\\path with space\\" });
                Assert(SshTools.ProbeInteractiveSshLauncher() == 0, "interactive ssh launcher probe failed");
                Assert(SshTools.ProbeInteractiveSshLauncherFailure() != 0, "interactive ssh failure probe unexpectedly succeeded");
                var childProbe = new ProcessStartInfo();
                childProbe.FileName = Application.ExecutablePath;
                childProbe.Arguments = "--self-test-child-exit-probe";
                childProbe.UseShellExecute = false;
                childProbe.CreateNoWindow = true;
                Assert(InteractiveConsoleLauncher.WaitForExit(childProbe) == 37, "same-executable child exit code was not preserved");
                Assert(SshTools.ConnectionCommand(record).IndexOf(record.ConfigPath, StringComparison.Ordinal) >= 0, "agent command missing config");

                string publicKeyContents = File.ReadAllText(record.PublicKeyPath);
                File.WriteAllText(record.PublicKeyPath, publicKeyContents + "ssh-ed25519 AAAA attacker\n", new UTF8Encoding(false));
                bool multilineKeyRejected = false;
                try { SshTools.BuildInteractiveArguments(record, "install"); }
                catch (InvalidOperationException) { multilineKeyRejected = true; }
                Assert(multilineKeyRejected, "multiline public-key file was accepted");
                File.WriteAllText(record.PublicKeyPath, publicKeyContents, new UTF8Encoding(false));

                Match keyMatch = Regex.Match(publicKeyContents, "\\Assh-ed25519 (?<key>[A-Za-z0-9+/]+={0,2}) ");
                Assert(keyMatch.Success, "generated public-key test format missing");
                string keyData = keyMatch.Groups["key"].Value;
                char replacement = keyData[0] == 'A' ? 'B' : 'A';
                string mismatchedKey = "ssh-ed25519 " + replacement + keyData.Substring(1) + " " + record.Marker + Environment.NewLine;
                File.WriteAllText(record.PublicKeyPath, mismatchedKey, new UTF8Encoding(false));
                bool mismatchedKeyRejected = false;
                try { SshTools.BuildInteractiveArguments(record, "install"); }
                catch (InvalidOperationException) { mismatchedKeyRejected = true; }
                Assert(mismatchedKeyRejected, "public key that did not match the private key was accepted");
                File.WriteAllText(record.PublicKeyPath, publicKeyContents, new UTF8Encoding(false));

                string encryptedPrivateKey = Path.Combine(record.SessionDirectory, "id_ed25519_encrypted_test");
                var encryptedKeyInfo = new ProcessStartInfo();
                encryptedKeyInfo.FileName = Path.Combine(Environment.SystemDirectory, "OpenSSH", "ssh-keygen.exe");
                encryptedKeyInfo.Arguments = SshTools.BuildArgumentString(new[] {
                    "-q", "-t", "ed25519", "-N", "self-test-passphrase", "-C", record.Marker, "-f", encryptedPrivateKey
                });
                encryptedKeyInfo.UseShellExecute = false;
                encryptedKeyInfo.CreateNoWindow = true;
                Assert(InteractiveConsoleLauncher.WaitForExit(encryptedKeyInfo) == 0, "encrypted self-test key generation failed");
                string originalPrivateKeyPath = record.PrivateKeyPath;
                string originalPublicKeyPath = record.PublicKeyPath;
                record.PrivateKeyPath = encryptedPrivateKey;
                record.PublicKeyPath = encryptedPrivateKey + ".pub";
                bool encryptedKeyRejected = false;
                var encryptedKeyTimer = Stopwatch.StartNew();
                try { SshTools.BuildInteractiveArguments(record, "install"); }
                catch (InvalidOperationException) { encryptedKeyRejected = true; }
                encryptedKeyTimer.Stop();
                record.PrivateKeyPath = originalPrivateKeyPath;
                record.PublicKeyPath = originalPublicKeyPath;
                Assert(encryptedKeyRejected, "passphrase-protected replacement key was accepted");
                Assert(encryptedKeyTimer.ElapsedMilliseconds < 5000, "passphrase-protected replacement key prompted or timed out");

                string auditHash = InteractiveAudit.HashText("PRIVATE_PAYLOAD_TEST");
                string auditDetails = InteractiveAudit.BuildStartupDetails("PRIVATE_PAYLOAD_TEST");
                Assert(auditDetails.IndexOf(auditHash, StringComparison.Ordinal) >= 0, "startup audit payload hash missing");
                Assert(auditDetails.IndexOf("PRIVATE_PAYLOAD_TEST", StringComparison.Ordinal) < 0, "startup audit details leaked the raw payload");
                Assert(InteractiveAudit.TryAppend(record, "install", "self_test", 123, auditDetails), "audit append failed");
                string audit = File.ReadAllText(InteractiveAudit.PathFor(record));
                Assert(audit.IndexOf(auditHash, StringComparison.Ordinal) >= 0, "audit payload hash missing");
                Assert(audit.IndexOf("PRIVATE_PAYLOAD_TEST", StringComparison.Ordinal) < 0, "audit leaked the raw payload");
                File.Delete(InteractiveAudit.PathFor(record));
                Directory.CreateDirectory(InteractiveAudit.PathFor(record));
                Assert(!InteractiveAudit.TryAppend(record, "install", "expected_failure", null, null), "audit write failure was not contained");
                Directory.Delete(InteractiveAudit.PathFor(record));

                string legacyScript = Path.Combine(record.SessionDirectory, "ssh-action-install." + "ps1");
                string legacyResult = Path.Combine(record.SessionDirectory, "ssh-action-install." + "result");
                File.WriteAllText(legacyScript, "legacy");
                File.WriteAllText(legacyResult, "1");
                SessionStore.DeleteSecretMaterial(record);
                Assert(!File.Exists(legacyScript) && !File.Exists(legacyResult), "legacy helper cleanup failed");
                report.AppendLine("SELF-TEST OK");
                report.AppendLine("Fingerprint: " + record.Fingerprint);
                report.AppendLine("Config safeguards: OK");
                report.AppendLine("Install/remove marker logic: OK");
                report.AppendLine("Optional expiry command generation: OK");
                report.AppendLine("Direct remote command transport: OK");
                report.AppendLine("Windows argument round-trip: OK");
                report.AppendLine("Constrained manager/OpenSSH launch and exit propagation: OK");
                report.AppendLine("Stored-session and public-key validation: OK");
                report.AppendLine("Audit privacy/failure containment and legacy cleanup: OK");
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

        private static void AssertArgumentRoundTrip(IEnumerable<string> arguments)
        {
            string[] expected = arguments.ToArray();
            string commandLine = "ssh.exe" + (expected.Length == 0 ? "" : " " + SshTools.BuildArgumentString(expected));
            int count;
            IntPtr argv = CommandLineToArgvW(commandLine, out count);
            if (argv == IntPtr.Zero) throw new InvalidOperationException("CommandLineToArgvW failed.");
            try
            {
                Assert(count == expected.Length + 1, "Windows argument count changed during quoting");
                for (int i = 0; i < expected.Length; i++)
                {
                    string actual = Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, (i + 1) * IntPtr.Size));
                    Assert(string.Equals(actual, expected[i], StringComparison.Ordinal), "Windows argument changed during quoting at index " + i.ToString(CultureInfo.InvariantCulture));
                }
            }
            finally
            {
                LocalFree(argv);
            }
        }
    }
}
