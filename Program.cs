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
        public string BootstrapMethod { get; set; }
        public string AccessMode { get; set; }
        public string User { get; set; }
        public int Port { get; set; }
        public string CreatedUtc { get; set; }
        public string ExpiresUtc { get; set; }
        public bool EnforceServerExpiry { get; set; }
        public string State { get; set; }
        public string Fingerprint { get; set; }
        public string ServerHostKeyFingerprint { get; set; }
        public string ServerHostKeyAlgorithm { get; set; }
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

    internal enum TemporaryAccessOutcome
    {
        Accepted,
        Rejected,
        Indeterminate
    }

    internal sealed class TemporaryAccessCheck
    {
        public TemporaryAccessOutcome Outcome { get; set; }
        public RunResult Result { get; set; }
    }

    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            EmbeddedDependencyLoader.Initialize();

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
                try
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
                catch (Exception ex)
                {
                    Console.Error.WriteLine("UI render failed: " + ex.Message);
                    return 4;
                }
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
                ? "The server fingerprint was confirmed in the main window. Enter SSH and sudo passwords when requested. Passwords are handled only by ssh.exe and the remote sudo command."
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

    public partial class MainForm : Form
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
        private ToolTip _fieldToolTips;
        private readonly List<SessionRecord> _records = new List<SessionRecord>();
        private bool _busy;

        public MainForm()
        {
            Text = "Agent SSH Key Manager";
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(920, 820);
            Size = new Size(1000, 900);
            Font = new Font("Segoe UI", 9F, FontStyle.Regular, GraphicsUnit.Point);
            Icon = SystemIcons.Shield;

            _fieldToolTips = new ToolTip();
            _fieldToolTips.AutoPopDelay = 15000;
            _fieldToolTips.InitialDelay = 450;
            _fieldToolTips.ReshowDelay = 100;
            _fieldToolTips.ShowAlways = true;
            _fieldToolTips.IsBalloon = true;
            _fieldToolTips.ToolTipTitle = "Field help";
            Disposed += delegate { _fieldToolTips.Dispose(); };

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
            intro.Text = "This tool creates, installs, verifies, and later removes a temporary SSH key for an agent. Bootstrap with a password, an existing SSH key, or a manual console command.";
            intro.ForeColor = Color.FromArgb(30, 65, 110);
            intro.Font = new Font(Font, FontStyle.Bold);
            Controls.Add(intro);

            var setup = new GroupBox();
            setup.Text = "Create a temporary access";
            setup.Location = new Point(18, 72);
            setup.Size = new Size(950, 226);
            setup.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(setup);

            Label hostLabel = MakeLabel("Server (IP or hostname)", 16, 27, 180);
            setup.Controls.Add(hostLabel);
            _hostText = new TextBox();
            _hostText.Location = new Point(16, 49);
            _hostText.Size = new Size(275, 25);
            setup.Controls.Add(_hostText);
            SetFieldHelp("Enter the server's IP address or name. Example: 192.168.1.20",
                hostLabel, _hostText);

            Label userLabel = MakeLabel("Bootstrap user", 309, 27, 160);
            setup.Controls.Add(userLabel);
            _userText = new TextBox();
            _userText.Location = new Point(309, 49);
            _userText.Size = new Size(170, 25);
            setup.Controls.Add(_userText);
            SetFieldHelp("Enter an existing Linux user that can sign in. Sudo is needed to create a temporary administrator.",
                userLabel, _userText);

            Label portLabel = MakeLabel("Port", 497, 27, 70);
            setup.Controls.Add(portLabel);
            _portNumber = new NumericUpDown();
            _portNumber.Location = new Point(497, 49);
            _portNumber.Size = new Size(74, 25);
            _portNumber.Minimum = 1;
            _portNumber.Maximum = 65535;
            _portNumber.Value = 22;
            setup.Controls.Add(_portNumber);
            SetFieldHelp("Enter the SSH port. It is usually 22.",
                portLabel, _portNumber);

            Label durationLabel = MakeLabel("Duration", 589, 27, 90);
            setup.Controls.Add(durationLabel);
            _hoursNumber = new NumericUpDown();
            _hoursNumber.Location = new Point(589, 49);
            _hoursNumber.Size = new Size(64, 25);
            _hoursNumber.Minimum = 1;
            _hoursNumber.Maximum = 168;
            _hoursNumber.Value = 8;
            setup.Controls.Add(_hoursNumber);
            Label hoursLabel = MakeLabel("hours", 658, 52, 60);
            setup.Controls.Add(hoursLabel);
            SetFieldHelp("Choose how many hours the access is planned to last. Automatic blocking requires the expiry option.",
                durationLabel, _hoursNumber, hoursLabel);

            _createButton = new Button();
            _createButton.Text = "Create access";
            _createButton.Location = new Point(744, 43);
            _createButton.Size = new Size(165, 36);
            _createButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _createButton.Click += CreateButtonClick;
            setup.Controls.Add(_createButton);
            SetFieldHelp("Create and test the temporary SSH access.",
                _createButton);

            BuildBootstrapUi(setup);

            _expiryCheck = new CheckBox();
            _expiryCheck.Location = new Point(500, 197);
            _expiryCheck.Size = new Size(238, 23);
            _expiryCheck.Checked = true;
            _expiryCheck.Text = "OpenSSH expiry option (optional)";
            setup.Controls.Add(_expiryCheck);
            SetFieldHelp("Optional: Block new logins after the selected time. Open SSH connections stay active.",
                _expiryCheck);

            _dedicatedAdminCheck = new CheckBox();
            _dedicatedAdminCheck.Location = new Point(16, 197);
            _dedicatedAdminCheck.Size = new Size(475, 23);
            _dedicatedAdminCheck.Checked = true;
            _dedicatedAdminCheck.Text = "Create a dedicated temporary administrator account with sudo (recommended)";
            setup.Controls.Add(_dedicatedAdminCheck);
            SetFieldHelp("Checked: create a temporary user with full sudo access. Unchecked: add the key to the existing user.",
                _dedicatedAdminCheck);

            _busyLabel = new Label();
            _busyLabel.Location = new Point(744, 96);
            _busyLabel.Size = new Size(165, 22);
            _busyLabel.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _busyLabel.TextAlign = ContentAlignment.MiddleCenter;
            _busyLabel.ForeColor = Color.DarkOrange;
            setup.Controls.Add(_busyLabel);

            var sessionsGroup = new GroupBox();
            sessionsGroup.Text = "Access sessions";
            sessionsGroup.Location = new Point(18, 308);
            sessionsGroup.Size = new Size(950, 285);
            sessionsGroup.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(sessionsGroup);

            _sessionsList = new ListView();
            _sessionsList.Location = new Point(14, 25);
            _sessionsList.Size = new Size(922, 186);
            _sessionsList.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            _sessionsList.View = View.Details;
            _sessionsList.FullRowSelect = true;
            _sessionsList.HideSelection = false;
            _sessionsList.MultiSelect = false;
            _sessionsList.Columns.Add("Status", 100);
            _sessionsList.Columns.Add("Alias", 135);
            _sessionsList.Columns.Add("Server", 155);
            _sessionsList.Columns.Add("User", 110);
            _sessionsList.Columns.Add("Planned until", 135);
            _sessionsList.Columns.Add("Bootstrap", 135);
            _sessionsList.Columns.Add("sudo", 120);
            _sessionsList.SelectedIndexChanged += delegate { UpdateSelection(); };
            sessionsGroup.Controls.Add(_sessionsList);

            _copyButton = MakeButton("Copy agent connection details", 14, 225, 220);
            _copyButton.Click += CopyButtonClick;
            sessionsGroup.Controls.Add(_copyButton);

            _testButton = MakeButton("Test connection", 244, 225, 155);
            _testButton.Click += TestButtonClick;
            sessionsGroup.Controls.Add(_testButton);

            _removeButton = MakeButton("Delete access", 409, 225, 165);
            _removeButton.Click += RemoveButtonClick;
            sessionsGroup.Controls.Add(_removeButton);

            _folderButton = MakeButton("Open folder", 584, 225, 135);
            _folderButton.Click += FolderButtonClick;
            sessionsGroup.Controls.Add(_folderButton);

            var detailGroup = new GroupBox();
            detailGroup.Text = "Selected access";
            detailGroup.Location = new Point(18, 603);
            detailGroup.Size = new Size(950, 115);
            detailGroup.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(detailGroup);

            _detailsText = new TextBox();
            _detailsText.Location = new Point(14, 24);
            _detailsText.Size = new Size(922, 76);
            _detailsText.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            _detailsText.Multiline = true;
            _detailsText.ReadOnly = true;
            _detailsText.BackColor = SystemColors.Window;
            detailGroup.Controls.Add(_detailsText);

            var logGroup = new GroupBox();
            logGroup.Text = "Log (contains no passwords or private keys)";
            logGroup.Location = new Point(18, 728);
            logGroup.Size = new Size(950, 122);
            logGroup.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(logGroup);

            _logText = new TextBox();
            _logText.Location = new Point(14, 24);
            _logText.Size = new Size(922, 84);
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

        private void SetFieldHelp(string text, params Control[] controls)
        {
            if (_fieldToolTips == null || controls == null) return;
            foreach (Control control in controls)
            {
                if (control == null) continue;
                control.AccessibleDescription = text;
                _fieldToolTips.SetToolTip(control, text);
            }
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
                item.SubItems.Add(BootstrapMethods.DisplayName(record.BootstrapMethod));
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
            bool testable = hasRecord && record.State != "Removed" && File.Exists(record.PrivateKeyPath);
            _copyButton.Enabled = !_busy && usable;
            _testButton.Enabled = !_busy && testable;
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
            _detailsText.Text = users + "Bootstrap: " + BootstrapMethods.DisplayName(record.BootstrapMethod) + Environment.NewLine +
                                "Temporary key fingerprint: " + (record.Fingerprint ?? "-") + Environment.NewLine +
                                "Server host-key fingerprint: " + (record.ServerHostKeyFingerprint ?? "-") + Environment.NewLine +
                                "Agent SSH command: " + command;
        }

        private void SetBusy(bool busy, string text)
        {
            _busy = busy;
            _busyLabel.Text = busy ? text : "";
            _createButton.Enabled = !busy;
            UpdateBootstrapUi();
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

            string bootstrapMethod = SelectedBootstrapMethod();
            if (bootstrapMethod != BootstrapMethods.Password)
            {
                await CreateNonPasswordAccessAsync(host, user, port, hours, bootstrapMethod);
                return;
            }

            BootstrapHostKey confirmedHostKey = null;
            SetBusy(true, "Checking server ...");
            bool passwordAvailable = await PreparePasswordBootstrapAsync(host, port, user,
                delegate(BootstrapHostKey value) { confirmedHostKey = value; });
            SetBusy(false, "");
            if (!passwordAvailable) return;

            bool dedicatedAdmin = _dedicatedAdminCheck.Checked;
            bool enforceServerExpiry = _expiryCheck.Checked;

            DialogResult confirmation = MessageBox.Show(this,
                BuildHostKeyReviewText(host, port, confirmedHostKey) + "\n\n" +
                "A new temporary key will be generated, then a separate SSH window will open.\n\n" +
                "1. Enter the SSH password and, if requested, the sudo password only in that separate window.\n" +
                "   The window remains open after SSH finishes; press ENTER after reviewing the result.\n" +
                (dedicatedAdmin
                    ? "2. The tool creates a dedicated temporary account with unrestricted passwordless sudo. This grants full administrator access.\n\n"
                    : "2. The key is installed for the existing user. Root or unrestricted sudo also grants full administrator access.\n\n") +
                (enforceServerExpiry
                    ? "The optional OpenSSH expiry setting will be tested first. If the server rejects it, the tool can retry the same access without that option.\n\n"
                    : "The server will not expire this access automatically. You must remove it with this tool after the work is complete.\n\n") +
                "Continue?",
                "Create temporary access", MessageBoxButtons.OKCancel,
                dedicatedAdmin ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
            if (confirmation != DialogResult.OK) return;

            SetBusy(true, "Creating access …");
            SessionRecord record = null;
            try
            {
                record = await Task.Run(delegate
                {
                    SessionRecord newRecord = SessionStore.Create(host, user, port, hours, enforceServerExpiry,
                        dedicatedAdmin, BootstrapMethods.Password);
                    try
                    {
                        SshTools.GenerateKeyAndFiles(newRecord, enforceServerExpiry);
                        ExistingKeyBootstrapper.WriteKnownHosts(newRecord, confirmedHostKey);
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
                Log("Temporary key " + record.Alias + " was generated locally.");

                int installExit = await Task.Run(delegate { return SshTools.RunInteractiveInstall(record); });
                if (installExit != 0)
                {
                    Log(installExit == -1073741510
                        ? "The separate SSH window was interrupted or closed. The key will still be tested automatically."
                        : "The SSH operation returned exit code " + installExit + ". The key will still be tested for safety.");
                }

                TemporaryAccessCheck verification = await Task.Run(delegate { return SshTools.CheckTemporaryAccess(record); });
                if (verification.Outcome != TemporaryAccessOutcome.Accepted && record.EnforceServerExpiry)
                {
                    DialogResult retryWithoutExpiry = MessageBox.Show(this,
                        "The new key could not log in with the OpenSSH expiry option. The server may not support this option. Retry without automatic expiry?\n\nThe separate password window will open again. You must then remove the access manually with this tool.",
                        "Retry without expiry option", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                    if (retryWithoutExpiry == DialogResult.Yes)
                    {
                        record.EnforceServerExpiry = false;
                        record.LastMessage = "Retrying without a server-side expiry setting.";
                        SshTools.WriteAgentInstructions(record);
                        SessionStore.Save(record);
                        Log("The key could not be verified with the optional expiry setting. Retrying without that option.");
                        installExit = await Task.Run(delegate { return SshTools.RunInteractiveInstall(record); });
                        verification = await Task.Run(delegate { return SshTools.CheckTemporaryAccess(record); });
                    }
                }
                if (verification.Outcome != TemporaryAccessOutcome.Accepted)
                {
                    RunResult verificationResult = verification.Result ?? new RunResult();
                    record.State = "SetupFailed";
                    record.LastMessage = (installExit == -1073741510
                        ? "The SSH window was interrupted before completion. "
                        : "SSH setup failed (exit code " + installExit + "). ") +
                        "The new key could not be verified. " + SafeOneLine(verificationResult.Combined) +
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
                SshTools.WriteAgentInstructions(record);
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

        private async void CopyButtonClick(object sender, EventArgs e)
        {
            SessionRecord record = SelectedRecord();
            if (record == null || record.State != "Active") return;
            string details = AgentConnectionDetails(record);
            string buttonText = _copyButton.Text;
            _copyButton.Enabled = false;
            _copyButton.Text = "Copying ...";
            try
            {
                if (!await ClipboardHelper.TryCopyTextAsync(details))
                {
                    Log("Windows could not open the clipboard after several attempts. The access remains active.");
                    MessageBox.Show(this,
                        "Windows could not open the clipboard after several attempts. Close any application that may be using it, then try again.",
                        "Clipboard unavailable", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                Log("Copied the generated agent connection details for " + record.Alias + ".");
                MessageBox.Show(this,
                    "The connection details were copied. They reference the generated private-key file but do not include its contents or any bootstrap credential.",
                    "Connection details copied", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            finally
            {
                if (!_copyButton.IsDisposed)
                {
                    _copyButton.Text = buttonText;
                    UpdateSelection();
                }
            }
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

            if (record.BootstrapMethod != BootstrapMethods.Password)
            {
                await RemoveNonPasswordAccessAsync(record);
                return;
            }

            SetBusy(true, "Removing access …");
            try
            {
                bool cleanupConfirmed = false;
                if (!record.UsesDedicatedAdminAccount && File.Exists(record.PrivateKeyPath))
                {
                    RunResult removal = await Task.Run(delegate { return SshTools.RemoveUsingTemporaryKey(record); });
                    cleanupConfirmed = SshTools.CleanupWasConfirmed(record, removal);
                    if (!cleanupConfirmed)
                    {
                        Log("Automatic removal was not possible: " + SafeOneLine(removal.Combined));
                    }
                }

                if (!cleanupConfirmed)
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
                    cleanupConfirmed = true;
                }

                if (!cleanupConfirmed)
                {
                    throw new InvalidOperationException("The server did not confirm removal of the temporary access.");
                }

                TemporaryAccessCheck postRemoval = await Task.Run(delegate { return SshTools.CheckTemporaryAccess(record); });
                if (postRemoval.Outcome == TemporaryAccessOutcome.Accepted)
                {
                    record.State = "RemovalFailed";
                    record.LastMessage = "The server still accepts the key; local data was not deleted.";
                    SessionStore.Save(record);
                    RefreshList(record);
                    Log(record.LastMessage);
                    MessageBox.Show(this, record.LastMessage, "Removal not confirmed", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                if (postRemoval.Outcome == TemporaryAccessOutcome.Indeterminate)
                {
                    Log("The follow-up login test was inconclusive, but the pinned cleanup command confirmed that this session's server artifacts were removed.");
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

    }

    public static class SessionStore
    {
        public static readonly string Root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AgentSshKeyManager");
        public static readonly string SessionsRoot = Path.Combine(Root, "Sessions");
        public static readonly string LegacySessionsRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "CodexSshAccessManager", "Sessions");
        internal static readonly string[] LegacyInteractiveHelperPatterns =
        {
            "ssh-action-*." + "ps1",
            "ssh-action-*." + "result"
        };

        public static SessionRecord Create(string host, string user, int port, int hours, bool serverExpiry, bool dedicatedAdmin)
        {
            return Create(host, user, port, hours, serverExpiry, dedicatedAdmin, BootstrapMethods.Password);
        }

        public static SessionRecord Create(string host, string user, int port, int hours, bool serverExpiry,
            bool dedicatedAdmin, string bootstrapMethod)
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
            record.BootstrapMethod = string.IsNullOrWhiteSpace(bootstrapMethod) ? BootstrapMethods.Password : bootstrapMethod;
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
            string temp = path + ".tmp." + Guid.NewGuid().ToString("N");
            var serializer = new XmlSerializer(typeof(SessionRecord));
            try
            {
                using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    serializer.Serialize(stream, record);
                    stream.Flush(true);
                }

                const int attempts = 8;
                for (int attempt = 0; attempt < attempts; attempt++)
                {
                    try
                    {
                        if (File.Exists(path)) File.Replace(temp, path, null);
                        else File.Move(temp, path);
                        return;
                    }
                    catch (IOException)
                    {
                        if (!File.Exists(temp) && File.Exists(path)) return;
                        if (attempt + 1 == attempts) throw;
                        System.Threading.Thread.Sleep(40 + (attempt * 40));
                    }
                }
            }
            finally
            {
                DeleteTemporaryMetadataOrThrow(temp, 8, 40);
            }
        }

        // A leftover session.xml.tmp file can make later state changes ambiguous. Retry
        // transient locks (for example from indexing or endpoint protection), then make
        // the problem visible to the caller instead of silently leaving the file behind.
        internal static void DeleteTemporaryMetadataOrThrow(string path, int attempts, int initialDelayMilliseconds)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return;
            if (attempts < 1) throw new ArgumentOutOfRangeException("attempts");
            if (initialDelayMilliseconds < 0) throw new ArgumentOutOfRangeException("initialDelayMilliseconds");

            Exception lastFailure = null;
            for (int attempt = 0; attempt < attempts; attempt++)
            {
                try
                {
                    if (!File.Exists(path)) return;
                    File.Delete(path);
                    if (!File.Exists(path)) return;
                    lastFailure = new IOException("The temporary metadata file is still present after deletion.");
                }
                catch (IOException ex)
                {
                    lastFailure = ex;
                }
                catch (UnauthorizedAccessException ex)
                {
                    lastFailure = ex;
                }

                if (attempt + 1 < attempts)
                {
                    System.Threading.Thread.Sleep(initialDelayMilliseconds + (attempt * initialDelayMilliseconds));
                }
            }

            throw new IOException("Could not remove temporary session metadata: " + path, lastFailure);
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
            if (string.IsNullOrWhiteSpace(record.BootstrapMethod))
            {
                record.BootstrapMethod = BootstrapMethods.Password;
            }
        }

        private static bool IsValidStoredRecord(SessionRecord record)
        {
            if (record == null || !Regex.IsMatch(record.Id ?? "", "^[a-f0-9]{32}$")) return false;
            if (string.IsNullOrWhiteSpace(record.Host) || record.Host.Length > 253 ||
                !Regex.IsMatch(record.Host, "^[A-Za-z0-9._:-]+$") || !Regex.IsMatch(record.Host, "[A-Za-z0-9]")) return false;
            if (!IsSafeLogin(record.User) || !IsSafeLogin(record.BootstrapUser)) return false;
            if (record.BootstrapMethod != BootstrapMethods.Password &&
                record.BootstrapMethod != BootstrapMethods.ExistingKey &&
                record.BootstrapMethod != BootstrapMethods.Manual) return false;
            if (!string.IsNullOrWhiteSpace(record.ServerHostKeyFingerprint))
            {
                try { ExistingKeyBootstrapper.NormalizeFingerprint(record.ServerHostKeyFingerprint); }
                catch { return false; }
            }
            if (!string.IsNullOrWhiteSpace(record.ServerHostKeyAlgorithm) &&
                !Regex.IsMatch(record.ServerHostKeyAlgorithm, "^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521))$")) return false;
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
                foreach (string pattern in LegacyInteractiveHelperPatterns)
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
                SetAndVerifyPrivateFileSecurity(path);
            }
            catch
            {
                // OpenSSH also validates the file when establishing a connection.
            }
        }

        public static void RequireSecurePrivateFile(string path)
        {
            try
            {
                SetAndVerifyPrivateFileSecurity(path);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    "The generated private key could not be protected with restrictive Windows file permissions.", ex);
            }
        }

        private static void SetAndVerifyPrivateFileSecurity(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                throw new FileNotFoundException("The file to protect does not exist.", path);
            }

            SecurityIdentifier userSid = WindowsIdentity.GetCurrent().User;
            SecurityIdentifier systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var security = new FileSecurity();
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(userSid, FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, AccessControlType.Allow));
            File.SetAccessControl(path, security);

            FileSecurity applied = File.GetAccessControl(path, AccessControlSections.Owner | AccessControlSections.Access);
            if (!applied.AreAccessRulesProtected || !userSid.Equals(applied.GetOwner(typeof(SecurityIdentifier))))
            {
                throw new UnauthorizedAccessException("The private-key ACL or owner was not applied.");
            }

            bool userAllowed = false;
            bool systemAllowed = false;
            AuthorizationRuleCollection rules = applied.GetAccessRules(true, true, typeof(SecurityIdentifier));
            foreach (FileSystemAccessRule rule in rules)
            {
                var identity = rule.IdentityReference as SecurityIdentifier;
                bool isUser = userSid.Equals(identity);
                bool isSystem = systemSid.Equals(identity);
                if (rule.IsInherited || (!isUser && !isSystem) || rule.AccessControlType != AccessControlType.Allow)
                {
                    throw new UnauthorizedAccessException("The private-key ACL contains an unexpected access rule.");
                }
                if (isUser) userAllowed = true;
                if (isSystem) systemAllowed = true;
            }
            if (!userAllowed || !systemAllowed)
            {
                throw new UnauthorizedAccessException("The private-key ACL is incomplete.");
            }
        }
    }

    public static class SshTools
    {
        internal const string AgentTaskInstruction = "Use this temporary account to connect to the server via SSH. Then confirm whether you have sudo rights.";
        internal const string RootSudoCompatibilityPrefix = "sudo() { if [ \"$#\" -eq 1 ] && [ \"$1\" = \"-v\" ]; then return 0; fi; command \"$@\"; }; ";
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
            SessionStore.RequireSecurePrivateFile(record.PrivateKeyPath);

            var fingerprintArgs = new List<string>();
            fingerprintArgs.Add("-lf");
            fingerprintArgs.Add(record.PublicKeyPath);
            RunResult fingerprint = RunHidden(SshKeygenPath, fingerprintArgs, 10000);
            if (fingerprint.ExitCode != 0) throw new InvalidOperationException("The key fingerprint could not be determined.");
            record.Fingerprint = fingerprint.StandardOutput.Trim();

            File.WriteAllText(record.ConfigPath, BuildConfig(record), new UTF8Encoding(false));
            WriteAgentInstructions(record);
        }

        public static void WriteAgentInstructions(SessionRecord record)
        {
            string validityText = record.EnforceServerExpiry
                ? "The server-side access expires on " + record.ExpiresUtcValue.ToLocalTime().ToString("yyyy-MM-dd 'at' HH:mm") + ".\r\n"
                : "Planned end: " + record.ExpiresUtcValue.ToLocalTime().ToString("yyyy-MM-dd 'at' HH:mm") + ". Remove the access with this tool afterwards.\r\n";
            string text = AgentTaskInstruction + "\r\n\r\n" +
                "Temporary SSH access for an agent\r\n\r\n" +
                "Server: " + record.Host + "\r\n" +
                "Port: " + record.Port.ToString(CultureInfo.InvariantCulture) + "\r\n" +
                "User: " + record.User + "\r\n" +
                "Private key file: " + record.PrivateKeyPath + "\r\n" +
                "Server host-key fingerprint: " + (record.ServerHostKeyFingerprint ?? "not recorded") + "\r\n\r\n" +
                "Connect:\r\n" + ConnectionCommand(record) + "\r\n\r\n" +
                validityText;
            string path = Path.Combine(record.SessionDirectory, "AGENT-SSH-COMMAND.txt");
            File.WriteAllText(path, text, new UTF8Encoding(true));
            SessionStore.TrySecurePrivateFile(path);
        }

        public static string BuildManualInstallCommand(SessionRecord record)
        {
            string publicKey = ReadValidatedPublicKey(record);
            string options = "no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc";
            string authorizedLine = options + " " + publicKey;
            long expiryUnixSeconds = UnixSeconds(record.ExpiresUtcValue);
            string command = record.UsesDedicatedAdminAccount
                ? BuildDedicatedSetupCommand(record, authorizedLine, record.EnforceServerExpiry, expiryUnixSeconds)
                : BuildInstallCommand(record.Marker, authorizedLine, record.EnforceServerExpiry, expiryUnixSeconds);
            return record.UsesDedicatedAdminAccount && string.Equals(record.BootstrapUser, "root", StringComparison.Ordinal)
                ? RootSudoCompatibilityPrefix + command
                : command;
        }

        public static string BuildManualCleanupCommand(SessionRecord record)
        {
            string command = record.UsesDedicatedAdminAccount
                ? BuildDedicatedCleanupCommand(record)
                : BuildRemovalCommand(record.Marker, record.Id);
            return record.UsesDedicatedAdminAccount && string.Equals(record.BootstrapUser, "root", StringComparison.Ordinal)
                ? RootSudoCompatibilityPrefix + command
                : command;
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
                if (record.UsesDedicatedAdminAccount && string.Equals(record.BootstrapUser, "root", StringComparison.Ordinal))
                {
                    remote = RootSudoCompatibilityPrefix + remote;
                }
                loginUser = record.UsesDedicatedAdminAccount ? record.BootstrapUser : record.User;
            }
            else
            {
                remote = record.UsesDedicatedAdminAccount
                    ? BuildDedicatedCleanupCommand(record)
                    : BuildRemovalCommand(record.Marker, record.Id);
                if (record.UsesDedicatedAdminAccount && string.Equals(record.BootstrapUser, "root", StringComparison.Ordinal))
                {
                    remote = RootSudoCompatibilityPrefix + remote;
                }
                loginUser = record.UsesDedicatedAdminAccount ? record.BootstrapUser : record.User;
            }

            var args = BaseInteractiveArguments(record);
            args.Add(loginUser + "@" + record.Host);
            // ProcessStartInfo launches ssh.exe directly, so this is passed as one
            // argv value without a local shell or an encoded decoder pipeline.
            args.Add(remote);
            return args;
        }

        internal static string ReadValidatedPublicKey(SessionRecord record)
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

        internal static TemporaryAccessCheck CheckTemporaryAccess(SessionRecord record)
        {
            if (record == null || !File.Exists(record.PrivateKeyPath) ||
                !File.Exists(record.KnownHostsPath) || !File.Exists(record.ConfigPath))
            {
                return new TemporaryAccessCheck
                {
                    Outcome = TemporaryAccessOutcome.Indeterminate,
                    Result = new RunResult
                    {
                        ExitCode = -1,
                        StandardError = "The local files required to test the temporary access are missing."
                    }
                };
            }
            try
            {
                RunResult result = VerifyKey(record);
                return new TemporaryAccessCheck
                {
                    Outcome = ClassifyTemporaryAccessResult(result),
                    Result = result
                };
            }
            catch (Exception ex)
            {
                return new TemporaryAccessCheck
                {
                    Outcome = TemporaryAccessOutcome.Indeterminate,
                    Result = new RunResult { ExitCode = -1, StandardError = ex.Message }
                };
            }
        }

        internal static TemporaryAccessOutcome ClassifyTemporaryAccessResult(RunResult result)
        {
            if (result == null || result.TimedOut) return TemporaryAccessOutcome.Indeterminate;
            if (result.ExitCode == 0 &&
                (result.StandardOutput ?? "").IndexOf("AGENT_SSH_ACCESS_OK", StringComparison.Ordinal) >= 0)
            {
                return TemporaryAccessOutcome.Accepted;
            }

            string error = (result.StandardError ?? "").ToLowerInvariant();
            bool localKeyFailure = error.Contains("load key") ||
                error.Contains("identity file") ||
                error.Contains("bad permissions") ||
                error.Contains("unprotected private key") ||
                error.Contains("error in libcrypto") ||
                error.Contains("no such file or directory");
            if (result.ExitCode != 0 && !localKeyFailure && error.Contains("permission denied"))
            {
                return TemporaryAccessOutcome.Rejected;
            }
            return TemporaryAccessOutcome.Indeterminate;
        }

        internal static string CleanupConfirmation(SessionRecord record)
        {
            if (record == null)
            {
                throw new InvalidOperationException("The access session identifier is invalid.");
            }
            return CleanupConfirmation(record.Id);
        }

        private static string CleanupConfirmation(string id)
        {
            if (!Regex.IsMatch(id ?? "", "^[a-fA-F0-9]{32}$"))
            {
                throw new InvalidOperationException("The access session identifier is invalid.");
            }
            return "AGENT_SSH_CLEANUP_OK:" + id.ToLowerInvariant();
        }

        internal static bool CleanupWasConfirmed(SessionRecord record, int exitCode, string standardOutput)
        {
            if (exitCode != 0) return false;
            string expected = CleanupConfirmation(record);
            string[] lines = (standardOutput ?? "").Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
            foreach (string line in lines)
            {
                if (string.Equals(line.Trim(), expected, StringComparison.Ordinal)) return true;
            }
            return false;
        }

        internal static bool CleanupWasConfirmed(SessionRecord record, RunResult result)
        {
            return result != null && CleanupWasConfirmed(record, result.ExitCode, result.StandardOutput);
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
            args.Add("StrictHostKeyChecking=yes");
            args.Add("-o");
            args.Add("UserKnownHostsFile=" + record.KnownHostsPath);
            args.Add("-o");
            args.Add("ConnectTimeout=20");
            args.Add("-o");
            args.Add("ConnectionAttempts=1");
            AddHostKeyAlgorithmArgument(args, record);
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
            AddHostKeyAlgorithmArgument(args, record);
            return args;
        }

        private static void AddHostKeyAlgorithmArgument(List<string> args, SessionRecord record)
        {
            string algorithms = HostKeyAlgorithms(record);
            if (algorithms.Length == 0) return;
            args.Add("-o");
            args.Add("HostKeyAlgorithms=" + algorithms);
        }

        private static string HostKeyAlgorithms(SessionRecord record)
        {
            string algorithm = record == null ? "" : (record.ServerHostKeyAlgorithm ?? "");
            if (algorithm == "ssh-rsa") return "rsa-sha2-512,rsa-sha2-256,ssh-rsa";
            return algorithm;
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
                   "t=$(mktemp \"$d/.agent-ssh-key.XXXXXXXXXX\"); trap 'rm -f \"$t\"' EXIT HUP INT TERM; " +
                   "awk -v m=" + ShellQuote(marker) +
                   " '!(length($0)>=length(m) && substr($0,length($0)-length(m)+1)==m) { print }' \"$f\" > \"$t\"; " +
                   "printf '%s\\n' \"$authorized_line\" >> \"$t\"; chmod 600 \"$t\"; mv \"$t\" \"$f\"; trap - EXIT HUP INT TERM; " +
                   "grep -Fqx -- \"$authorized_line\" \"$f\"; " +
                   "awk -v m=" + ShellQuote(marker) +
                   " 'length($0)>=length(m) && substr($0,length($0)-length(m)+1)==m { count++ } END { exit(count == 1 ? 0 : 1) }' \"$f\"";
        }

        public static string BuildDedicatedSetupCommand(SessionRecord record, string authorizedLine)
        {
            return BuildDedicatedSetupCommand(record, authorizedLine, false, 0);
        }

        public static string BuildDedicatedSetupCommand(SessionRecord record, string authorizedLine, bool useExpiry, long expiryUnixSeconds)
        {
            string sudoers = SudoersPath(record);
            string owner = OwnershipPath(record);
            string home = DedicatedHomePath(record);
            string sudoRule = record.User + " ALL=(ALL:ALL) NOPASSWD: ALL";
            string markerLine = "# " + record.Marker;
            string ownerValue = record.Marker + " user=" + record.User;
            string ownerHomeValue = "home=" + home;
            return "set -eu; " + BuildAuthorizedLineAssignment(authorizedLine, useExpiry, expiryUnixSeconds) +
                   "u=" + ShellQuote(record.User) + "; h=" + ShellQuote(home) + "; rule=" + ShellQuote(sudoers) + "; owner=" + ShellQuote(owner) + "; " +
                   "owner_value=" + ShellQuote(ownerValue) + "; owner_home_value=" + ShellQuote(ownerHomeValue) + "; sudo -v; " +
                   "sudo install -d -m 700 -o root -g root /var/lib/agent-ssh-key-manager; " +
                   "if id -u \"$u\" >/dev/null 2>&1; then " +
                   "actual_h=$(getent passwd \"$u\" | cut -d: -f6); [ \"$actual_h\" = \"$h\" ]; " +
                   "if sudo test -f \"$owner\"; then sudo grep -Fqx -- \"$owner_value\" \"$owner\"; " +
                   "if sudo grep -q '^home=' \"$owner\"; then sudo grep -Fqx -- \"$owner_home_value\" \"$owner\"; fi; " +
                   "else sudo test -f \"$rule\"; sudo grep -Fqx -- " + ShellQuote(markerLine) + " \"$rule\"; " +
                   "sudo grep -Fqx -- " + ShellQuote(sudoRule) + " \"$rule\"; " +
                   "printf '%s\\n%s\\n' \"$owner_value\" \"$owner_home_value\" | sudo tee \"$owner\" >/dev/null; fi; " +
                   "else if sudo test -e \"$owner\"; then sudo grep -Fqx -- \"$owner_value\" \"$owner\"; " +
                   "if sudo grep -q '^home=' \"$owner\"; then sudo grep -Fqx -- \"$owner_home_value\" \"$owner\"; fi; " +
                   "else printf '%s\\n%s\\n' \"$owner_value\" \"$owner_home_value\" | sudo tee \"$owner\" >/dev/null; fi; " +
                   "sudo /usr/sbin/useradd --create-home --home-dir \"$h\" --user-group --shell /bin/bash \"$u\"; fi; " +
                   "actual_h=$(getent passwd \"$u\" | cut -d: -f6); [ \"$actual_h\" = \"$h\" ]; " +
                   "printf '%s\\n%s\\n' \"$owner_value\" \"$owner_home_value\" | sudo tee \"$owner\" >/dev/null; " +
                   "sudo chmod 600 \"$owner\"; " +
                   "p=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \\n'); [ -n \"$p\" ]; " +
                   "printf '%s:%s\\n' \"$u\" \"$p\" | sudo /usr/sbin/chpasswd; unset p; " +
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

        internal static long UnixSecondsForBootstrap(DateTime value)
        {
            return UnixSeconds(value);
        }

        public static string BuildDedicatedCleanupCommand(SessionRecord record)
        {
            string sudoers = SudoersPath(record);
            string owner = OwnershipPath(record);
            string home = DedicatedHomePath(record);
            string sudoRule = record.User + " ALL=(ALL:ALL) NOPASSWD: ALL";
            string markerLine = "# " + record.Marker;
            string ownerValue = record.Marker + " user=" + record.User;
            string ownerHomeValue = "home=" + home;
            string confirmation = CleanupConfirmation(record);
            return "set -eu; u=" + ShellQuote(record.User) + "; h=" + ShellQuote(home) + "; rule=" + ShellQuote(sudoers) + "; owner=" + ShellQuote(owner) + "; " +
                   "owner_value=" + ShellQuote(ownerValue) + "; owner_home_value=" + ShellQuote(ownerHomeValue) + "; owned=0; sudo -v; " +
                   "if sudo test -f \"$owner\"; then sudo grep -Fqx -- \"$owner_value\" \"$owner\"; owned=1; " +
                   "if sudo grep -q '^home=' \"$owner\"; then sudo grep -Fqx -- \"$owner_home_value\" \"$owner\"; fi; " +
                   "elif sudo test -f \"$rule\"; then sudo grep -Fqx -- " + ShellQuote(markerLine) + " \"$rule\"; " +
                   "sudo grep -Fqx -- " + ShellQuote(sudoRule) + " \"$rule\"; owned=1; " +
                   "elif id -u \"$u\" >/dev/null 2>&1; then printf '%s\\n' 'Refusing to remove an unowned account.' >&2; exit 1; fi; " +
                   "if sudo test -e \"$rule\"; then sudo grep -Fqx -- " + ShellQuote(markerLine) + " \"$rule\"; " +
                   "sudo grep -Fqx -- " + ShellQuote(sudoRule) + " \"$rule\"; fi; " +
                   "if id -u \"$u\" >/dev/null 2>&1; then " +
                   "actual_h=$(getent passwd \"$u\" | cut -d: -f6); [ \"$actual_h\" = \"$h\" ]; sudo rm -f \"$h/.ssh/authorized_keys\"; " +
                   "sudo pkill -TERM -u \"$u\" >/dev/null 2>&1 || true; sleep 1; " +
                   "sudo pkill -KILL -u \"$u\" >/dev/null 2>&1 || true; " +
                   "sudo /usr/sbin/userdel --remove \"$u\"; fi; " +
                   "if sudo test -e \"$h\"; then if [ \"$owned\" -ne 1 ]; then printf '%s\\n' 'Refusing to remove an unowned home directory.' >&2; exit 1; fi; " +
                   "sudo rm -rf -- \"$h\"; fi; " +
                   "sudo rm -f \"$rule\"; ! id -u \"$u\" >/dev/null 2>&1; sudo test ! -e \"$rule\"; sudo test ! -e \"$h\"; " +
                   "sudo rm -f \"$owner\"; sudo test ! -e \"$owner\"; printf '%s\\n' " + ShellQuote(confirmation);
        }

        private static string DedicatedHomePath(SessionRecord record)
        {
            return "/home/" + record.User;
        }

        public static string BuildRemovalCommand(string marker, string id)
        {
            string suffix = Regex.Replace(id ?? "session", "[^A-Za-z0-9]", "");
            if (suffix.Length > 16) suffix = suffix.Substring(0, 16);
            string confirmation = CleanupConfirmation(id);
            return "set -eu; f=\"$HOME/.ssh/authorized_keys\"; " +
                   "if [ -f \"$f\" ]; then t=$(mktemp \"${f}.agent-ssh-" + suffix + ".XXXXXXXXXX\"); " +
                   "trap 'rm -f \"$t\"' EXIT HUP INT TERM; " +
                   "awk -v m=" + ShellQuote(marker) +
                   " '!(length($0)>=length(m) && substr($0,length($0)-length(m)+1)==m) { print }' \"$f\" > \"$t\"; " +
                   "chmod 600 \"$t\"; mv \"$t\" \"$f\"; trap - EXIT HUP INT TERM; fi; " +
                   "if [ -e \"$f\" ]; then [ -f \"$f\" ]; " +
                   "marker_count=$(awk -v m=" + ShellQuote(marker) +
                   " 'length($0)>=length(m) && substr($0,length($0)-length(m)+1)==m { count++ } END { print count+0 }' \"$f\"); " +
                   "[ \"$marker_count\" -eq 0 ]; fi; " +
                   "printf '%s\\n' " + ShellQuote(confirmation);
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
            string hostKeyAlgorithms = HostKeyAlgorithms(record);
            if (hostKeyAlgorithms.Length > 0) text.AppendLine("    HostKeyAlgorithms " + hostKeyAlgorithms);
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
                record.BootstrapMethod = BootstrapMethods.ExistingKey;
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
                byte[] testHostKeyData = JoinBytes(SshBinaryString(Encoding.ASCII.GetBytes("ssh-ed25519")),
                    SshBinaryString(Enumerable.Range(1, 32).Select(value => (byte)value).ToArray()));
                var testHostKey = new BootstrapHostKey
                {
                    Algorithm = "ssh-ed25519",
                    Fingerprint = SshFingerprint(testHostKeyData),
                    KeyData = testHostKeyData,
                    AuthenticationMethods = new[] { "publickey" },
                    AuthenticationMethodsKnown = true
                };
                ExistingKeyBootstrapper.WriteKnownHosts(record, testHostKey);
                SshTools.WriteAgentInstructions(record);
                Assert(File.Exists(record.PrivateKeyPath), "private key missing");
                Assert(File.Exists(record.PublicKeyPath), "public key missing");
                Assert((record.Fingerprint ?? "").IndexOf("SHA256:", StringComparison.Ordinal) >= 0, "fingerprint missing");
                string config = File.ReadAllText(record.ConfigPath);
                Assert(config.IndexOf("BatchMode yes", StringComparison.Ordinal) >= 0, "BatchMode missing");
                Assert(config.IndexOf("PasswordAuthentication no", StringComparison.Ordinal) >= 0, "password auth not disabled");
                Assert(config.IndexOf("HostKeyAlgorithms ssh-ed25519", StringComparison.Ordinal) >= 0,
                    "confirmed host-key algorithm was not pinned in the agent config");
                Assert(File.ReadAllText(record.KnownHostsPath).IndexOf("ssh-ed25519", StringComparison.Ordinal) >= 0,
                    "confirmed server host key was not written");
                Assert(string.Equals(record.ServerHostKeyFingerprint, testHostKey.Fingerprint, StringComparison.Ordinal),
                    "server host-key fingerprint was not recorded");
                Assert(!ExistingKeyBootstrapper.HostKeyMatches(testHostKey, new BootstrapHostKey
                {
                    Algorithm = testHostKey.Algorithm,
                    Fingerprint = testHostKey.Fingerprint,
                    KeyData = testHostKeyData.Concat(new byte[] { 0 }).ToArray()
                }), "host-key raw data mismatch was accepted");

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
                string sessionPath = Path.Combine(record.SessionDirectory, "session.xml");
                FileStream sessionLock = new FileStream(sessionPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                var releaseSessionLock = new System.Threading.Thread(new System.Threading.ThreadStart(delegate
                {
                    System.Threading.Thread.Sleep(180);
                    sessionLock.Dispose();
                }));
                releaseSessionLock.IsBackground = true;
                try
                {
                    releaseSessionLock.Start();
                    record.LastMessage = "Session save retry test";
                    SessionStore.Save(record);
                    releaseSessionLock.Join();
                }
                finally
                {
                    sessionLock.Dispose();
                    if (releaseSessionLock.IsAlive) releaseSessionLock.Join();
                }
                Assert(!Directory.GetFiles(record.SessionDirectory, "session.xml.tmp.*").Any(),
                    "session metadata save left a temporary file after a transient lock");
                string lockedMetadataTemp = Path.Combine(record.SessionDirectory, "session.xml.tmp.locked");
                File.WriteAllText(lockedMetadataTemp, "temporary metadata");
                bool lockedMetadataFailureWasReported = false;
                using (var lockedMetadata = new FileStream(lockedMetadataTemp, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    try
                    {
                        SessionStore.DeleteTemporaryMetadataOrThrow(lockedMetadataTemp, 2, 10);
                    }
                    catch (IOException)
                    {
                        lockedMetadataFailureWasReported = true;
                    }
                }
                Assert(lockedMetadataFailureWasReported && File.Exists(lockedMetadataTemp),
                    "undeletable temporary session metadata was not surfaced");
                SessionStore.DeleteTemporaryMetadataOrThrow(lockedMetadataTemp, 2, 10);
                Assert(!File.Exists(lockedMetadataTemp), "temporary session metadata was not deleted after its lock was released");
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
                Assert(install.IndexOf("mktemp", StringComparison.Ordinal) >= 0 &&
                    install.IndexOf("printf '%s\\n' \"$authorized_line\"", StringComparison.Ordinal) >= 0,
                    "existing-user install is not an atomic marker replacement");
                Assert(expiryInstall.IndexOf("date -d @4102444799", StringComparison.Ordinal) >= 0, "server-local expiry conversion missing");
                Assert(expiryInstall.IndexOf("expiry-time=", StringComparison.Ordinal) >= 0, "expiry key option missing");
                Assert(removal.IndexOf(record.Marker, StringComparison.Ordinal) >= 0, "removal marker missing");
                string cleanupConfirmation = SshTools.CleanupConfirmation(record);
                Assert(removal.IndexOf(cleanupConfirmation, StringComparison.Ordinal) >= 0,
                    "existing-user cleanup postcondition missing");
                Assert(removal.IndexOf("marker_count=$(awk", StringComparison.Ordinal) >= 0,
                    "existing-user cleanup does not fail closed when marker verification is unreadable");
                Assert(dedicatedSetup.IndexOf("useradd", StringComparison.Ordinal) >= 0, "dedicated user creation missing");
                Assert(dedicatedSetup.IndexOf("chpasswd", StringComparison.Ordinal) >= 0, "random account password setup missing");
                Assert(dedicatedSetup.IndexOf("visudo", StringComparison.Ordinal) >= 0, "sudoers validation missing");
                Assert(dedicatedSetup.IndexOf("grep -Fqx", StringComparison.Ordinal) >= 0, "existing dedicated account ownership proof missing");
                Assert(dedicatedSetup.IndexOf("/var/lib/agent-ssh-key-manager/", StringComparison.Ordinal) >= 0, "durable dedicated account ownership marker missing");
                Assert(dedicatedSetup.IndexOf("--home-dir", StringComparison.Ordinal) >= 0 &&
                    dedicatedSetup.IndexOf("home=/home/" + record.User, StringComparison.Ordinal) >= 0,
                    "dedicated account home ownership metadata is missing");
                Assert(dedicatedSetup.IndexOf("visudo", StringComparison.Ordinal) < dedicatedSetup.IndexOf("authorized_keys", StringComparison.Ordinal), "public key exposed before sudoers validation");
                Assert(dedicatedCleanup.IndexOf("userdel", StringComparison.Ordinal) >= 0, "dedicated cleanup missing");
                Assert(dedicatedCleanup.IndexOf("grep -Fqx", StringComparison.Ordinal) >= 0, "dedicated cleanup ownership proof missing");
                Assert(dedicatedCleanup.IndexOf("/var/lib/agent-ssh-key-manager/", StringComparison.Ordinal) >= 0, "dedicated cleanup ownership marker missing");
                Assert(dedicatedCleanup.IndexOf("rm -rf -- \"$h\"", StringComparison.Ordinal) >= 0 &&
                    dedicatedCleanup.IndexOf("sudo test ! -e \"$h\"", StringComparison.Ordinal) >= 0,
                    "dedicated cleanup does not remove and verify its exact owned home directory");
                Assert(dedicatedCleanup.IndexOf(cleanupConfirmation, StringComparison.Ordinal) >= 0 &&
                    dedicatedCleanup.IndexOf("test ! -e", StringComparison.Ordinal) >= 0,
                    "dedicated cleanup postcondition missing");
                Assert(SshTools.CleanupWasConfirmed(record, 0, "before\n" + cleanupConfirmation + "\nafter"),
                    "valid cleanup confirmation was rejected");
                Assert(!SshTools.CleanupWasConfirmed(record, 1, cleanupConfirmation) &&
                    !SshTools.CleanupWasConfirmed(record, 0, "AGENT_SSH_CLEANUP_OK:wrong") &&
                    !SshTools.CleanupWasConfirmed(record, 0, "prefix" + cleanupConfirmation + "suffix"),
                    "invalid cleanup confirmation was accepted");
                Assert(ManualActionDialog.ContainsConfirmationLine("output\r\n" + cleanupConfirmation + "\r\n", cleanupConfirmation) &&
                    !ManualActionDialog.ContainsConfirmationLine("cleanup complete", cleanupConfirmation),
                    "manual cleanup confirmation validation failed");
                Assert(!ManualActionDialog.ContainsConfirmationLine(
                    "prefix" + cleanupConfirmation, cleanupConfirmation),
                    "partial manual cleanup confirmation was accepted");
                Assert(SshTools.ClassifyTemporaryAccessResult(new RunResult
                {
                    ExitCode = 0,
                    StandardOutput = "AGENT_SSH_ACCESS_OK"
                }) == TemporaryAccessOutcome.Accepted, "successful temporary login was not classified as accepted");
                Assert(SshTools.ClassifyTemporaryAccessResult(new RunResult
                {
                    ExitCode = 255,
                    StandardError = "Permission denied (publickey)."
                }) == TemporaryAccessOutcome.Rejected, "definitive authentication rejection was not classified correctly");
                Assert(SshTools.ClassifyTemporaryAccessResult(new RunResult
                {
                    ExitCode = -1,
                    TimedOut = true,
                    StandardError = "Connection timed out"
                }) == TemporaryAccessOutcome.Indeterminate, "timeout was incorrectly treated as revocation");
                Assert(SshTools.ClassifyTemporaryAccessResult(new RunResult
                {
                    ExitCode = 255,
                    StandardError = "Load key failed. Permission denied (publickey)."
                }) == TemporaryAccessOutcome.Indeterminate, "local key failure was incorrectly treated as revocation");
                Assert(SshTools.ClassifyTemporaryAccessResult(new RunResult
                {
                    ExitCode = 255,
                    StandardError = "REMOTE HOST IDENTIFICATION HAS CHANGED"
                }) == TemporaryAccessOutcome.Indeterminate, "host-key failure was incorrectly treated as revocation");
                string savedKnownHostsPath = record.KnownHostsPath;
                record.KnownHostsPath = Path.Combine(record.SessionDirectory, "missing-known-hosts");
                Assert(SshTools.CheckTemporaryAccess(record).Outcome == TemporaryAccessOutcome.Indeterminate,
                    "missing host-key pin data was incorrectly treated as revocation");
                record.KnownHostsPath = savedKnownHostsPath;
                Assert(directSetup.StartsWith("set -eu; ", StringComparison.Ordinal), "direct remote command prefix missing");
                Assert(directSetup.IndexOf(record.Marker, StringComparison.Ordinal) >= 0, "direct remote command marker missing");
                Assert(interactiveInstall.Contains("StrictHostKeyChecking=yes"),
                    "interactive password bootstrap does not pin the confirmed host key");
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

                KeyFileInspection openSshInspection = ExistingKeyBootstrapper.InspectAndValidatePrivateKey(
                    record.PrivateKeyPath, "");
                Assert(openSshInspection.Format == "OpenSSH" && !openSshInspection.IsEncrypted,
                    "generated OpenSSH key was not recognized");

                const string testPassphrase = "local-self-test-only-passphrase";
                string encryptedPrivateKey = Path.Combine(record.SessionDirectory, "encrypted-test-key.pem");
                WriteEncryptedPkcs8TestKey(encryptedPrivateKey, testPassphrase);
                File.Copy(record.PublicKeyPath, encryptedPrivateKey + ".pub");
                KeyFileInspection encryptedInspection = ExistingKeyBootstrapper.InspectAndValidatePrivateKey(
                    encryptedPrivateKey, testPassphrase);
                Assert(encryptedInspection.IsEncrypted, "encrypted private key was not recognized");
                bool wrongPassphraseRejected = false;
                try { ExistingKeyBootstrapper.InspectAndValidatePrivateKey(encryptedPrivateKey, "wrong-passphrase"); }
                catch (BootstrapException ex) { wrongPassphraseRejected = ex.Kind == BootstrapFailureKind.IncorrectKeyPassphrase; }
                Assert(wrongPassphraseRejected, "incorrect private-key passphrase was not diagnosed");

                string ppkPath = Path.Combine(record.SessionDirectory, "bootstrap-test.ppk");
                WriteUnencryptedPpkV2TestKey(ppkPath);
                KeyFileInspection ppkInspection = ExistingKeyBootstrapper.InspectAndValidatePrivateKey(ppkPath, "");
                Assert(ppkInspection.Format == "PuTTY PPK" && !ppkInspection.IsEncrypted,
                    "PuTTY PPK key was not parsed");

                string unsupportedKeyPath = Path.Combine(record.SessionDirectory, "unsupported-key.txt");
                File.WriteAllText(unsupportedKeyPath, "not an SSH private key", new UTF8Encoding(false));
                bool unsupportedRejected = false;
                try { ExistingKeyBootstrapper.InspectAndValidatePrivateKey(unsupportedKeyPath, ""); }
                catch (BootstrapException ex) { unsupportedRejected = ex.Kind == BootstrapFailureKind.UnsupportedKeyFormat; }
                Assert(unsupportedRejected, "unsupported private-key format was not diagnosed");

                string[] probedMethods = ExistingKeyBootstrapper.ParseAuthenticationMethods(
                    "No suitable authentication method found to complete authentication (publickey,password,keyboard-interactive).");
                Assert(probedMethods.SequenceEqual(new[] { "publickey", "password", "keyboard-interactive" }),
                    "SSH.NET authentication-method probe result was not parsed");

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

                string manualInstall = SshTools.BuildManualInstallCommand(record);
                string manualCleanup = SshTools.BuildManualCleanupCommand(record);
                Assert(manualInstall.IndexOf(record.Marker, StringComparison.Ordinal) >= 0,
                    "manual installation command marker missing");
                Assert(manualCleanup.IndexOf(record.Marker, StringComparison.Ordinal) >= 0,
                    "manual cleanup command marker missing");
                Assert(removal.IndexOf("awk -v m=", StringComparison.Ordinal) >= 0,
                    "existing-user removal does not preserve unrelated authorized_keys entries");
                string originalBootstrapUser = record.BootstrapUser;
                record.BootstrapUser = "root";
                Assert(SshTools.BuildManualInstallCommand(record).StartsWith(SshTools.RootSudoCompatibilityPrefix,
                    StringComparison.Ordinal), "root bootstrap without sudo compatibility is missing");
                record.BootstrapUser = originalBootstrapUser;

                string sessionXml = File.ReadAllText(Path.Combine(record.SessionDirectory, "session.xml"));
                string agentInstructions = File.ReadAllText(Path.Combine(record.SessionDirectory, "AGENT-SSH-COMMAND.txt"));
                Assert(agentInstructions.StartsWith(SshTools.AgentTaskInstruction, StringComparison.Ordinal),
                    "agent task instruction missing from generated connection details");
                Assert(agentInstructions.IndexOf("server-side access expires", StringComparison.OrdinalIgnoreCase) >= 0,
                    "expiry-enabled handoff does not describe server-side expiry");
                record.EnforceServerExpiry = false;
                SshTools.WriteAgentInstructions(record);
                string noExpiryInstructions = File.ReadAllText(Path.Combine(record.SessionDirectory, "AGENT-SSH-COMMAND.txt"));
                Assert(noExpiryInstructions.IndexOf("Planned end:", StringComparison.Ordinal) >= 0 &&
                    noExpiryInstructions.IndexOf("server-side access expires", StringComparison.OrdinalIgnoreCase) < 0,
                    "handoff was not regenerated accurately after disabling expiry");
                record.EnforceServerExpiry = true;
                SshTools.WriteAgentInstructions(record);
                foreach (string secret in new[] { testPassphrase, "wrong-passphrase", "sudo-password-sentinel" })
                {
                    Assert(sessionXml.IndexOf(secret, StringComparison.Ordinal) < 0,
                        "session metadata leaked a passphrase or password");
                    Assert(agentInstructions.IndexOf(secret, StringComparison.Ordinal) < 0,
                        "agent instructions leaked a passphrase or password");
                }
                Assert(typeof(SessionRecord).GetProperties().All(property =>
                    property.Name.IndexOf("Passphrase", StringComparison.OrdinalIgnoreCase) < 0 &&
                    property.Name.IndexOf("Password", StringComparison.OrdinalIgnoreCase) < 0 &&
                    property.Name.IndexOf("BootstrapKey", StringComparison.OrdinalIgnoreCase) < 0),
                    "session metadata model contains a bootstrap credential field");
                Assert(typeof(Renci.SshNet.SshClient).Assembly.GetName().Version != null,
                    "embedded SSH library could not be loaded");

                string legacyResult = Path.Combine(record.SessionDirectory, "ssh-action-install." + "result");
                File.WriteAllText(legacyResult, "1");
                SessionStore.DeleteSecretMaterial(record);
                Assert(SessionStore.LegacyInteractiveHelperPatterns.Contains("ssh-action-*." + "ps1") &&
                    !File.Exists(legacyResult), "legacy helper cleanup failed");
                report.AppendLine("SELF-TEST OK");
                report.AppendLine("Fingerprint: " + record.Fingerprint);
                report.AppendLine("Config safeguards: OK");
                report.AppendLine("Install/remove marker logic: OK");
                report.AppendLine("Definitive cleanup and three-state access verification: OK");
                report.AppendLine("Optional expiry command generation: OK");
                report.AppendLine("Direct remote command transport: OK");
                report.AppendLine("Windows argument round-trip: OK");
                report.AppendLine("Constrained manager/OpenSSH launch and exit propagation: OK");
                report.AppendLine("Stored-session and public-key validation: OK");
                report.AppendLine("OpenSSH, encrypted-key, and PuTTY PPK parsing: OK");
                report.AppendLine("Server fingerprint pinning and mismatch rejection: OK");
                report.AppendLine("Manual fallback and credential-free metadata: OK");
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

        private static void WriteEncryptedPkcs8TestKey(string path, string passphrase)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair pair =
                    Org.BouncyCastle.Security.DotNetUtilities.GetRsaKeyPair(rsa);
                char[] password = passphrase.ToCharArray();
                try
                {
                    using (var textWriter = new StreamWriter(path, false, new UTF8Encoding(false)))
                    using (var pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(textWriter))
                    {
                        pemWriter.WriteObject(pair.Private, "AES-256-CBC", password,
                            new Org.BouncyCastle.Security.SecureRandom());
                    }
                }
                finally
                {
                    Array.Clear(password, 0, password.Length);
                }
            }
        }

        private static void WriteUnencryptedPpkV2TestKey(string path)
        {
            const string algorithm = "ssh-rsa";
            const string encryption = "none";
            const string comment = "AgentSshKeyManager self-test";
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                RSAParameters parameters = rsa.ExportParameters(true);
                byte[] publicBlob = JoinBytes(
                    SshBinaryString(Encoding.ASCII.GetBytes(algorithm)),
                    SshMpint(parameters.Exponent),
                    SshMpint(parameters.Modulus));
                byte[] privateBlob = JoinBytes(
                    SshMpint(parameters.D),
                    SshMpint(parameters.P),
                    SshMpint(parameters.Q),
                    SshMpint(parameters.InverseQ));
                byte[] macData = JoinBytes(
                    SshBinaryString(Encoding.ASCII.GetBytes(algorithm)),
                    SshBinaryString(Encoding.ASCII.GetBytes(encryption)),
                    SshBinaryString(Encoding.UTF8.GetBytes(comment)),
                    SshBinaryString(publicBlob),
                    SshBinaryString(privateBlob));
                byte[] macKey;
                using (SHA1 sha1 = SHA1.Create())
                {
                    macKey = sha1.ComputeHash(Encoding.ASCII.GetBytes("putty-private-key-file-mac-key"));
                }
                byte[] mac;
                using (var hmac = new HMACSHA1(macKey))
                {
                    mac = hmac.ComputeHash(macData);
                }

                string[] publicLines = SplitBase64(publicBlob);
                string[] privateLines = SplitBase64(privateBlob);
                var text = new StringBuilder();
                text.AppendLine("PuTTY-User-Key-File-2: " + algorithm);
                text.AppendLine("Encryption: " + encryption);
                text.AppendLine("Comment: " + comment);
                text.AppendLine("Public-Lines: " + publicLines.Length.ToString(CultureInfo.InvariantCulture));
                foreach (string line in publicLines) text.AppendLine(line);
                text.AppendLine("Private-Lines: " + privateLines.Length.ToString(CultureInfo.InvariantCulture));
                foreach (string line in privateLines) text.AppendLine(line);
                text.AppendLine("Private-MAC: " + string.Concat(mac.Select(value =>
                    value.ToString("x2", CultureInfo.InvariantCulture)).ToArray()));
                File.WriteAllText(path, text.ToString(), new UTF8Encoding(false));
                Array.Clear(macKey, 0, macKey.Length);
                Array.Clear(privateBlob, 0, privateBlob.Length);
            }
        }

        private static string[] SplitBase64(byte[] value)
        {
            string encoded = Convert.ToBase64String(value);
            var lines = new List<string>();
            for (int index = 0; index < encoded.Length; index += 64)
            {
                lines.Add(encoded.Substring(index, Math.Min(64, encoded.Length - index)));
            }
            return lines.ToArray();
        }

        private static byte[] SshMpint(byte[] unsignedBigEndian)
        {
            if (unsignedBigEndian == null || unsignedBigEndian.Length == 0)
            {
                return SshBinaryString(new byte[0]);
            }
            int first = 0;
            while (first < unsignedBigEndian.Length - 1 && unsignedBigEndian[first] == 0) first++;
            int length = unsignedBigEndian.Length - first;
            bool leadingZero = (unsignedBigEndian[first] & 0x80) != 0;
            byte[] value = new byte[length + (leadingZero ? 1 : 0)];
            Buffer.BlockCopy(unsignedBigEndian, first, value, leadingZero ? 1 : 0, length);
            return SshBinaryString(value);
        }

        private static byte[] SshBinaryString(byte[] value)
        {
            byte[] safe = value ?? new byte[0];
            byte[] result = new byte[safe.Length + 4];
            result[0] = (byte)((safe.Length >> 24) & 0xff);
            result[1] = (byte)((safe.Length >> 16) & 0xff);
            result[2] = (byte)((safe.Length >> 8) & 0xff);
            result[3] = (byte)(safe.Length & 0xff);
            Buffer.BlockCopy(safe, 0, result, 4, safe.Length);
            return result;
        }

        private static byte[] JoinBytes(params byte[][] values)
        {
            int length = values.Sum(value => value == null ? 0 : value.Length);
            byte[] result = new byte[length];
            int offset = 0;
            foreach (byte[] value in values)
            {
                if (value == null) continue;
                Buffer.BlockCopy(value, 0, result, offset, value.Length);
                offset += value.Length;
            }
            return result;
        }

        private static string SshFingerprint(byte[] keyData)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return "SHA256:" + Convert.ToBase64String(sha256.ComputeHash(keyData)).TrimEnd('=');
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
