using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Media;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AegisGuard.UI
{
    public partial class Form1 : Form
    {
        private readonly ThreatDatabase _database;
        private readonly CloudScanner _cloudScanner;
        private readonly ScannerEngine _scanner;
        private readonly QuarantineEngine _quarantine;
        private readonly RealTimeWatcher _realTimeWatcher;

        private NotifyIcon _notifyIcon = null!;
        private ContextMenuStrip _trayMenu = null!;
        private ContextMenuStrip _quarantineContextMenu = null!;
        private ToolStripMenuItem _menuToggleProtection = null!;

        private bool _isDarkMode = true;
        private bool _isDeepDark = true;
        private bool _minimizeToTrayOnClose = true;
        private bool _showNotifications = true;
        private bool _showThreatPopup = true; // Option pour la popup d'alerte
        private bool _isExiting = false;
        private Color? _customTextColor = null;

        private Panel _sidebarPanel = null!;
        private Panel _contentPanel = null!;
        private Panel _homeView = null!;
        private Panel _quarantineView = null!;
        private Panel _settingsView = null!;

        private Panel _statusHeader = null!;
        private Label _lblStatusTitle = null!;
        private Label _lblStatusDesc = null!;

        private Button _btnNavHome = null!;
        private Button _btnNavQuarantine = null!;
        private Button _btnNavSettings = null!;

        private RoundButton _btnBigScan = null!;
        private Button _btnScanFile = null!;
        private Button _btnScanFolder = null!;
        private Button _btnToggleProtection = null!;
        private FlowLayoutPanel _actionButtonsPanel = null!;

        private Panel _pnlOfflineWarningHome = null!;
        private Label _lblOfflineMsg = null!;
        private Panel _pnlScanBanner = null!;
        private Label _lblScanResult = null!;

        private ListView _lstQuarantine = null!;
        private Label _lblQuarantineTitle = null!;
        private Label _lblQuarantineSubTitle = null!;

        private Label _lblNetworkStatusSidebar = null!;
        private System.Windows.Forms.Timer _networkTimer = null!;
        private bool _isOnline = true;

        private Label _lblSettingsTitle = null!;
        private Label _lblApparenceGroup = null!;
        private Label _lblOpacity = null!;
        private Label _lblComportementGroup = null!;
        private Label _lblSystemGroup = null!;

        private TrackBar _trkOpacity = null!;
        private Label _lblOpacityValue = null!;
        private CheckBox _chkMinimizeToTray = null!;
        private CheckBox _chkNotifications = null!;
        private CheckBox _chkShowThreatPopup = null!;
        private CheckBox _chkDeepDark = null!;
        private Button _btnThemeToggle = null!;
        private Button _btnPickTextColor = null!;
        private Button _btnResetTextColor = null!;
        private Button _btnManageExclusions = null!;

        public Form1()
        {
            InitializeComponent();

            this.Text = "AegisGuard Security";
            this.Size = new Size(1100, 700);
            this.MinimumSize = new Size(980, 620);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.FormBorderStyle = FormBorderStyle.Sizable;
            this.MaximizeBox = true;

            try
            {
                if (Properties.Resources.security_guard_shield_icon_153085 != null)
                {
                    using (var ms = new MemoryStream(Properties.Resources.security_guard_shield_icon_153085))
                    {
                        this.Icon = new Icon(ms);
                    }
                }
            }
            catch
            {
                this.Icon = SystemIcons.Shield;
            }

            _database = new ThreatDatabase();
            _cloudScanner = new CloudScanner();
            _scanner = new ScannerEngine(_database, _cloudScanner);
            _quarantine = new QuarantineEngine();
            _realTimeWatcher = new RealTimeWatcher(_scanner, _quarantine);

            _realTimeWatcher.ThreatDetected += OnRealTimeThreatDetected;

            BuildUI();
            SetupSystemTray();
            SetupQuarantineContextMenu();
            SetupNetworkMonitoring();
            ApplyTheme();

            _realTimeWatcher.StartAllDrives();
            UpdateStatusUI();

            SwitchView(_homeView, _btnNavHome);
        }

        #region Threat Handling

        private void OnRealTimeThreatDetected(string filePath, string threatName)
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new Action(() => OnRealTimeThreatDetected(filePath, threatName)));
                return;
            }

            SystemSounds.Hand.Play();

            // 1. Récupération du chemin d'origine si le fichier a été déplacé en quarantaine
            string originalPath = filePath;
            string metaFile = filePath + ".meta";
            if (File.Exists(metaFile))
            {
                try { originalPath = File.ReadAllText(metaFile); } catch { }
            }

            // 2. Notification Toast
            if (_showNotifications && _notifyIcon != null)
            {
                _notifyIcon.ShowBalloonTip(
                    3000,
                    "⚠️ Menaces Detectées",
                    $"Le fichier '{Path.GetFileName(originalPath)}' a été neutralisé.",
                    ToolTipIcon.Warning
                );
            }

            // 3. Affichage de la popup avec le VRAI chemin d'origine
            if (_showThreatPopup)
            {
                ThreatPopupForm popup = new ThreatPopupForm(originalPath, threatName, () =>
                {
                    ShowWindow();
                    SwitchView(_quarantineView, _btnNavQuarantine);
                });
                popup.ShowDialog(this);
            }

            RefreshQuarantineList();
        }

        #endregion

        #region Network Monitoring

        private void SetupNetworkMonitoring()
        {
            _networkTimer = new System.Windows.Forms.Timer { Interval = 4000 };
            _networkTimer.Tick += async (s, e) => await CheckNetworkConnectionAsync();
            _networkTimer.Start();

            _ = CheckNetworkConnectionAsync();
        }

        private async Task CheckNetworkConnectionAsync()
        {
            bool hasNetwork = NetworkInterface.GetIsNetworkAvailable();
            bool canReachWeb = false;

            if (hasNetwork)
            {
                await Task.Run(() =>
                {
                    try
                    {
                        using (Ping p = new Ping())
                        {
                            PingReply reply = p.Send("1.1.1.1", 1200);
                            canReachWeb = (reply.Status == IPStatus.Success);
                        }
                    }
                    catch
                    {
                        canReachWeb = false;
                    }
                });
            }

            _isOnline = canReachWeb;

            if (_isOnline)
            {
                _lblNetworkStatusSidebar.Text = "🌐 Connecté";
                _lblNetworkStatusSidebar.ForeColor = Color.FromArgb(46, 125, 50);
                _pnlOfflineWarningHome.Visible = false;
            }
            else
            {
                _lblNetworkStatusSidebar.Text = "🚫 Hors-Connexion";
                _lblNetworkStatusSidebar.ForeColor = Color.FromArgb(211, 47, 47);
                _pnlOfflineWarningHome.Visible = true;
            }
        }

        #endregion

        #region UI Building

        private void BuildUI()
        {
            _sidebarPanel = new Panel { Dock = DockStyle.Left, Width = 230 };

            Label lblAppName = new Label
            {
                Text = "🛡️ AegisGuard",
                Font = new Font("Segoe UI", 15, FontStyle.Bold),
                Location = new Point(20, 20),
                AutoSize = true,
                BackColor = Color.Transparent
            };

            _btnNavHome = CreateStyledButton("🏠 Accueil", new Point(12, 80), new Size(206, 45));
            _btnNavHome.Click += (s, e) => SwitchView(_homeView, _btnNavHome);

            _btnNavQuarantine = CreateStyledButton("📦 Quarantaine", new Point(12, 135), new Size(206, 45));
            _btnNavQuarantine.Click += (s, e) => SwitchView(_quarantineView, _btnNavQuarantine);

            _btnNavSettings = CreateStyledButton("⚙️ Paramètres", new Point(12, 190), new Size(206, 45));
            _btnNavSettings.Click += (s, e) => SwitchView(_settingsView, _btnNavSettings);

            _lblNetworkStatusSidebar = new Label
            {
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                Dock = DockStyle.Bottom,
                Height = 45,
                TextAlign = ContentAlignment.MiddleCenter,
                Text = "🌐 Vérification...",
                BackColor = Color.Transparent
            };

            _sidebarPanel.Controls.Add(lblAppName);
            _sidebarPanel.Controls.Add(_btnNavHome);
            _sidebarPanel.Controls.Add(_btnNavQuarantine);
            _sidebarPanel.Controls.Add(_btnNavSettings);
            _sidebarPanel.Controls.Add(_lblNetworkStatusSidebar);

            _contentPanel = new Panel { Dock = DockStyle.Fill };

            BuildHomeView();
            BuildQuarantineView();
            BuildSettingsView();

            _contentPanel.Controls.Add(_homeView);
            _contentPanel.Controls.Add(_quarantineView);
            _contentPanel.Controls.Add(_settingsView);

            this.Controls.Add(_contentPanel);
            this.Controls.Add(_sidebarPanel);

            this.Resize += Form1_Resize;
        }

        private Button CreateStyledButton(string text, Point location, Size size)
        {
            return new Button
            {
                Text = text,
                Font = new Font("Segoe UI", 9.5f),
                Location = location,
                Size = size,
                FlatStyle = FlatStyle.Flat,
                AutoEllipsis = true,
                Padding = new Padding(3),
                TextAlign = ContentAlignment.MiddleCenter
            };
        }

        private void BuildHomeView()
        {
            _homeView = new Panel { Dock = DockStyle.Fill };

            _statusHeader = new Panel { Dock = DockStyle.Top, Height = 85 };

            _lblStatusTitle = new Label
            {
                Font = new Font("Segoe UI", 14, FontStyle.Bold),
                ForeColor = Color.White,
                Location = new Point(25, 15),
                AutoSize = true,
                BackColor = Color.Transparent
            };

            _lblStatusDesc = new Label
            {
                Font = new Font("Segoe UI", 9.5f),
                ForeColor = Color.White,
                Location = new Point(27, 48),
                AutoSize = true,
                BackColor = Color.Transparent
            };

            _statusHeader.Controls.Add(_lblStatusTitle);
            _statusHeader.Controls.Add(_lblStatusDesc);

            Panel mainHomeContainer = new Panel
            {
                Dock = DockStyle.Fill,
                Padding = new Padding(20),
                BackColor = Color.Transparent
            };

            _pnlOfflineWarningHome = new Panel
            {
                Dock = DockStyle.Top,
                Height = 42,
                BackColor = Color.FromArgb(255, 243, 205),
                BorderStyle = BorderStyle.FixedSingle,
                Visible = false
            };

            _lblOfflineMsg = new Label
            {
                Text = "🚫 Vous n'êtes pas connecté à internet, les performances de l'application seront réduites.",
                Font = new Font("Segoe UI", 9f, FontStyle.Bold),
                ForeColor = Color.FromArgb(133, 100, 4),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter,
                BackColor = Color.Transparent
            };
            _pnlOfflineWarningHome.Controls.Add(_lblOfflineMsg);

            _btnBigScan = new RoundButton
            {
                Text = "ANALYSER\nLE PC",
                Font = new Font("Segoe UI", 12f, FontStyle.Bold),
                Size = new Size(160, 160),
                Cursor = Cursors.Hand
            };
            _btnBigScan.Click += BtnBigScan_Click;

            _actionButtonsPanel = new FlowLayoutPanel
            {
                Size = new Size(720, 55),
                WrapContents = false,
                AutoScroll = false,
                BackColor = Color.Transparent
            };

            _btnScanFile = CreateStyledButton("📄 Analyser un fichier", Point.Empty, new Size(230, 45));
            _btnScanFile.Margin = new Padding(5);
            _btnScanFile.Click += BtnScanFile_Click;

            _btnScanFolder = CreateStyledButton("📁 Analyser un dossier", Point.Empty, new Size(230, 45));
            _btnScanFolder.Margin = new Padding(5);
            _btnScanFolder.Click += BtnScanFolder_Click;

            _btnToggleProtection = CreateStyledButton("🛡️ Désactiver protection", Point.Empty, new Size(230, 45));
            _btnToggleProtection.Margin = new Padding(5);
            _btnToggleProtection.Click += (s, e) => ToggleRealTimeProtection();

            _actionButtonsPanel.Controls.Add(_btnScanFile);
            _actionButtonsPanel.Controls.Add(_btnScanFolder);
            _actionButtonsPanel.Controls.Add(_btnToggleProtection);

            _pnlScanBanner = new Panel
            {
                Size = new Size(710, 50),
                Visible = false
            };

            _lblScanResult = new Label
            {
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                ForeColor = Color.White,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter,
                BackColor = Color.Transparent
            };
            _pnlScanBanner.Controls.Add(_lblScanResult);

            mainHomeContainer.Controls.Add(_pnlScanBanner);
            mainHomeContainer.Controls.Add(_actionButtonsPanel);
            mainHomeContainer.Controls.Add(_btnBigScan);
            mainHomeContainer.Controls.Add(_pnlOfflineWarningHome);

            _homeView.Controls.Add(mainHomeContainer);
            _homeView.Controls.Add(_statusHeader);

            mainHomeContainer.Resize += (s, e) => CenterHomeElements(mainHomeContainer.Width);
        }

        private void CenterHomeElements(int containerWidth)
        {
            if (_btnBigScan != null)
                _btnBigScan.Location = new Point((containerWidth - _btnBigScan.Width) / 2, 60);

            if (_actionButtonsPanel != null)
                _actionButtonsPanel.Location = new Point((containerWidth - _actionButtonsPanel.Width) / 2, 245);

            if (_pnlScanBanner != null)
                _pnlScanBanner.Location = new Point((containerWidth - _pnlScanBanner.Width) / 2, 315);
        }

        private void BuildQuarantineView()
        {
            _quarantineView = new Panel { Dock = DockStyle.Fill, Visible = false };

            _lblQuarantineTitle = new Label
            {
                Text = "Zone de Quarantaine",
                Font = new Font("Segoe UI", 15, FontStyle.Bold),
                Location = new Point(25, 20),
                AutoSize = true,
                BackColor = Color.Transparent
            };

            _lblQuarantineSubTitle = new Label
            {
                Text = "Les fichiers neutralisés sont isolés en toute sécurité dans cette zone (clic droit pour gérer).",
                Font = new Font("Segoe UI", 9.5f),
                Location = new Point(27, 52),
                AutoSize = true,
                BackColor = Color.Transparent
            };

            _lstQuarantine = new ListView
            {
                Location = new Point(25, 90),
                Size = new Size(810, 520),
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                ShowItemToolTips = true
            };
            _lstQuarantine.Columns.Add("Nom du Fichier", 220);
            _lstQuarantine.Columns.Add("Date de Détection", 160);
            _lstQuarantine.Columns.Add("Chemin d'Accès Initial", 420);

            _quarantineView.Controls.Add(_lblQuarantineTitle);
            _quarantineView.Controls.Add(_lblQuarantineSubTitle);
            _quarantineView.Controls.Add(_lstQuarantine);
        }

        private void BuildSettingsView()
        {
            _settingsView = new Panel { Dock = DockStyle.Fill, Visible = false, Padding = new Padding(25) };

            _lblSettingsTitle = new Label
            {
                Text = "Paramètres de l'application",
                Font = new Font("Segoe UI", 15, FontStyle.Bold),
                Location = new Point(25, 20),
                AutoSize = true,
                BackColor = Color.Transparent
            };

            _lblApparenceGroup = new Label
            {
                Text = "🎨 APPARENCE ET PERSONNALISATION",
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                Location = new Point(25, 70),
                AutoSize = true,
                BackColor = Color.Transparent
            };

            _btnThemeToggle = CreateStyledButton("☀️ Mode Clair", new Point(25, 100), new Size(220, 40));
            _btnThemeToggle.Click += (s, e) => { _isDarkMode = !_isDarkMode; ApplyTheme(); };

            _btnPickTextColor = CreateStyledButton("🎨 Couleur des textes", new Point(255, 100), new Size(200, 40));
            _btnPickTextColor.Click += BtnPickTextColor_Click;

            _btnResetTextColor = CreateStyledButton("🔄 Réinitialiser", new Point(465, 100), new Size(130, 40));
            _btnResetTextColor.Click += (s, e) => { _customTextColor = null; ApplyTheme(); };

            _chkDeepDark = new CheckBox
            {
                Text = "🌙 Mode Noir Profond (Arrière-plan sombre élégant)",
                Font = new Font("Segoe UI", 9.5f),
                Location = new Point(25, 150),
                AutoSize = true,
                Checked = _isDeepDark,
                BackColor = Color.Transparent
            };
            _chkDeepDark.CheckedChanged += (s, e) => { _isDeepDark = _chkDeepDark.Checked; ApplyTheme(); };

            _lblOpacity = new Label
            {
                Text = "Opacité de la fenêtre :",
                Font = new Font("Segoe UI", 9.5f),
                Location = new Point(25, 185),
                AutoSize = true,
                BackColor = Color.Transparent
            };

            _trkOpacity = new TrackBar
            {
                Minimum = 30,
                Maximum = 100,
                Value = 100,
                TickFrequency = 10,
                Location = new Point(25, 210),
                Width = 250
            };
            _trkOpacity.ValueChanged += (s, e) =>
            {
                this.Opacity = _trkOpacity.Value / 100.0;
                _lblOpacityValue.Text = $"{_trkOpacity.Value}%";
            };

            _lblOpacityValue = new Label
            {
                Text = "100%",
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                Location = new Point(285, 215),
                AutoSize = true,
                BackColor = Color.Transparent
            };

            _lblComportementGroup = new Label
            {
                Text = "⚙️ COMPORTEMENT ET ALERTES",
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                Location = new Point(25, 265),
                AutoSize = true,
                BackColor = Color.Transparent
            };

            _chkShowThreatPopup = new CheckBox
            {
                Text = "🚨 Afficher la fenêtre popup d'alerte lors d'une détection",
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                Location = new Point(25, 295),
                AutoSize = true,
                Checked = _showThreatPopup,
                BackColor = Color.Transparent
            };
            _chkShowThreatPopup.CheckedChanged += (s, e) => _showThreatPopup = _chkShowThreatPopup.Checked;

            _chkMinimizeToTray = new CheckBox
            {
                Text = "Réduire dans la zone de notification lors de la fermeture (croix rouge)",
                Font = new Font("Segoe UI", 9.5f),
                Location = new Point(25, 325),
                AutoSize = true,
                Checked = _minimizeToTrayOnClose,
                BackColor = Color.Transparent
            };
            _chkMinimizeToTray.CheckedChanged += (s, e) => _minimizeToTrayOnClose = _chkMinimizeToTray.Checked;

            _chkNotifications = new CheckBox
            {
                Text = "🔔 Activer les notifications système (popups toast)",
                Font = new Font("Segoe UI", 9.5f),
                Location = new Point(25, 355),
                AutoSize = true,
                Checked = _showNotifications,
                BackColor = Color.Transparent
            };
            _chkNotifications.CheckedChanged += (s, e) => _showNotifications = _chkNotifications.Checked;

            _btnManageExclusions = CreateStyledButton("🛡️ Gérer la liste des exclusions", new Point(25, 390), new Size(280, 40));
            _btnManageExclusions.Click += (s, e) => OpenExclusionsManager();

            _lblSystemGroup = new Label
            {
                Text = "⚠️ ARRÊT DU SERVICE",
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                Location = new Point(25, 445),
                AutoSize = true,
                BackColor = Color.Transparent
            };

            Button btnQuitApp = new Button
            {
                Text = "⛔ Quitter complètement AegisGuard",
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                BackColor = Color.FromArgb(198, 40, 40),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Location = new Point(25, 475),
                Size = new Size(290, 45),
                Cursor = Cursors.Hand,
                AutoEllipsis = true
            };
            btnQuitApp.FlatAppearance.BorderSize = 0;
            btnQuitApp.Click += (s, e) =>
            {
                if (MessageBox.Show("Voulez-vous vraiment fermer l'antivirus ? La protection en temps réel sera désactivée.", "Quitter AegisGuard", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes)
                {
                    ExitApplication();
                }
            };

            _settingsView.Controls.Add(_lblSettingsTitle);
            _settingsView.Controls.Add(_lblApparenceGroup);
            _settingsView.Controls.Add(_btnThemeToggle);
            _settingsView.Controls.Add(_btnPickTextColor);
            _settingsView.Controls.Add(_btnResetTextColor);
            _settingsView.Controls.Add(_chkDeepDark);
            _settingsView.Controls.Add(_lblOpacity);
            _settingsView.Controls.Add(_trkOpacity);
            _settingsView.Controls.Add(_lblOpacityValue);
            _settingsView.Controls.Add(_lblComportementGroup);
            _settingsView.Controls.Add(_chkShowThreatPopup);
            _settingsView.Controls.Add(_chkMinimizeToTray);
            _settingsView.Controls.Add(_chkNotifications);
            _settingsView.Controls.Add(_btnManageExclusions);
            _settingsView.Controls.Add(_lblSystemGroup);
            _settingsView.Controls.Add(btnQuitApp);
        }

        private void OpenExclusionsManager()
        {
            Form dlg = new Form
            {
                Text = "Gestion des Exclusions",
                Size = new Size(500, 400),
                StartPosition = FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false,
                BackColor = Color.FromArgb(30, 30, 35)
            };

            ListBox lstExclusions = new ListBox
            {
                Location = new Point(20, 20),
                Size = new Size(445, 260),
                BackColor = Color.FromArgb(20, 20, 25),
                ForeColor = Color.White
            };

            foreach (var ex in _scanner.GetExclusions())
            {
                lstExclusions.Items.Add(ex);
            }

            Button btnAdd = new Button { Text = "➕ Ajouter un fichier", Location = new Point(20, 295), Size = new Size(140, 35), FlatStyle = FlatStyle.Flat, ForeColor = Color.White };
            btnAdd.Click += (s, e) =>
            {
                using (OpenFileDialog ofd = new OpenFileDialog())
                {
                    if (ofd.ShowDialog() == DialogResult.OK)
                    {
                        _scanner.AddExclusion(ofd.FileName);
                        lstExclusions.Items.Add(ofd.FileName);
                    }
                }
            };

            Button btnRemove = new Button { Text = "❌ Retirer", Location = new Point(170, 295), Size = new Size(110, 35), FlatStyle = FlatStyle.Flat, ForeColor = Color.White };
            btnRemove.Click += (s, e) =>
            {
                if (lstExclusions.SelectedItem != null)
                {
                    string path = lstExclusions.SelectedItem.ToString()!;
                    _scanner.RemoveExclusion(path);
                    lstExclusions.Items.Remove(path);
                }
            };

            Button btnClose = new Button { Text = "Fermer", Location = new Point(355, 295), Size = new Size(110, 35), FlatStyle = FlatStyle.Flat, ForeColor = Color.White };
            btnClose.Click += (s, e) => dlg.Close();

            dlg.Controls.Add(lstExclusions);
            dlg.Controls.Add(btnAdd);
            dlg.Controls.Add(btnRemove);
            dlg.Controls.Add(btnClose);

            dlg.ShowDialog(this);
        }

        private void BtnPickTextColor_Click(object? sender, EventArgs e)
        {
            using (ColorDialog cd = new ColorDialog())
            {
                if (cd.ShowDialog() == DialogResult.OK)
                {
                    _customTextColor = cd.Color;
                    ApplyTheme();
                }
            }
        }

        private void Form1_Resize(object? sender, EventArgs e)
        {
            AdjustQuarantineColumns();
        }

        private void AdjustQuarantineColumns()
        {
            if (_lstQuarantine != null && _lstQuarantine.Columns.Count == 3)
            {
                int totalWidth = _lstQuarantine.ClientSize.Width;
                if (totalWidth > 400)
                {
                    _lstQuarantine.Columns[0].Width = 220;
                    _lstQuarantine.Columns[1].Width = 160;
                    _lstQuarantine.Columns[2].Width = totalWidth - 380;
                }
            }
        }

        #endregion

        #region Navigation & Thèmes

        private void SwitchView(Panel targetView, Button activeBtn)
        {
            _homeView.Visible = false;
            _quarantineView.Visible = false;
            _settingsView.Visible = false;

            targetView.Visible = true;

            Color activeBg;
            Color defaultBg;

            if (_isDarkMode)
            {
                activeBg = Color.FromArgb(45, 45, 48);
                defaultBg = _isDeepDark ? Color.FromArgb(22, 22, 22) : Color.FromArgb(30, 30, 30);
            }
            else
            {
                activeBg = Color.FromArgb(210, 210, 215);
                defaultBg = Color.FromArgb(240, 240, 240);
            }

            _btnNavHome.BackColor = (_btnNavHome == activeBtn) ? activeBg : defaultBg;
            _btnNavQuarantine.BackColor = (_btnNavQuarantine == activeBtn) ? activeBg : defaultBg;
            _btnNavSettings.BackColor = (_btnNavSettings == activeBtn) ? activeBg : defaultBg;

            if (targetView == _quarantineView) RefreshQuarantineList();
            if (targetView == _homeView) CenterHomeElements(_homeView.Width);
        }

        private void ApplyTheme()
        {
            Color defaultText = _isDarkMode ? Color.White : Color.FromArgb(20, 20, 20);
            Color effectiveTextColor = _customTextColor ?? defaultText;

            this.Opacity = _trkOpacity.Value / 100.0;
            _lblOpacityValue.Text = $"{_trkOpacity.Value}%";

            Color mainBg;
            Color sidebarBg;

            if (_isDarkMode)
            {
                if (_isDeepDark)
                {
                    mainBg = Color.FromArgb(15, 15, 15);
                    sidebarBg = Color.FromArgb(22, 22, 22);
                }
                else
                {
                    mainBg = Color.FromArgb(28, 28, 30);
                    sidebarBg = Color.FromArgb(38, 38, 40);
                }
            }
            else
            {
                mainBg = Color.FromArgb(245, 245, 247);
                sidebarBg = Color.FromArgb(230, 230, 235);
            }

            this.BackColor = mainBg;
            _sidebarPanel.BackColor = sidebarBg;
            _contentPanel.BackColor = mainBg;
            _homeView.BackColor = mainBg;
            _quarantineView.BackColor = mainBg;
            _settingsView.BackColor = mainBg;

            _chkDeepDark.Enabled = _isDarkMode;

            Color btnBg = _isDarkMode ? Color.FromArgb(45, 45, 48) : Color.FromArgb(220, 220, 225);

            SetControlsColor(_sidebarPanel, btnBg, effectiveTextColor);
            SetControlsColor(_homeView, btnBg, effectiveTextColor);
            SetControlsColor(_quarantineView, btnBg, effectiveTextColor);
            SetControlsColor(_settingsView, btnBg, effectiveTextColor);

            _lstQuarantine.BackColor = _isDarkMode ? Color.FromArgb(25, 25, 28) : Color.White;
            _lstQuarantine.ForeColor = effectiveTextColor;

            _btnThemeToggle.Text = _isDarkMode ? "☀️ Passage au Mode Clair" : "🌙 Passage au Mode Sombre";
            _lblNetworkStatusSidebar.ForeColor = _isOnline ? Color.FromArgb(76, 175, 80) : Color.FromArgb(244, 67, 54);

            SwitchView(_homeView.Visible ? _homeView : (_quarantineView.Visible ? _quarantineView : _settingsView),
                       _homeView.Visible ? _btnNavHome : (_quarantineView.Visible ? _btnNavQuarantine : _btnNavSettings));
            UpdateStatusUI();
        }

        private void SetControlsColor(Control parent, Color btnBg, Color text)
        {
            foreach (Control c in parent.Controls)
            {
                if (c == _lblNetworkStatusSidebar || c == _lblOfflineMsg) continue;

                if (c is Label lbl && c != _lblScanResult)
                {
                    lbl.ForeColor = text;
                    lbl.BackColor = Color.Transparent;
                }
                else if (c is CheckBox chk)
                {
                    chk.ForeColor = text;
                    chk.BackColor = Color.Transparent;
                }
                else if (c is Panel || c is FlowLayoutPanel)
                {
                    if (c != _pnlOfflineWarningHome && c != _statusHeader && c != _pnlScanBanner && c != _sidebarPanel)
                    {
                        c.BackColor = Color.Transparent;
                    }
                }
                else if (c is Button btn && !(c is RoundButton) && btn.BackColor != Color.FromArgb(198, 40, 40))
                {
                    btn.BackColor = btnBg;
                    btn.ForeColor = text;
                    btn.FlatAppearance.BorderColor = text;
                }

                if (c.HasChildren)
                {
                    SetControlsColor(c, btnBg, text);
                }
            }
        }

        #endregion

        #region Status Banners

        private enum StatusSeverity { Green, Orange, Red }

        private void ShowScanBanner(string message, StatusSeverity severity)
        {
            _lblScanResult.Text = message;

            switch (severity)
            {
                case StatusSeverity.Green:
                    _pnlScanBanner.BackColor = Color.FromArgb(46, 125, 50);
                    break;
                case StatusSeverity.Orange:
                    _pnlScanBanner.BackColor = Color.FromArgb(230, 81, 0);
                    break;
                case StatusSeverity.Red:
                    _pnlScanBanner.BackColor = Color.FromArgb(198, 40, 40);
                    break;
            }

            _pnlScanBanner.Visible = true;
        }

        #endregion

        #region Scan Logic

        private async void BtnBigScan_Click(object? sender, EventArgs e)
        {
            Cursor = Cursors.WaitCursor;
            _btnBigScan.Enabled = false;
            _pnlScanBanner.Visible = false;

            string[] targetFolders = new string[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
            };

            int totalScanned = 0;
            List<ScanResult> threatsFound = new List<ScanResult>();

            await Task.Run(async () =>
            {
                foreach (string folder in targetFolders)
                {
                    if (Directory.Exists(folder))
                    {
                        var files = Directory.GetFiles(folder, "*.*", SearchOption.AllDirectories);
                        foreach (var file in files)
                        {
                            totalScanned++;
                            ScanResult res = await _scanner.ScanFileAsync(file);
                            if (res.IsInfected)
                            {
                                threatsFound.Add(res);
                            }
                        }
                    }
                }
            });

            Cursor = Cursors.Default;
            _btnBigScan.Enabled = true;

            if (threatsFound.Count > 0)
            {
                foreach (var threat in threatsFound)
                {
                    _quarantine.QuarantineFile(threat.FilePath, out _);
                }
                RefreshQuarantineList();
                ShowScanBanner($"⚠️ MENACE DÉTECTÉE ! {threatsFound.Count} fichier(s) infecté(s) mis en quarantaine.", StatusSeverity.Red);
            }
            else
            {
                ShowScanBanner($"✅ SYSTÈME PROTÉGÉ : {totalScanned} fichiers analysés. Aucune menace.", StatusSeverity.Green);
            }
        }

        private async void BtnScanFile_Click(object? sender, EventArgs e)
        {
            using (OpenFileDialog ofd = new OpenFileDialog())
            {
                ofd.Title = "Sélectionnez un fichier à analyser";
                ofd.Filter = "Tous les fichiers (*.*)|*.*";

                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    _pnlScanBanner.Visible = false;
                    _btnScanFile.Enabled = false;
                    Cursor = Cursors.WaitCursor;

                    ScanResult result = await _scanner.ScanFileAsync(ofd.FileName);

                    Cursor = Cursors.Default;
                    _btnScanFile.Enabled = true;

                    if (result.IsInfected)
                    {
                        _quarantine.QuarantineFile(result.FilePath, out _);
                        RefreshQuarantineList();
                        string mode = result.ScannedViaCloud ? "[Cloud VT]" : "[Local]";
                        ShowScanBanner($"🚨 FICHIER INFECTÉ ! '{Path.GetFileName(ofd.FileName)}' ({result.ThreatName}) {mode} a été isolé.", StatusSeverity.Red);
                    }
                    else
                    {
                        ShowScanBanner($"✅ FICHIER SAIN : '{Path.GetFileName(ofd.FileName)}' ne présente aucun risque.", StatusSeverity.Green);
                    }
                }
            }
        }

        private async void BtnScanFolder_Click(object? sender, EventArgs e)
        {
            using (FolderBrowserDialog fbd = new FolderBrowserDialog())
            {
                if (fbd.ShowDialog() == DialogResult.OK)
                {
                    _pnlScanBanner.Visible = false;
                    _btnScanFolder.Enabled = false;
                    Cursor = Cursors.WaitCursor;

                    int filesCount = 0;
                    List<ScanResult> threatsFound = new List<ScanResult>();

                    await Task.Run(async () =>
                    {
                        if (Directory.Exists(fbd.SelectedPath))
                        {
                            var files = Directory.GetFiles(fbd.SelectedPath, "*.*", SearchOption.AllDirectories);
                            filesCount = files.Length;
                            foreach (var file in files)
                            {
                                ScanResult res = await _scanner.ScanFileAsync(file);
                                if (res.IsInfected)
                                {
                                    threatsFound.Add(res);
                                }
                            }
                        }
                    });

                    Cursor = Cursors.Default;
                    _btnScanFolder.Enabled = true;

                    if (threatsFound.Count > 0)
                    {
                        foreach (var threat in threatsFound)
                        {
                            _quarantine.QuarantineFile(threat.FilePath, out _);
                        }
                        RefreshQuarantineList();
                        ShowScanBanner($"⚠️ ALERTE : {threatsFound.Count} menace(s) isolée(s) dans le dossier.", StatusSeverity.Red);
                    }
                    else if (filesCount == 0)
                    {
                        ShowScanBanner($"🟧 DOSSIER VIDE OU ACCÈS RESTREINT : Aucun fichier analysable.", StatusSeverity.Orange);
                    }
                    else
                    {
                        ShowScanBanner($"✅ DOSSIER PROPRE : {filesCount} fichiers vérifiés sans menace.", StatusSeverity.Green);
                    }
                }
            }
        }

        private void ToggleRealTimeProtection()
        {
            if (_realTimeWatcher.IsRunning) _realTimeWatcher.Stop();
            else _realTimeWatcher.StartAllDrives();
            UpdateStatusUI();
        }

        private void UpdateStatusUI()
        {
            if (_realTimeWatcher.IsRunning)
            {
                _statusHeader.BackColor = Color.FromArgb(46, 125, 50);
                _lblStatusTitle.Text = "Votre appareil est protégé";
                _lblStatusDesc.Text = "La protection en temps réel AegisGuard est active.";
                _btnToggleProtection.Text = "🛡️ Désactiver protection";

                if (_menuToggleProtection != null)
                    _menuToggleProtection.Text = "Désactiver la protection en temps réel";

                if (_notifyIcon != null)
                    _notifyIcon.Text = "AegisGuard - Protection Active";
            }
            else
            {
                _statusHeader.BackColor = Color.FromArgb(198, 40, 40);
                _lblStatusTitle.Text = "Protection désactivée";
                _lblStatusDesc.Text = "Votre appareil n'est plus surveillé en temps réel.";
                _btnToggleProtection.Text = "🛡️ Activer protection";

                if (_menuToggleProtection != null)
                    _menuToggleProtection.Text = "Activer la protection en temps réel";

                if (_notifyIcon != null)
                    _notifyIcon.Text = "AegisGuard - Protection Inactive";
            }
        }

        #endregion

        #region Quarantine & System Tray

        private void SetupQuarantineContextMenu()
        {
            _quarantineContextMenu = new ContextMenuStrip();
            _quarantineContextMenu.Items.Add("🔄 Restaurer le fichier", null, (s, e) => RestoreSelectedQuarantineFile());
            _quarantineContextMenu.Items.Add("❌ Supprimer définitivement", null, (s, e) => DeleteSelectedQuarantineFile());

            _lstQuarantine.ContextMenuStrip = _quarantineContextMenu;
        }

        private void RefreshQuarantineList()
        {
            _lstQuarantine.Items.Clear();

            // Pointe sur C:\ProgramData\AegisGuard\Quarantine
            string commonAppData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string quarantinePath = Path.Combine(commonAppData, "AegisGuard", "Quarantine");

            if (Directory.Exists(quarantinePath))
            {
                string[] files = Directory.GetFiles(quarantinePath, "*.locked");
                foreach (string file in files)
                {
                    FileInfo fi = new FileInfo(file);
                    string originalPath = "Non enregistré";

                    string metaFile = file + ".meta";
                    if (File.Exists(metaFile))
                    {
                        try { originalPath = File.ReadAllText(metaFile); } catch { }
                    }

                    ListViewItem item = new ListViewItem(fi.Name) { Tag = file };
                    item.SubItems.Add(fi.CreationTime.ToString("g"));
                    item.SubItems.Add(originalPath);

                    item.ToolTipText = $"Nom : {fi.Name}\nDétecté le : {fi.CreationTime:g}\nChemin d'origine : {originalPath}";

                    _lstQuarantine.Items.Add(item);
                }
            }
            AdjustQuarantineColumns();
        }

        private void RestoreSelectedQuarantineFile()
        {
            if (_lstQuarantine.SelectedItems.Count == 0) return;

            ListViewItem item = _lstQuarantine.SelectedItems[0];
            string lockedFilePath = item.Tag?.ToString() ?? string.Empty;

            DialogResult choice = MessageBox.Show(
                "Voulez-vous également ajouter ce fichier à la liste des EXCLUSIONS pour éviter que l'antivirus ne le resupprime immédiatement ?",
                "Restauration & Exclusions",
                MessageBoxButtons.YesNoCancel,
                MessageBoxIcon.Question
            );

            if (choice == DialogResult.Cancel) return;

            if (_quarantine.RestoreFile(lockedFilePath, out string originalPath))
            {
                if (choice == DialogResult.Yes)
                {
                    _scanner.AddExclusion(originalPath);
                }

                MessageBox.Show($"Le fichier a été restauré avec succès vers :\n{originalPath}", "Restauration réussie", MessageBoxButtons.OK, MessageBoxIcon.Information);
                RefreshQuarantineList();
            }
            else
            {
                MessageBox.Show("Erreur lors de la restauration du fichier.", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void DeleteSelectedQuarantineFile()
        {
            if (_lstQuarantine.SelectedItems.Count == 0) return;

            ListViewItem item = _lstQuarantine.SelectedItems[0];
            string lockedFilePath = item.Tag?.ToString() ?? string.Empty;

            if (MessageBox.Show("Voulez-vous vraiment supprimer définitivement ce fichier ?", "Confirmation", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes)
            {
                if (_quarantine.DeleteFile(lockedFilePath))
                {
                    RefreshQuarantineList();
                }
            }
        }

        private void SetupSystemTray()
        {
            _trayMenu = new ContextMenuStrip();

            _menuToggleProtection = new ToolStripMenuItem("Désactiver la protection en temps réel", null, (s, e) => ToggleRealTimeProtection());

            _trayMenu.Items.Add("Ouvrir AegisGuard", null, (s, e) => ShowWindow());
            _trayMenu.Items.Add(_menuToggleProtection);
            _trayMenu.Items.Add("-");
            _trayMenu.Items.Add("Quitter complètement", null, (s, e) => ExitApplication());

            _notifyIcon = new NotifyIcon
            {
                Icon = SystemIcons.Shield,
                Text = "AegisGuard - Protection Active",
                ContextMenuStrip = _trayMenu,
                Visible = true
            };

            _notifyIcon.DoubleClick += (s, e) => ShowWindow();
        }

        private void ShowWindow()
        {
            this.Show();
            this.WindowState = FormWindowState.Normal;
            this.BringToFront();
        }

        private void ExitApplication()
        {
            _isExiting = true;
            Application.Exit();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (!_isExiting && e.CloseReason == CloseReason.UserClosing && _minimizeToTrayOnClose)
            {
                e.Cancel = true;
                this.Hide();

                // Affiche la notification uniquement si l'option est cochée dans les paramètres
                if (_showNotifications && _notifyIcon != null)
                {
                    _notifyIcon.ShowBalloonTip(
                        2000,
                        "AegisGuard",
                        "L'antivirus continue de tourner en arrière-plan.",
                        ToolTipIcon.Info
                    );
                }
            }
            else
            {
                base.OnFormClosing(e);
            }
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            _networkTimer?.Stop();
            _realTimeWatcher?.Stop();
            if (_notifyIcon != null)
            {
                _notifyIcon.Visible = false;
                _notifyIcon.Dispose();
            }
            base.OnFormClosed(e);
        }

        #endregion
    }

    #region Threat Popup Form (Style Avast Redessiné)

    public class ThreatPopupForm : Form
    {
        public ThreatPopupForm(string filePath, string threatName, Action openQuarantineCallback)
        {
            this.Text = "AegisGuard - Menace Bloquée";
            this.Size = new Size(680, 520);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.FormBorderStyle = FormBorderStyle.FixedSingle;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.ShowInTaskbar = true;
            this.TopMost = true;
            this.BackColor = Color.FromArgb(20, 29, 47); // Fond bleu nuit inspiré d'Avast
            try
            {
                if (Properties.Resources.security_guard_shield_icon_153085 != null)
                {
                    using (var ms = new MemoryStream(Properties.Resources.security_guard_shield_icon_153085))
                    {
                        this.Icon = new Icon(ms);
                    }
                }
            }
            catch
            {
                this.Icon = SystemIcons.Shield;
            }

            // En-tête de marque
            Panel headerPanel = new Panel
            {
                Dock = DockStyle.Top,
                Height = 45,
                BackColor = Color.FromArgb(15, 23, 38)
            };

            Label lblBrand = new Label
            {
                Text = "🛡️  AegisGuard Security",
                Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(255, 152, 0),
                Location = new Point(18, 12),
                AutoSize = true,
                BackColor = Color.Transparent
            };
            headerPanel.Controls.Add(lblBrand);

            // Graphique central (Dossier avec badge d'alerte rouge)
            Panel graphicPanel = new Panel
            {
                Size = new Size(110, 95),
                Location = new Point((this.ClientSize.Width - 110) / 2, 60),
                BackColor = Color.Transparent
            };

            Label lblFolderIcon = new Label
            {
                Text = "📁",
                Font = new Font("Segoe UI", 48f),
                Location = new Point(0, -10),
                Size = new Size(100, 80),
                TextAlign = ContentAlignment.MiddleCenter,
                BackColor = Color.Transparent
            };

            Label lblBadge = new Label
            {
                Text = "❗",
                Font = new Font("Segoe UI", 16f, FontStyle.Bold),
                ForeColor = Color.White,
                BackColor = Color.FromArgb(220, 38, 38),
                Size = new Size(32, 32),
                Location = new Point(65, 45),
                TextAlign = ContentAlignment.MiddleCenter
            };
            lblBadge.Paint += (s, pe) =>
            {
                using (var path = new GraphicsPath())
                {
                    path.AddEllipse(0, 0, lblBadge.Width - 1, lblBadge.Height - 1);
                    lblBadge.Region = new Region(path);
                }
            };

            graphicPanel.Controls.Add(lblBadge);
            graphicPanel.Controls.Add(lblFolderIcon);

            // Titre d'alerte principal
            Label lblMainTitle = new Label
            {
                Text = "Menace bloquée",
                Font = new Font("Segoe UI", 18f, FontStyle.Bold),
                ForeColor = Color.White,
                Location = new Point(0, 162),
                Size = new Size(this.ClientSize.Width, 38),
                TextAlign = ContentAlignment.MiddleCenter,
                BackColor = Color.Transparent
            };

            // Description corrigée (hauteur et marge adaptées pour ne plus couper le texte)
            string fileNameOnly = Path.GetFileName(filePath);
            Label lblMainDesc = new Label
            {
                Text = $"Nous avons bloqué le fichier '{fileNameOnly}' car il a été identifié comme étant infecté par {threatName}.",
                Font = new Font("Segoe UI", 10f),
                ForeColor = Color.FromArgb(200, 210, 225),
                Location = new Point(30, 200),
                Size = new Size(this.ClientSize.Width - 60, 55),
                TextAlign = ContentAlignment.TopCenter,
                BackColor = Color.Transparent
            };

            // Panneau de détails du fichier
            Panel detailsPanel = new Panel
            {
                Location = new Point(45, 260),
                Size = new Size(575, 120),
                BackColor = Color.FromArgb(14, 21, 35),
                BorderStyle = BorderStyle.None
            };

            Label lblDetailThreat = new Label
            {
                Text = $"⚠️  Menace :  {threatName}",
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(244, 67, 54),
                Location = new Point(15, 12),
                AutoSize = true,
                BackColor = Color.Transparent
            };

            // Chemin d'origine détaillé (autorise 2 lignes si le chemin est très long)
            Label lblDetailPath = new Label
            {
                Text = $"📄  Emplacement d'origine :  {filePath}",
                Font = new Font("Segoe UI", 8.5f),
                ForeColor = Color.Gainsboro,
                Location = new Point(15, 39),
                Size = new Size(545, 32),
                AutoEllipsis = true,
                BackColor = Color.Transparent
            };

            Label lblDetailTime = new Label
            {
                Text = $"🕒  Date de détection :  {DateTime.Now:dd/MM/yyyy à HH:mm:ss}",
                Font = new Font("Segoe UI", 9f),
                ForeColor = Color.Gainsboro,
                Location = new Point(15, 68), // Modifié de 63 à 68
                AutoSize = true,
                BackColor = Color.Transparent
            };

            Label lblDetailStatus = new Label
            {
                Text = $"🔒  Action automatique :  Fichier déplacé vers la Quarantaine sécurisée",
                Font = new Font("Segoe UI", 9f, FontStyle.Italic),
                ForeColor = Color.FromArgb(76, 175, 80),
                Location = new Point(15, 92), // Modifié de 88 à 92
                AutoSize = true,
                BackColor = Color.Transparent
            };

            detailsPanel.Controls.Add(lblDetailThreat);
            detailsPanel.Controls.Add(lblDetailPath);
            detailsPanel.Controls.Add(lblDetailTime);
            detailsPanel.Controls.Add(lblDetailStatus);

            // Boutons d'action
            Button btnQuarantine = new Button
            {
                Text = "VOIR EN QUARANTAINE",
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                BackColor = Color.FromArgb(0, 150, 75), // Vert Avast
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Location = new Point(45, 400),
                Size = new Size(330, 48),
                Cursor = Cursors.Hand
            };
            btnQuarantine.FlatAppearance.BorderSize = 0;
            btnQuarantine.Click += (s, e) =>
            {
                openQuarantineCallback?.Invoke();
                this.Close();
            };

            Button btnClose = new Button
            {
                Text = "FERMER",
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                BackColor = Color.FromArgb(28, 40, 62),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Location = new Point(390, 400),
                Size = new Size(230, 48),
                Cursor = Cursors.Hand
            };
            btnClose.FlatAppearance.BorderSize = 0;
            btnClose.Click += (s, e) => this.Close();

            // Ajout des contrôles à la boîte de dialogue
            this.Controls.Add(headerPanel);
            this.Controls.Add(graphicPanel);
            this.Controls.Add(lblMainTitle);
            this.Controls.Add(lblMainDesc);
            this.Controls.Add(detailsPanel);
            this.Controls.Add(btnQuarantine);
            this.Controls.Add(btnClose);
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            this.Activate();
            this.Focus();
        }
    }

    #endregion

    #region RoundButton Custom Control

    public class RoundButton : Button
    {
        protected override void OnPaint(PaintEventArgs pevent)
        {
            GraphicsPath path = new GraphicsPath();
            path.AddEllipse(0, 0, ClientSize.Width, ClientSize.Height);
            this.Region = new Region(path);

            pevent.Graphics.SmoothingMode = SmoothingMode.AntiAlias;

            Color btnColor = Enabled ? Color.FromArgb(0, 122, 204) : Color.Gray;
            using (SolidBrush brush = new SolidBrush(btnColor))
            {
                pevent.Graphics.FillEllipse(brush, 0, 0, ClientSize.Width, ClientSize.Height);
            }

            TextRenderer.DrawText(
                pevent.Graphics,
                Text,
                Font,
                ClientRectangle,
                ForeColor,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        }
    }

    #endregion
}