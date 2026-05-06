using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace Obscurize
{
    // ============================================================
    //  MainWindow – Obscurize Control Panel
    //
    //  Entirely code-driven WinForms form – no .designer.cs or
    //  RESX dependency.  Closing hides the window; the process
    //  lives on in the system tray until the user selects Exit.
    //
    //  Layout (480 × 590 client area):
    //
    //   ┌──────────────────────────────────────────┐
    //   │  HEADER  (logo + status badge)           │ 64 px
    //   ├──────────────────────────────────────────┤
    //   │  POWER BUTTON  (big toggle)              │ 72 px
    //   ├──────────────────────────────────────────┤
    //   │  MODE SELECTOR  (Defensive | Trap)       │ 56 px
    //   ├──────────────────────────────────────────┤
    //   │  SPOOF STATUS PANEL  (8 rows × 28 px)   │ 240 px
    //   ├──────────────────────────────────────────┤
    //   │  LOG  (scrolling RichTextBox)            │ 158 px
    //   └──────────────────────────────────────────┘
    // ============================================================

    internal sealed class MainWindow : Form
    {
        // ── Palette ───────────────────────────────────────────────
        private static readonly Color ColBackground  = Color.FromArgb(18,  18,  28);
        private static readonly Color ColPanel       = Color.FromArgb(28,  28,  44);
        private static readonly Color ColAccentBlue  = Color.FromArgb(52, 120, 240);
        private static readonly Color ColAccentAmber = Color.FromArgb(220, 130,  20);
        private static readonly Color ColSuccess      = Color.FromArgb( 80, 200, 120);
        private static readonly Color ColMuted        = Color.FromArgb(100, 100, 130);
        private static readonly Color ColText         = Color.FromArgb(230, 230, 240);
        private static readonly Color ColTextDim      = Color.FromArgb(140, 140, 160);
        private static readonly Color ColBorder       = Color.FromArgb( 50,  50,  70);
        private static readonly Color ColDanger       = Color.FromArgb(220,  70,  70);

        // ── Controls ──────────────────────────────────────────────
        private readonly Label        _lblStatusBadge;
        private readonly PowerButton  _btnPower;
        private readonly ModeButton   _btnDefensive;
        private readonly ModeButton   _btnTrap;
        private readonly ModeButton   _btnDomainOff;
        private readonly ModeButton   _btnDomainWorkgroup;
        private readonly ModeButton   _btnDomainJoined;
        private readonly Panel        _spoofPanel;
        private readonly SpoofRow[]   _spoofRows;
        private readonly RichTextBox  _rtbLog;

        // ── State ─────────────────────────────────────────────────
        private ServiceStatus _currentStatus  = ServiceStatus.ServiceOffline;
        private int           _domainMode     = ObscurizeConst.DomainModeOff;

        // Spoof row definitions (label, Defensive value, Trap value)
        private static readonly (string Label, string Defensive, string Trap)[] SpoofDefs =
        {
            ("Username",           "admin",                 ObscurizeConst.TrapUsernameDefault),
            ("Computer Name",      ObscurizeConst.DefComputerName, ObscurizeConst.TrapCompNameDefault),
            ("RAM Reported",       $"{ObscurizeConst.DefMemoryMB / 1024} GB",  $"{ObscurizeConst.TrapMemoryMB / 1024} GB"),
            ("Screen Resolution",  $"{ObscurizeConst.DefScreenWidth}×{ObscurizeConst.DefScreenHeight}", $"{ObscurizeConst.TrapScreenWidth}×{ObscurizeConst.TrapScreenHeight}"),
            ("MAC Address OUI",    "00:0C:29  (VMware)",   "00:1B:21  (Intel)"),
            ("BIOS Manufacturer",  ObscurizeConst.DefManufacturer, ObscurizeConst.TrapManufacturer),
            ("VM Processes",       "Visible (vmtoolsd…)",  "Hidden"),
            ("VM Services",        "Visible (VMTools…)",   "Hidden"),
            // Domain row: _trapValue = domain-active string; handled specially in SetSpoofRowsActive
            ("Domain",             $"{ObscurizeConst.SpoofDomainInactive}  (PartOfDomain: False)",
                                   $"{ObscurizeConst.SpoofDomainActive}  (PartOfDomain: True)"),
        };

        // ─────────────────────────────────────────────────────────

        internal MainWindow()
        {
            // ── Form properties ───────────────────────────────────
            Text            = "Obscurize – Control Panel";
            ClientSize      = new Size(480, 659);
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox     = false;
            BackColor       = ColBackground;
            StartPosition   = FormStartPosition.CenterScreen;
            Font            = new Font("Segoe UI", 9f, FontStyle.Regular, GraphicsUnit.Point);
            ShowInTaskbar   = true;
            Icon            = TrayIconRenderer.CreateShieldIcon(ShieldState.Inactive);

            // Hide to tray on close instead of exiting.
            FormClosing += (_, e) =>
            {
                e.Cancel = true;
                Hide();
            };

            int y = 0;

            // ── Header ────────────────────────────────────────────
            Panel pnlHeader = MakePanel(0, y, 480, 64, ColPanel);
            y += 64;

            Label lblTitle = new()
            {
                Text      = "OBSCURIZE",
                Font      = new Font("Segoe UI", 16f, FontStyle.Bold, GraphicsUnit.Point),
                ForeColor = ColText,
                AutoSize  = false,
                Bounds    = new Rectangle(16, 16, 220, 32),
                TextAlign = ContentAlignment.MiddleLeft,
                BackColor = Color.Transparent,
            };

            _lblStatusBadge = new Label
            {
                Font      = new Font("Segoe UI", 8f, FontStyle.Bold, GraphicsUnit.Point),
                ForeColor = Color.Black,
                AutoSize  = false,
                Bounds    = new Rectangle(380, 22, 84, 20),
                TextAlign = ContentAlignment.MiddleCenter,
                BackColor = ColMuted,
                Text      = "OFFLINE",
            };
            RoundCorners(_lblStatusBadge, 4);

            pnlHeader.Controls.Add(lblTitle);
            pnlHeader.Controls.Add(_lblStatusBadge);
            Controls.Add(pnlHeader);

            AddSeparator(y); y += 1;

            // ── Power button ──────────────────────────────────────
            Panel pnlPower = MakePanel(0, y, 480, 72, ColBackground);
            y += 72;

            _btnPower = new PowerButton
            {
                Bounds   = new Rectangle(160, 12, 160, 48),
                TabIndex = 0,
            };
            _btnPower.Click += OnPowerClick;

            pnlPower.Controls.Add(_btnPower);
            Controls.Add(pnlPower);

            AddSeparator(y); y += 1;

            // ── Mode selector ─────────────────────────────────────
            Panel pnlMode = MakePanel(0, y, 480, 56, ColBackground);
            y += 56;

            Label lblMode = new()
            {
                Text      = "MODE",
                Font      = new Font("Segoe UI", 7.5f, FontStyle.Bold, GraphicsUnit.Point),
                ForeColor = ColMuted,
                AutoSize  = false,
                Bounds    = new Rectangle(16, 8, 60, 16),
                TextAlign = ContentAlignment.MiddleLeft,
                BackColor = Color.Transparent,
            };

            _btnDefensive = new ModeButton("Defensive", ColAccentBlue)
            {
                Bounds   = new Rectangle(80,  8, 170, 40),
                TabIndex = 1,
            };
            _btnTrap = new ModeButton("Trap", ColAccentAmber)
            {
                Bounds   = new Rectangle(260, 8, 170, 40),
                TabIndex = 2,
            };

            _btnDefensive.Click += (_, _) => ControlPipeClient.Send(ObscurizeConst.CtrlSetModeDefensive);
            _btnTrap.Click      += (_, _) => ControlPipeClient.Send(ObscurizeConst.CtrlSetModeTrap);

            pnlMode.Controls.Add(lblMode);
            pnlMode.Controls.Add(_btnDefensive);
            pnlMode.Controls.Add(_btnTrap);
            Controls.Add(pnlMode);

            AddSeparator(y); y += 1;

            // ── Domain mode selector ───────────────────────────────
            Panel pnlDomain = MakePanel(0, y, 480, 40, ColBackground);
            y += 40;

            Label lblDomain = new()
            {
                Text      = "DOMAIN",
                Font      = new Font("Segoe UI", 7.5f, FontStyle.Bold, GraphicsUnit.Point),
                ForeColor = ColMuted,
                AutoSize  = false,
                Bounds    = new Rectangle(16, 12, 60, 16),
                TextAlign = ContentAlignment.MiddleLeft,
                BackColor = Color.Transparent,
            };

            _btnDomainOff = new ModeButton("Off", ColMuted)
            {
                Bounds   = new Rectangle(80,  4, 128, 32),
                TabIndex = 3,
            };
            _btnDomainWorkgroup = new ModeButton("Workgroup", ColAccentAmber)
            {
                Bounds   = new Rectangle(212, 4, 128, 32),
                TabIndex = 4,
            };
            _btnDomainJoined = new ModeButton("Joined", ColSuccess)
            {
                Bounds   = new Rectangle(344, 4, 128, 32),
                TabIndex = 5,
            };

            _btnDomainOff.Click      += (_, _) => OnDomainModeClick(ObscurizeConst.DomainModeOff);
            _btnDomainWorkgroup.Click += (_, _) => OnDomainModeClick(ObscurizeConst.DomainModeWorkgroup);
            _btnDomainJoined.Click    += (_, _) => OnDomainModeClick(ObscurizeConst.DomainModeJoined);

            pnlDomain.Controls.Add(lblDomain);
            pnlDomain.Controls.Add(_btnDomainOff);
            pnlDomain.Controls.Add(_btnDomainWorkgroup);
            pnlDomain.Controls.Add(_btnDomainJoined);
            Controls.Add(pnlDomain);

            AddSeparator(y); y += 1;

            // ── Spoof status panel ────────────────────────────────
            Label lblSpoofs = new()
            {
                Text      = "ACTIVE SPOOFS",
                Font      = new Font("Segoe UI", 7.5f, FontStyle.Bold, GraphicsUnit.Point),
                ForeColor = ColMuted,
                AutoSize  = false,
                Bounds    = new Rectangle(16, y + 6, 120, 16),
                TextAlign = ContentAlignment.MiddleLeft,
                BackColor = ColBackground,
            };
            Controls.Add(lblSpoofs);
            y += 24;

            _spoofPanel = MakePanel(0, y, 480, SpoofDefs.Length * 28 + 4, ColPanel);
            y += _spoofPanel.Height;

            _spoofRows = new SpoofRow[SpoofDefs.Length];
            for (int i = 0; i < SpoofDefs.Length; i++)
            {
                _spoofRows[i] = new SpoofRow(
                    SpoofDefs[i].Label,
                    SpoofDefs[i].Defensive,
                    SpoofDefs[i].Trap)
                {
                    Bounds = new Rectangle(0, i * 28, 480, 28),
                };
                _spoofPanel.Controls.Add(_spoofRows[i]);
            }
            Controls.Add(_spoofPanel);

            AddSeparator(y); y += 1;

            // ── Log ───────────────────────────────────────────────
            Label lblLog = new()
            {
                Text      = "LOG",
                Font      = new Font("Segoe UI", 7.5f, FontStyle.Bold, GraphicsUnit.Point),
                ForeColor = ColMuted,
                AutoSize  = false,
                Bounds    = new Rectangle(16, y + 5, 40, 14),
                TextAlign = ContentAlignment.MiddleLeft,
                BackColor = ColBackground,
            };
            Controls.Add(lblLog);
            y += 22;

            _rtbLog = new RichTextBox
            {
                Bounds         = new Rectangle(0, y, 480, ClientSize.Height - y),
                BackColor      = ColPanel,
                ForeColor      = ColTextDim,
                Font           = new Font("Consolas", 8.5f, FontStyle.Regular, GraphicsUnit.Point),
                ReadOnly       = true,
                BorderStyle    = BorderStyle.None,
                ScrollBars     = RichTextBoxScrollBars.Vertical,
                WordWrap       = false,
                DetectUrls     = false,
            };
            Controls.Add(_rtbLog);

            // ── Initial state ─────────────────────────────────────
            // Sync domain mode buttons with whatever is already in the registry.
            try
            {
                using var regKey = Microsoft.Win32.Registry.LocalMachine
                    .OpenSubKey(ObscurizeConst.ConfigKey, writable: false);
                if (regKey?.GetValue(ObscurizeConst.ConfigValueDomainMode) is int domVal
                    && domVal >= ObscurizeConst.DomainModeOff
                    && domVal <= ObscurizeConst.DomainModeJoined)
                {
                    _domainMode = domVal;
                }
            }
            catch { /* registry not yet created – leave default Off */ }
            UpdateDomainButtonSelection();

            StatusPoller.Current.StatusChanged += (_, s) => this.Invoke(new Action(() => UpdateStatus(s)));
            // Sync with whatever the poller already knows – avoids the race where
            // the poller transitions from ServiceOffline → ActiveDefensive before
            // this handler is registered, leaving the window stuck on INACTIVE.
            UpdateStatus(StatusPoller.Current.LastStatus);

            AppendLog("Control panel opened.", ColTextDim);
            AppendLog("Polling service status…", ColTextDim);
        }

        // ── Status update ─────────────────────────────────────────

        internal void UpdateStatus(ServiceStatus status)
        {
            if (InvokeRequired) { Invoke(new Action(() => UpdateStatus(status))); return; }

            _currentStatus = status;

            switch (status)
            {
                case ServiceStatus.ServiceOffline:
                    _lblStatusBadge.Text      = "OFFLINE";
                    _lblStatusBadge.BackColor = ColDanger;
                    _btnPower.SetState(false, ColMuted);
                    SetModeButtonsEnabled(false);
                    SetSpoofRowsActive(false, false);
                    break;

                case ServiceStatus.Disabled:
                    _lblStatusBadge.Text      = "DISABLED";
                    _lblStatusBadge.BackColor = ColMuted;
                    _btnPower.SetState(false, ColMuted);
                    SetModeButtonsEnabled(true);
                    SetSpoofRowsActive(false, false);
                    break;

                case ServiceStatus.ActiveDefensive:
                    _lblStatusBadge.Text      = "DEFENSIVE";
                    _lblStatusBadge.BackColor = ColAccentBlue;
                    _btnPower.SetState(true, ColAccentBlue);
                    _btnDefensive.SetSelected(true);
                    _btnTrap.SetSelected(false);
                    SetModeButtonsEnabled(true);
                    SetSpoofRowsActive(true, false);
                    break;

                case ServiceStatus.ActiveTrap:
                    _lblStatusBadge.Text      = "TRAP";
                    _lblStatusBadge.BackColor = ColAccentAmber;
                    _btnPower.SetState(true, ColAccentAmber);
                    _btnDefensive.SetSelected(false);
                    _btnTrap.SetSelected(true);
                    SetModeButtonsEnabled(true);
                    SetSpoofRowsActive(true, true);
                    break;
            }
        }

        // ── Power button handler ──────────────────────────────────

        private void OnPowerClick(object? sender, EventArgs e)
        {
            bool isEnabled = _currentStatus == ServiceStatus.ActiveDefensive
                          || _currentStatus == ServiceStatus.ActiveTrap;

            if (isEnabled)
            {
                bool sent = ControlPipeClient.Send(ObscurizeConst.CtrlDisable);
                AppendLog(sent ? "Sent: Disable" : "Failed to contact service.", sent ? ColTextDim : ColDanger);
            }
            else
            {
                bool sent = ControlPipeClient.Send(ObscurizeConst.CtrlEnable);
                AppendLog(sent ? "Sent: Enable" : "Failed to contact service.", sent ? ColTextDim : ColDanger);
            }
        }

        // ── Domain mode button handler ────────────────────────────

        private void OnDomainModeClick(int newMode)
        {
            if (newMode == _domainMode) return;

            int ctrlCode = newMode switch
            {
                ObscurizeConst.DomainModeJoined    => ObscurizeConst.CtrlDomainJoined,
                ObscurizeConst.DomainModeWorkgroup  => ObscurizeConst.CtrlDomainWorkgroup,
                _                                   => ObscurizeConst.CtrlDomainOff,
            };

            bool sent = ControlPipeClient.Send(ctrlCode);
            if (sent) _domainMode = newMode;

            UpdateDomainButtonSelection();

            bool isActive = _currentStatus == ServiceStatus.ActiveDefensive
                         || _currentStatus == ServiceStatus.ActiveTrap;
            _spoofRows[SpoofDefs.Length - 1].SetActive(
                isActive && _domainMode != ObscurizeConst.DomainModeOff,
                _domainMode == ObscurizeConst.DomainModeJoined);

            string modeLabel = newMode switch
            {
                ObscurizeConst.DomainModeJoined    => $"Joined → {ObscurizeConst.SpoofDomainActive}",
                ObscurizeConst.DomainModeWorkgroup  => "Workgroup → WORKGROUP",
                _                                   => "Off (pass-through)",
            };
            AppendLog(sent ? $"Sent: Domain {modeLabel}" : "Failed to contact service.",
                      sent ? ColTextDim : ColDanger);
        }

        private void UpdateDomainButtonSelection()
        {
            _btnDomainOff.SetSelected(_domainMode == ObscurizeConst.DomainModeOff);
            _btnDomainWorkgroup.SetSelected(_domainMode == ObscurizeConst.DomainModeWorkgroup);
            _btnDomainJoined.SetSelected(_domainMode == ObscurizeConst.DomainModeJoined);
        }

        // ── Spoof row state helpers ───────────────────────────────

        private void SetSpoofRowsActive(bool active, bool trapMode)
        {
            for (int i = 0; i < _spoofRows.Length - 1; i++)
                _spoofRows[i].SetActive(active, trapMode);

            // Domain row: active only when domain spoofing is on (mode ≠ Off).
            // trapMode=true shows the Joined ("CORP.DEV") value.
            _spoofRows[_spoofRows.Length - 1].SetActive(
                active && _domainMode != ObscurizeConst.DomainModeOff,
                _domainMode == ObscurizeConst.DomainModeJoined);
        }

        private void SetModeButtonsEnabled(bool enabled)
        {
            _btnDefensive.Enabled = enabled;
            _btnTrap.Enabled      = enabled;

            if (!enabled)
            {
                _btnDefensive.SetSelected(false);
                _btnTrap.SetSelected(false);
            }
        }

        // ── Log helpers ───────────────────────────────────────────

        internal void AppendLog(string message, Color? color = null)
        {
            if (InvokeRequired) { Invoke(new Action(() => AppendLog(message, color))); return; }

            string line = $"[{DateTime.Now:HH:mm:ss}]  {message}\n";
            _rtbLog.SelectionStart  = _rtbLog.TextLength;
            _rtbLog.SelectionLength = 0;
            _rtbLog.SelectionColor  = color ?? ColTextDim;
            _rtbLog.AppendText(line);
            _rtbLog.ScrollToCaret();
        }

        // ── Layout helpers ────────────────────────────────────────

        private Panel MakePanel(int x, int y, int w, int h, Color bg)
        {
            Panel p = new()
            {
                Bounds    = new Rectangle(x, y, w, h),
                BackColor = bg,
            };
            Controls.Add(p);
            return p;
        }

        private void AddSeparator(int y)
        {
            Panel sep = new()
            {
                Bounds    = new Rectangle(0, y, 480, 1),
                BackColor = ColBorder,
            };
            Controls.Add(sep);
        }

        private static void RoundCorners(Control c, int radius)
        {
            // Creates a rounded-rectangle region for a control.
            System.Drawing.Drawing2D.GraphicsPath path = new();
            Rectangle r = new(0, 0, c.Width, c.Height);
            int d = radius * 2;
            path.AddArc(r.X, r.Y, d, d, 180, 90);
            path.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            path.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            path.CloseFigure();
            c.Region = new Region(path);
        }
    }

    // ============================================================
    //  PowerButton – custom-drawn circular power toggle
    // ============================================================

    internal sealed class PowerButton : Control
    {
        private bool  _on;
        private Color _activeColor = Color.FromArgb(52, 120, 240);

        internal void SetState(bool on, Color activeColor)
        {
            _on          = on;
            _activeColor = activeColor;
            Invalidate();
        }

        public PowerButton()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint
                   | ControlStyles.OptimizedDoubleBuffer | ControlStyles.SupportsTransparentBackColor, true);
            BackColor = Color.Transparent;
            Cursor    = Cursors.Hand;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            Color back  = _on  ? _activeColor : Color.FromArgb(50, 50, 70);
            Color text  = Color.White;
            string label = _on ? "  ACTIVE" : "  INACTIVE";

            // Pill background
            using SolidBrush bg = new(back);
            g.FillRectangle(bg, 0, 0, Width, Height);

            // Power glyph (circle + vertical line)
            int cx = 24, cy = Height / 2, r = 10;
            using Pen ring    = new(text, 2f);
            using Pen linePen = new(text, 2f);
            g.DrawEllipse(ring, cx - r, cy - r, r * 2, r * 2);
            g.DrawLine(linePen, cx, cy - r - 4, cx, cy - 2);

            // Label
            using Font   f  = new("Segoe UI", 9.5f, FontStyle.Bold, GraphicsUnit.Point);
            using Brush  tb = new SolidBrush(text);
            SizeF  sz = g.MeasureString(label, f);
            g.DrawString(label, f, tb, 40, (Height - sz.Height) / 2f);

            // Border
            using Pen border = new(Color.FromArgb(80, 80, 100), 1);
            g.DrawRectangle(border, 0, 0, Width - 1, Height - 1);
        }

        protected override void OnMouseEnter(EventArgs e) { Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { Invalidate(); base.OnMouseLeave(e); }
    }

    // ============================================================
    //  ModeButton – selectable mode radio-style button
    // ============================================================

    internal sealed class ModeButton : Control
    {
        private readonly string _label;
        private readonly Color  _accent;
        private bool            _selected;

        internal void SetSelected(bool selected) { _selected = selected; Invalidate(); }

        internal ModeButton(string label, Color accent)
        {
            _label  = label;
            _accent = accent;
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint
                   | ControlStyles.OptimizedDoubleBuffer | ControlStyles.SupportsTransparentBackColor, true);
            BackColor = Color.Transparent;
            Cursor    = Cursors.Hand;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            Color bg     = _selected ? _accent : Color.FromArgb(40, 40, 58);
            Color fg     = _selected ? Color.White : Color.FromArgb(160, 160, 180);
            Color border = _selected ? _accent : Color.FromArgb(70, 70, 90);

            using SolidBrush bgBrush = new(bg);
            using SolidBrush fgBrush = new(fg);
            using Pen        bdrPen  = new(border, _selected ? 2f : 1f);

            g.FillRectangle(bgBrush, 1, 1, Width - 2, Height - 2);
            g.DrawRectangle(bdrPen,  0, 0, Width - 1, Height - 1);

            using Font f = new("Segoe UI", 9.5f, _selected ? FontStyle.Bold : FontStyle.Regular,
                               GraphicsUnit.Point);
            SizeF sz = g.MeasureString(_label, f);
            g.DrawString(_label, f, fgBrush, (Width - sz.Width) / 2f, (Height - sz.Height) / 2f);
        }

        protected override void OnMouseEnter(EventArgs e) { Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { Invalidate(); base.OnMouseLeave(e); }
    }

    // ============================================================
    //  SpoofRow – single row in the Active Spoofs panel
    // ============================================================

    internal sealed class SpoofRow : Control
    {
        private readonly string _labelText;
        private readonly string _defensiveValue;
        private readonly string _trapValue;
        private bool            _active;
        private bool            _trapMode;

        private static readonly Color ColSuccess = Color.FromArgb(80, 200, 120);
        private static readonly Color ColMuted   = Color.FromArgb(90, 90, 110);
        private static readonly Color ColText    = Color.FromArgb(220, 220, 235);
        private static readonly Color ColBorder  = Color.FromArgb(45,  45,  65);

        internal void SetActive(bool active, bool trapMode)
        {
            _active   = active;
            _trapMode = trapMode;
            Invalidate();
        }

        internal SpoofRow(string label, string defensiveValue, string trapValue)
        {
            _labelText      = label;
            _defensiveValue = defensiveValue;
            _trapValue      = trapValue;
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint
                   | ControlStyles.OptimizedDoubleBuffer | ControlStyles.SupportsTransparentBackColor, true);
            BackColor = Color.Transparent;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            Color   indicatorColor = _active ? ColSuccess : ColMuted;
            string  value          = _trapMode ? _trapValue : _defensiveValue;

            // Indicator dot
            using SolidBrush dot = new(indicatorColor);
            g.FillEllipse(dot, 12, (Height - 8) / 2, 8, 8);

            // Label
            using Font   labelFont  = new("Segoe UI", 8.5f, FontStyle.Regular, GraphicsUnit.Point);
            using Brush  labelBrush = new SolidBrush(_active ? ColText : ColMuted);
            g.DrawString(_labelText, labelFont, labelBrush, 30, (Height - 14) / 2f);

            // Arrow + value on the right
            if (_active)
            {
                using Font   valFont  = new("Segoe UI", 8.5f, FontStyle.Bold, GraphicsUnit.Point);
                using Brush  valBrush = new SolidBrush(indicatorColor);
                SizeF sz = g.MeasureString(value, valFont);
                g.DrawString("→  " + value, valFont, valBrush, Width - sz.Width - 48,
                             (Height - sz.Height) / 2f);
            }

            // Bottom border
            using Pen sep = new(ColBorder, 1);
            g.DrawLine(sep, 0, Height - 1, Width, Height - 1);
        }
    }
}
