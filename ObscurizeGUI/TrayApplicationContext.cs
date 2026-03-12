using System;
using System.Drawing;
using System.Windows.Forms;

namespace Obscurize
{
    /// <summary>
    /// Owns the system-tray <see cref="NotifyIcon"/> and manages the
    /// lifecycle of the main <see cref="MainWindow"/>.
    ///
    /// The tray icon has three visual states:
    ///   Active + Defensive  →  blue shield
    ///   Active + Trap        →  amber shield
    ///   Inactive / offline   →  grey shield
    /// </summary>
    internal sealed class TrayApplicationContext : ApplicationContext
    {
        private readonly NotifyIcon   _trayIcon;
        private readonly ContextMenuStrip _contextMenu;
        private          MainWindow?  _mainWindow;

        // Menu items kept as fields so we can update their text dynamically.
        private readonly ToolStripMenuItem _itemToggle;
        private readonly ToolStripMenuItem _itemModeDefensive;
        private readonly ToolStripMenuItem _itemModeTrap;
        private readonly ToolStripMenuItem _itemOpen;

        // Shield icons generated once and reused.
        private readonly Icon _iconActiveDefensive;
        private readonly Icon _iconActiveTrap;
        private readonly Icon _iconInactive;

        internal TrayApplicationContext()
        {
            _iconActiveDefensive = TrayIconRenderer.CreateShieldIcon(ShieldState.ActiveDefensive);
            _iconActiveTrap      = TrayIconRenderer.CreateShieldIcon(ShieldState.ActiveTrap);
            _iconInactive        = TrayIconRenderer.CreateShieldIcon(ShieldState.Inactive);

            // ── Context menu ──────────────────────────────────────
            _itemOpen = new ToolStripMenuItem("Open Control Panel", null, OnOpenClicked);
            _itemOpen.Font = new Font(_itemOpen.Font, FontStyle.Bold);  // Default action

            _itemToggle = new ToolStripMenuItem("Enable", null, OnToggleClicked);

            _itemModeDefensive = new ToolStripMenuItem("Defensive Mode", null, OnModeDefensiveClicked);
            _itemModeTrap      = new ToolStripMenuItem("Trap Mode",      null, OnModeTrapClicked);

            ToolStripMenuItem modeMenu = new("Mode")
            {
                DropDownItems = { _itemModeDefensive, _itemModeTrap }
            };

            ToolStripMenuItem itemExit = new("Exit", null, OnExitClicked);

            _contextMenu = new ContextMenuStrip
            {
                Items =
                {
                    _itemOpen,
                    new ToolStripSeparator(),
                    _itemToggle,
                    modeMenu,
                    new ToolStripSeparator(),
                    itemExit
                }
            };

            // ── Tray icon ─────────────────────────────────────────
            _trayIcon = new NotifyIcon
            {
                Icon             = _iconInactive,
                Text             = "Obscurize – Inactive",
                Visible          = true,
                ContextMenuStrip = _contextMenu
            };
            _trayIcon.DoubleClick += (_, _) => ShowMainWindow();

            // Kick off the background status poller.
            StatusPoller.Current.StatusChanged += OnStatusChanged;
            StatusPoller.Current.Start();
        }

        // ── Window management ─────────────────────────────────────

        internal void ShowMainWindow()
        {
            if (_mainWindow == null || _mainWindow.IsDisposed)
            {
                _mainWindow = new MainWindow();
                _mainWindow.FormClosed += (_, _) => _mainWindow = null;
            }

            _mainWindow.Show();
            _mainWindow.Activate();
            if (_mainWindow.WindowState == FormWindowState.Minimized)
                _mainWindow.WindowState = FormWindowState.Normal;
        }

        // ── Menu handlers ─────────────────────────────────────────

        private void OnOpenClicked(object? sender, EventArgs e)
            => ShowMainWindow();

        private void OnToggleClicked(object? sender, EventArgs e)
        {
            bool isEnabled = StatusPoller.Current.IsEnabled;
            int code = isEnabled ? ObscurizeConst.CtrlDisable : ObscurizeConst.CtrlEnable;
            ControlPipeClient.Send(code);
        }

        private void OnModeDefensiveClicked(object? sender, EventArgs e)
            => ControlPipeClient.Send(ObscurizeConst.CtrlSetModeDefensive);

        private void OnModeTrapClicked(object? sender, EventArgs e)
            => ControlPipeClient.Send(ObscurizeConst.CtrlSetModeTrap);

        private void OnExitClicked(object? sender, EventArgs e)
        {
            StatusPoller.Current.Stop();
            _trayIcon.Visible = false;
            _trayIcon.Dispose();

            // Dispose the main window directly (bypasses the hide-on-close handler).
            _mainWindow?.Dispose();
            _mainWindow = null;

            Environment.Exit(0);
        }

        // ── Status poller callback ────────────────────────────────

        private void OnStatusChanged(object? sender, ServiceStatus status)
        {
            // May arrive from a background thread – marshal to UI thread.
            if (_trayIcon.ContextMenuStrip?.InvokeRequired == true)
            {
                _trayIcon.ContextMenuStrip.Invoke(new Action(() => OnStatusChanged(sender, status)));
                return;
            }

            switch (status)
            {
                case ServiceStatus.Disabled:
                    _trayIcon.Icon = _iconInactive;
                    _trayIcon.Text = "Obscurize – Disabled";
                    _itemToggle.Text = "Enable";
                    break;
                case ServiceStatus.ActiveDefensive:
                    _trayIcon.Icon = _iconActiveDefensive;
                    _trayIcon.Text = "Obscurize – Defensive Mode";
                    _itemToggle.Text = "Disable";
                    break;
                case ServiceStatus.ActiveTrap:
                    _trayIcon.Icon = _iconActiveTrap;
                    _trayIcon.Text = "Obscurize – Trap Mode";
                    _itemToggle.Text = "Disable";
                    break;
                case ServiceStatus.ServiceOffline:
                    _trayIcon.Icon = _iconInactive;
                    _trayIcon.Text = "Obscurize – Service Offline";
                    _itemToggle.Text = "Enable";
                    break;
            }

            // Propagate to open main window if present.
            _mainWindow?.UpdateStatus(status);
        }

        // ── Cleanup ───────────────────────────────────────────────

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                StatusPoller.Current.Stop();
                _trayIcon.Visible = false;
                _trayIcon.Dispose();
                _contextMenu.Dispose();
                _iconActiveDefensive.Dispose();
                _iconActiveTrap.Dispose();
                _iconInactive.Dispose();
                _mainWindow?.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
