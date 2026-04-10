using System;
using System.Threading;

namespace Obscurize
{
    /// <summary>
    /// Convenience enum used throughout the GUI to represent the
    /// four states the tray icon / main window can be in.
    /// </summary>
    internal enum ServiceStatus
    {
        ServiceOffline,     // Pipe connect failed – service not running
        Disabled,           // Service running but Enabled == 0
        ActiveDefensive,    // Enabled + Mode == Defensive
        ActiveTrap          // Enabled + Mode == Trap
    }

    /// <summary>
    /// Polls the ObscurizeService control pipe every 2 seconds on a
    /// background thread and raises <see cref="StatusChanged"/> whenever
    /// the reported status differs from the previous poll.
    ///
    /// Singleton – access via <see cref="Current"/>.
    /// </summary>
    internal sealed class StatusPoller
    {
        // ── Singleton ─────────────────────────────────────────────
        internal static readonly StatusPoller Current = new();
        private StatusPoller() { }

        // ── State ─────────────────────────────────────────────────
        private Thread?       _thread;
        private volatile bool _running;

        private ServiceStatus _lastStatus  = ServiceStatus.ServiceOffline;

        /// <summary>Last known status – used by MainWindow to sync on open.</summary>
        internal ServiceStatus LastStatus => _lastStatus;

        /// <summary>Last known enabled state (convenience for tray menu toggle label).</summary>
        internal bool IsEnabled => _lastStatus == ServiceStatus.ActiveDefensive
                                || _lastStatus == ServiceStatus.ActiveTrap;

        // ── Event ─────────────────────────────────────────────────
        internal event EventHandler<ServiceStatus>? StatusChanged;

        // ── Lifecycle ─────────────────────────────────────────────
        internal void Start()
        {
            if (_running) return;
            _running = true;

            _thread = new Thread(PollLoop)
            {
                IsBackground = true,
                Name         = "ObscurizeStatusPoller"
            };
            _thread.Start();
        }

        internal void Stop()
        {
            _running = false;
            // Thread is background so it dies with the process; no join needed.
        }

        // ── Poll loop ─────────────────────────────────────────────
        private void PollLoop()
        {
            // Fire immediately on first iteration, then every 2 s.
            while (_running)
            {
                ServiceStatus current = QueryCurrentStatus();

                if (current != _lastStatus)
                {
                    _lastStatus = current;
                    StatusChanged?.Invoke(this, current);
                }

                Thread.Sleep(2000);
            }
        }

        private static ServiceStatus QueryCurrentStatus()
        {
            int reply = ControlPipeClient.QueryStatus();

            return reply switch
            {
                ObscurizeConst.StatusDisabled        => ServiceStatus.Disabled,
                ObscurizeConst.StatusModeDefensive   => ServiceStatus.ActiveDefensive,
                ObscurizeConst.StatusModeTrap        => ServiceStatus.ActiveTrap,
                _                                    => ServiceStatus.ServiceOffline   // -1 or StatusError
            };
        }
    }
}
