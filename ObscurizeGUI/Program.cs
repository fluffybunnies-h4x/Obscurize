using System;
using System.Threading;
using System.Windows.Forms;

namespace Obscurize
{
    internal static class Program
    {
        // Single-instance mutex – prevents multiple GUI copies running at once.
        private static Mutex? _instanceMutex;

        [STAThread]
        static void Main()
        {
            // Must be called before any UI, including MessageBox.
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            const string mutexName = "Global\\ObscurizeGUI_SingleInstance";
            _instanceMutex = new Mutex(true, mutexName, out bool createdNew);

            if (!createdNew)
            {
                // Another instance is already running – bring its window to front
                // by posting a message (handled by the existing instance's tray app).
                MessageBox.Show(
                    "Obscurize is already running.\nLook for the shield icon in the system tray.",
                    "Obscurize",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return;
            }

            // Run as a tray-only application using ApplicationContext instead of a Form.
            using TrayApplicationContext context = new();
            Application.Run(context);

            _instanceMutex.ReleaseMutex();
        }
    }
}
