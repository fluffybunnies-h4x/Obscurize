using System.Management;

namespace Obscurize
{
    // ============================================================
    //  ServiceLocator – finds the running Obscurize service by its
    //  binary path rather than a fixed name.
    //
    //  ObscurizeInitializer.ps1 registers the service under a
    //  randomized name/display name (New-ServiceIdentity) so it
    //  doesn't stand out in a service scan, but the binary is
    //  always installed as "ObscurizeService.exe" regardless of
    //  install path. Matching on PathName finds the right service
    //  without needing to read service.cfg or know the install path.
    // ============================================================
    internal static class ServiceLocator
    {
        internal static (string ServiceName, string DisplayName)? FindObscurizeService()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT Name, DisplayName, PathName FROM Win32_Service " +
                    "WHERE PathName LIKE '%ObscurizeService.exe%'");

                foreach (ManagementObject mo in searcher.Get())
                {
                    if (mo["Name"] is string name && name.Length > 0)
                        return (name, mo["DisplayName"] as string ?? name);
                }
            }
            catch { /* WMI unavailable - identity line just won't be shown */ }

            return null;
        }
    }
}
