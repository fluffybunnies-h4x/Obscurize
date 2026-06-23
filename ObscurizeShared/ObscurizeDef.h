#ifndef _OBSCURIZE_DEF_H
#define _OBSCURIZE_DEF_H

// ============================================================
//  ObscurizeDef.h  –  Shared constants for Obscurize
//  Must stay in sync with ObscurizeConst.cs
// ============================================================

// ------------------------------------------------------------
//  Operating modes
// ------------------------------------------------------------

/// Defensive mode: make the host look like a VM so malware self-terminates.
#define OBS_MODE_DEFENSIVE          1
/// Trap mode: make a VM look like real hardware so malware executes fully.
#define OBS_MODE_TRAP               2

// ------------------------------------------------------------
//  Registry – configuration store
//  HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DeviceCache
//
//  Stored under an innocuous Windows-style path. Value names are
//  chosen to blend with legitimate device-management entries.
// ------------------------------------------------------------

#define OBS_CONFIG_KEY              L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\DeviceCache"
#define OBS_CONFIG_VALUE_ENABLED    L"DeviceState"      // DWORD  0/1
#define OBS_CONFIG_VALUE_MODE       L"CacheLevel"       // DWORD  OBS_MODE_*
#define OBS_CONFIG_VALUE_USERNAME   L"UserSID"          // SZ     Trap mode username
#define OBS_CONFIG_VALUE_COMPNAME   L"HostBinding"      // SZ     Trap mode computer name
#define OBS_CONFIG_VALUE_MACVENDOR  L"HardwarePrefix"   // BINARY 3 bytes OUI for Trap MAC
#define OBS_CONFIG_VALUE_DOMAIN_MODE    L"NetworkScope"     // DWORD  0=off/pass-through 1=WORKGROUP 2=domain-joined
#define OBS_CONFIG_VALUE_DOMAIN_NAME    L"NetworkDomain"    // SZ     spoofed domain name

// NT path of the key's parent – used by HookedNtEnumerateKey to hide DeviceCache
#define OBS_NT_CONFIG_PARENT \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"

// Domain mode constants
#define OBS_DOMAIN_MODE_OFF         0   // Hook disabled; real domain info returned
#define OBS_DOMAIN_MODE_WORKGROUP   1   // Force WORKGROUP / PartOfDomain: False
#define OBS_DOMAIN_MODE_JOINED      2   // Force domain-joined / PartOfDomain: True

// ------------------------------------------------------------
//  Registry – VM artefacts written/removed by the Service
//  (Defensive mode creates these; Trap mode removes them)
// ------------------------------------------------------------

// VMware Tools presence key
#define OBS_REG_VMWARE_ROOT         L"SOFTWARE\\VMware, Inc."
#define OBS_REG_VMWARE_TOOLS        L"SOFTWARE\\VMware, Inc.\\VMware Tools"
#define OBS_REG_VMWARE_TOOLS_VER    L"Version"       // SZ  value – fake version
#define OBS_REG_VMWARE_TOOLS_VERVAL L"12.3.5.22234"

// VirtualBox Guest Additions presence key
#define OBS_REG_VBOX_ROOT           L"SOFTWARE\\Oracle"
#define OBS_REG_VBOX_GA             L"SOFTWARE\\Oracle\\VirtualBox Guest Additions"
#define OBS_REG_VBOX_GA_VER         L"Version"
#define OBS_REG_VBOX_GA_VERVAL      L"7.0.14"

// BIOS / hardware description key (read by WMI Win32_ComputerSystem / Win32_BIOS)
#define OBS_REG_BIOS_KEY            L"HARDWARE\\DESCRIPTION\\System\\BIOS"
#define OBS_REG_BIOS_MANUFACTURER   L"SystemManufacturer"
#define OBS_REG_BIOS_PRODUCT        L"SystemProductName"
#define OBS_REG_BIOS_VENDOR         L"BIOSVendor"
#define OBS_REG_BIOS_VERSION        L"BIOSVersion"
#define OBS_REG_BIOS_RELEASEDATE    L"BIOSReleaseDate"
// Extended BIOS key values (read by WMI Win32_BaseBoard / systeminfo)
#define OBS_REG_BIOS_BASEBOARD_MFG  L"BaseBoardManufacturer"
#define OBS_REG_BIOS_BASEBOARD_PROD L"BaseBoardProduct"
#define OBS_REG_BIOS_BASEBOARD_VER  L"BaseBoardVersion"
#define OBS_REG_BIOS_SYSTEM_FAMILY  L"SystemFamily"
#define OBS_REG_BIOS_SYSTEM_SKU     L"SystemSKU"
#define OBS_REG_BIOS_SYSTEM_VER     L"SystemVersion"

// Internal NT registry path prefix (used in NtQueryValueKey comparisons)
#define OBS_NT_BIOS_PATH            L"\\REGISTRY\\MACHINE\\HARDWARE\\DESCRIPTION\\System\\BIOS"

// SystemInformation – mirrors BIOS key; read by some malware via SCM / WMI fallback
#define OBS_REG_SYSINFO_KEY         L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation"
#define OBS_REG_SYSINFO_MANUFACTURER L"SystemManufacturer"
#define OBS_REG_SYSINFO_PRODUCT     L"SystemProductName"
#define OBS_REG_SYSINFO_BIOS_VENDOR L"BIOSVendor"
#define OBS_REG_SYSINFO_BIOS_VER    L"BIOSVersion"
#define OBS_REG_SYSINFO_BIOS_DATE   L"BIOSReleaseDate"

// CentralProcessor – ProcessorNameString read by WMI Win32_Processor / systeminfo
#define OBS_REG_CPU_BASE_KEY        L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor"
#define OBS_REG_CPU_PROC_NAME       L"ProcessorNameString"
#define OBS_REG_CPU_VENDOR          L"VendorIdentifier"
#define OBS_REG_CPU_MHZ             L"~MHz"

// Cryptography – MachineGuid checked by some fingerprinting tools
#define OBS_REG_CRYPTO_KEY          L"SOFTWARE\\Microsoft\\Cryptography"
#define OBS_REG_CRYPTO_MACHINEGUID  L"MachineGuid"

// ------------------------------------------------------------
//  Spoof values – Defensive mode (appear as VMware VM)
// ------------------------------------------------------------

#define OBS_DEF_MANUFACTURER        L"VMware, Inc."
#define OBS_DEF_PRODUCT             L"VMware Virtual Platform"
#define OBS_DEF_BIOS_VENDOR         L"Phoenix Technologies LTD"
#define OBS_DEF_BIOS_VERSION        L"6.00"
#define OBS_DEF_BIOS_DATE           L"07/02/2015"
#define OBS_DEF_USERNAME            L"admin"
#define OBS_DEF_COMPUTERNAME        L"DESKTOP-ANALY5T"
#define OBS_DEF_SCREEN_WIDTH        800
#define OBS_DEF_SCREEN_HEIGHT       600
// Report 2 GB RAM (below the 3 GB threshold checked by DEADVAX and similar)
#define OBS_DEF_MEMORY_MB           2048ULL
// VMware NIC OUI  00:0C:29
#define OBS_DEF_MAC_OUI             { 0x00, 0x0C, 0x29 }
// Extended BIOS fields (Win32_BaseBoard / systeminfo)
#define OBS_DEF_BASEBOARD_MFG       L"Intel Corporation"
#define OBS_DEF_BASEBOARD_PROD      L"440BX Desktop Reference Platform"
#define OBS_DEF_SYSTEM_FAMILY       L"VMware Virtual Platform"
#define OBS_DEF_SYSTEM_SKU          L"Not Specified"
// CPU spoofing – Defensive presents a dated Xeon (common sandbox fingerprint)
#define OBS_DEF_CPU_NAME            L"Intel(R) Xeon(R) CPU E5-2697 v4 @ 2.30GHz"
#define OBS_DEF_CPU_VENDOR          L"GenuineIntel"
#define OBS_DEF_CPU_MHZ             2300

// ------------------------------------------------------------
//  Spoof values – Trap mode (appear as real Dell workstation)
// ------------------------------------------------------------

#define OBS_TRAP_MANUFACTURER       L"Dell Inc."
#define OBS_TRAP_PRODUCT            L"Precision 5560"
#define OBS_TRAP_BIOS_VENDOR        L"Dell Inc."
#define OBS_TRAP_BIOS_VERSION       L"1.22.0"
#define OBS_TRAP_BIOS_DATE          L"04/14/2023"
#define OBS_TRAP_USERNAME_DEFAULT   L"jsmith"
#define OBS_TRAP_COMPNAME_DEFAULT   L"DESKTOP-J8K3M2"
#define OBS_TRAP_SCREEN_WIDTH       1920
#define OBS_TRAP_SCREEN_HEIGHT      1080
// Report 16 GB RAM (realistic workstation)
#define OBS_TRAP_MEMORY_MB          16384ULL
// Intel NIC OUI  00:1B:21
#define OBS_TRAP_MAC_OUI            { 0x00, 0x1B, 0x21 }
// Extended BIOS fields (Win32_BaseBoard / systeminfo)
#define OBS_TRAP_BASEBOARD_MFG      L"Dell Inc."
#define OBS_TRAP_BASEBOARD_PROD     L"0G9MWF"
#define OBS_TRAP_SYSTEM_FAMILY      L"Precision"
#define OBS_TRAP_SYSTEM_SKU         L"0857"
// CPU spoofing – Trap presents a modern workstation CPU
#define OBS_TRAP_CPU_NAME           L"11th Gen Intel(R) Core(TM) i7-1185G7 @ 3.00GHz"
#define OBS_TRAP_CPU_VENDOR         L"GenuineIntel"
#define OBS_TRAP_CPU_MHZ            3000

// ------------------------------------------------------------
//  Domain spoof values  (used by NetGetJoinInformation hook)
// ------------------------------------------------------------

/// Domain name returned when DomainMode = OBS_DOMAIN_MODE_JOINED
#define OBS_SPOOF_DOMAIN_ACTIVE     L"CORP.DEV"
/// Workgroup name returned when DomainMode = OBS_DOMAIN_MODE_WORKGROUP
#define OBS_SPOOF_DOMAIN_INACTIVE   L"WORKGROUP"

// PowerShell system-wide profile – installed by ArtefactManager to hook Get-WmiObject/Get-CimInstance
#define OBS_PS_PROFILE_PATH         L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\profile.ps1"
#define OBS_PS_PROFILE_BACKUP_PATH  L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\profile.obs_backup"

// ------------------------------------------------------------
//  Known VM process names (filtered in Trap mode)
// ------------------------------------------------------------

#define OBS_VM_PROCESSES { \
    L"vmtoolsd.exe",       \
    L"VBoxService.exe",    \
    L"VBoxTray.exe",       \
    L"vmsrvc.exe",         \
    L"vmusrvc.exe",        \
    L"VGAuthService.exe",  \
    L"vmwaretray.exe",     \
    L"vmwareuser.exe",     \
    L"vmacthlp.exe",       \
    NULL }

// ------------------------------------------------------------
//  Known VM service names (filtered in Trap mode)
// ------------------------------------------------------------

#define OBS_VM_SERVICES { \
    L"VMTools",           \
    L"VBoxGuest",         \
    L"VBoxMouse",         \
    L"VBoxSF",            \
    L"VBoxVideo",         \
    L"VGAuthService",     \
    L"vmhgfs",            \
    L"vmci",              \
    L"vmvss",             \
    L"VBoxService",       \
    NULL }

// ------------------------------------------------------------
//  Known VM registry vendor subkeys (filtered during
//  NtEnumerateKey of HKLM\SOFTWARE in Trap mode)
// ------------------------------------------------------------

#define OBS_VM_REGKEYS { \
    L"VMware, Inc.",     \
    L"Oracle",           \
    L"VBOX",             \
    NULL }

// ------------------------------------------------------------
//  Named pipe – GUI control interface
// ------------------------------------------------------------

#define OBS_CONTROL_PIPE_NAME       L"\\\\.\\pipe\\ObscurizeCtrl"

// ------------------------------------------------------------
//  Control codes  (GUI -> Service pipe protocol)
// ------------------------------------------------------------

#define OBS_CTRL_ENABLE             0x0001  // Enable Obscurize
#define OBS_CTRL_DISABLE            0x0002  // Disable Obscurize
#define OBS_CTRL_SET_MODE_DEFENSIVE 0x0003  // Switch to Defensive mode
#define OBS_CTRL_SET_MODE_TRAP      0x0004  // Switch to Trap mode
#define OBS_CTRL_QUERY_STATUS       0x0005  // Request status reply
#define OBS_CTRL_INJECT_ALL         0x0006  // Re-inject agent into all processes
#define OBS_CTRL_DETACH_ALL         0x0007  // Detach agent from all processes
#define OBS_CTRL_DOMAIN_OFF         0x0008  // Domain hook disabled – real domain info returned
#define OBS_CTRL_DOMAIN_WORKGROUP   0x0009  // Force WORKGROUP / PartOfDomain = False
#define OBS_CTRL_INJECT_PID         0x000A  // Agent → Service: inject into suspended PID, then reply
#define OBS_CTRL_DOMAIN_JOINED      0x000B  // Force domain-joined / PartOfDomain = True

// Status reply codes (Service -> GUI)
#define OBS_STATUS_OK               0x0000
#define OBS_STATUS_DISABLED         0x0001
#define OBS_STATUS_MODE_DEFENSIVE   0x0002
#define OBS_STATUS_MODE_TRAP        0x0003
#define OBS_STATUS_ERROR            0xFFFF

// ------------------------------------------------------------
//  Agent DLL header  (written into the PE at offset 40,
//  same approach as r77 so the Service can detect injection)
// ------------------------------------------------------------

#define OBS_HEADER_OFFSET           40
#define OBS_AGENT_SIGNATURE         0x4253  // 'BS'  – injected agent
#define OBS_SERVICE_SIGNATURE       0x5653  // 'VS'  – service process

// Process exclusions – never inject the agent into these.
// Shell/UI hosts are excluded because our NT-level hooks (NtQueryValueKey,
// NtEnumerateKey) are called thousands of times per second by the shell and
// its extensions, causing deadlocks and context-menu/folder-creation hangs.
// Malware samples run in their own process, so excluding these does not
// reduce spoofing coverage.
#define OBS_PROCESS_EXCLUSIONS { \
    /* Obscurize own processes */ \
    L"ObscurizeService.exe",     \
    L"ObscurizeGUI.exe",         \
    /* Windows security / UAC infrastructure – injecting here breaks elevation */ \
    L"consent.exe",              \
    L"winlogon.exe",             \
    L"lsass.exe",                \
    L"lsaiso.exe",               \
    /* Lock screen and logon UI – resolution hooks corrupt    \
       the lock screen display; these are security UI with   \
       no malware exposure */                                 \
    L"LockApp.exe",              \
    L"LogonUI.exe",              \
    /* Windows Defender / AV – injecting triggers self-protection */ \
    L"MsMpEng.exe",              \
    L"smartscreen.exe",          \
    L"SecurityHealthService.exe", \
    /* Shell and UI hosts – hooking these causes Explorer hangs/crashes */ \
    L"explorer.exe",             \
    /* MMC snap-in host – snap-ins use GetComputerNameExW to open       \
       \\COMPUTERNAME\IPC$ even for local management; the spoofed name  \
       fails to resolve, breaking Device Manager, Disk Management, etc. \
       No malware exposure: snap-ins are operator tools, not execution   \
       paths for samples */                                              \
    L"mmc.exe",                  \
    L"ShellExperienceHost.exe",  \
    L"StartMenuExperienceHost.exe", \
    L"SearchHost.exe",           \
    L"RuntimeBroker.exe",        \
    L"sihost.exe",               \
    L"taskhostw.exe",            \
    /* Build tools */ \
    L"MSBuild.exe",              \
    /* VMware Workstation host – uses named pipes for internal  \
       IPC (VMDB transport); injection breaks pipe            \
       communication and would cause VMware to spoof itself   \
       in Defensive mode */                                   \
    L"vmware.exe",               \
    L"vmware-vmx.exe",           \
    L"vmware-authd.exe",         \
    L"vmware-hostd.exe",         \
    L"vmnetdhcp.exe",            \
    L"vmnetnat.exe",             \
    L"vmnat.exe",                \
    L"vmware-unity-helper.exe",  \
    /* VMware Tools guest processes – coordinate with the     \
       hypervisor for snapshots via VSS quiesce; NT hooks     \
       inside these processes during VSS freeze cause BSOD */ \
    L"vmtoolsd.exe",             \
    L"VGAuthService.exe",        \
    L"vmacthlp.exe",             \
    /* VSS (Volume Shadow Copy) – kernel-coordinated freeze   \
       during snapshots and backups; NT hooks during freeze   \
       window cause BSOD */                                   \
    L"vssvc.exe",                \
    L"vss_ps.exe",               \
    /* Browsers – Chromium CIG blocks unsigned DLL injection, \
       leaving the process in a broken state on startup */    \
    L"chrome.exe",               \
    L"msedge.exe",               \
    L"brave.exe",                \
    L"opera.exe",                \
    L"vivaldi.exe",              \
    L"firefox.exe",              \
    L"waterfox.exe",             \
    /* OneDrive – setup and sync processes use protected DLL  \
       loading; injection corrupts ordinal resolution on      \
       first-run user login */                                \
    L"OneDriveSetup.exe",        \
    L"OneDrive.exe",             \
    /* Steam – CEF-based overlay and web helper; injection    \
       disrupts internal page rendering (blank overlay) */   \
    L"steam.exe",                \
    L"steamwebhelper.exe",       \
    L"steamservice.exe",         \
    /* Razer Synapse – CEF-based UI (same CIG issue as Steam); \
       service processes call GetComputerNameExW for device  \
       registration / cloud profile sync, so injection would \
       corrupt peripheral bindings under the spoofed name */ \
    L"RazerSynapse.exe",         \
    L"Razer Synapse 3.exe",      \
    L"RazerCentralService.exe",  \
    L"RazerGameScannerService.exe", \
    L"RazerBluetoothService.exe", \
    L"RazerChromaSDKService.exe", \
    L"RzSynapse.exe",            \
    L"RazerNgcx.exe",            \
    L"rzagent.exe",              \
    L"Razer Central.exe",        \
    L"Razer Updater.exe",        \
    L"RazerCortex.exe",          \
    L"RazerCortexBoostHelper.exe", \
    L"CortexLauncher.exe",       \
    L"CortexLauncherService.exe", \
    L"RazerAxon.exe",            \
    L"RazerAppEngine.exe",       \
    L"RzSDKServer.exe",          \
    /* Other CEF-based game launchers – same class of issue  \
       as Steam; injecting into CEF renderers corrupts       \
       internal page loading */                              \
    L"EpicGamesLauncher.exe",    \
    L"EpicWebHelper.exe",        \
    L"GalaxyClient.exe",         \
    L"GalaxyClientService.exe",  \
    L"EADesktop.exe",            \
    L"EABackgroundService.exe",  \
    L"UbisoftConnect.exe",       \
    L"upc.exe",                  \
    L"Battle.net.exe",           \
    L"Battle.net Launcher.exe",  \
    /* Sysmon – kernel driver (SysmonDrv) is Ring 0 and unaffected;    \
       user-mode service is excluded because (a) injecting into a      \
       security monitor is a stability hazard, and (b) the computer-   \
       name hook would tag Sysmon's XML events with the spoofed host,  \
       breaking SIEM correlation on the defending side */              \
    L"Sysmon.exe",               \
    L"Sysmon64.exe",             \
    /* Log shippers and forwarders – GetComputerNameExW runs inside    \
       these processes, so every event forwarded to a SIEM would carry \
       the spoofed hostname, corrupting log correlation.  No malware   \
       ever executes inside a log forwarder */                         \
    L"nxlog.exe",                \
    L"nxlog-ce.exe",             \
    L"winlogbeat.exe",           \
    L"filebeat.exe",             \
    L"metricbeat.exe",           \
    L"elastic-agent.exe",        \
    L"splunkd.exe",              \
    L"splunk.exe",               \
    L"fluent-bit.exe",           \
    L"fluentd.exe",              \
    L"wazuh-agent.exe",          \
    /* Sublime Text – non-standard DLL loader; injection corrupts  \
       ordinal resolution tables, producing "Ordinal Not Found"    \
       dialogs and crashing the editor process on launch */        \
    L"sublime_text.exe",         \
    NULL }

#endif  // _OBSCURIZE_DEF_H
