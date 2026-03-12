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
//  HKEY_LOCAL_MACHINE\SOFTWARE\ObscurizeConfig
// ------------------------------------------------------------

#define OBS_CONFIG_KEY              L"SOFTWARE\\ObscurizeConfig"
#define OBS_CONFIG_VALUE_ENABLED    L"Enabled"       // DWORD  0/1
#define OBS_CONFIG_VALUE_MODE       L"Mode"          // DWORD  OBS_MODE_*
#define OBS_CONFIG_VALUE_USERNAME   L"SpoofUsername" // SZ     Trap mode username
#define OBS_CONFIG_VALUE_COMPNAME   L"SpoofCompName" // SZ     Trap mode computer name
#define OBS_CONFIG_VALUE_MACVENDOR  L"SpoofMacOUI"   // BINARY 3 bytes OUI for Trap MAC

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
    L"winlogon.exe",             \
    L"MsMpEng.exe",              \
    L"MSBuild.exe",              \
    L"ObscurizeService.exe",     \
    L"ObscurizeGUI.exe",         \
    /* Shell and UI hosts – hooking these causes Explorer hangs/crashes */ \
    L"explorer.exe",             \
    L"ShellExperienceHost.exe",  \
    L"StartMenuExperienceHost.exe", \
    L"SearchHost.exe",           \
    L"RuntimeBroker.exe",        \
    L"sihost.exe",               \
    L"taskhostw.exe",            \
    NULL }

#endif  // _OBSCURIZE_DEF_H
