#include "ArtefactManager.h"
#include "../ObscurizeShared/ObscurizeDef.h"
#include "../ObscurizeAgent/Spoof.h"   // InstallDefensiveRegistryArtefacts / Remove... / InstallExtendedRegistryArtefacts

#include <Shlwapi.h>
#include <strsafe.h>
#include <stdio.h>    // _scprintf, sprintf_s
#include <string.h>   // strlen

// ============================================================
//  ObscurizeService – ArtefactManager.c
//
//  Manages the persistent (non-hook) artefacts for each mode.
//
//  Two-layer spoofing model:
//    Layer 1 (persistent, this file):
//      Physical registry writes and file creation that survive
//      hook removal and are visible to WMI / uninjected processes.
//    Layer 2 (runtime, Hooks.c in the Agent):
//      In-process API interception for processes that are already
//      injected.  Catches queries the persistent layer misses
//      (e.g. live GetUserNameW calls, GetAdaptersAddresses, etc.)
//
//  DEADVAX-specific artefacts:
//    • mapping.csv in %TEMP% – DEADVAX Stage 3 checks for this
//      file.  In Defensive mode we deliberately DO NOT create it
//      so Stage 3 exits ("artifacts missing → abort").
//      In Trap mode we DO create it so Stage 3 proceeds.
//    • 'VBE' in %TEMP% – same logic (Stage 2 marker file).
// ============================================================

// --------------------------------------------------------
//  Decoy file helpers
// --------------------------------------------------------

/// Build the path %TEMP%\<filename> into buf (MAX_PATH).
static BOOL BuildTempPath(LPCWSTR filename, LPWSTR buf, DWORD bufCch)
{
    WCHAR tmpDir[MAX_PATH + 1] = { 0 };
    if (!GetTempPathW(MAX_PATH, tmpDir)) return FALSE;
    return SUCCEEDED(StringCchPrintfW(buf, bufCch, L"%s%s", tmpDir, filename));
}

/// Create an empty file at path if it does not already exist.
static VOID CreateDecoyFile(LPCWSTR path)
{
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) return;  // Already exists

    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL,
                           CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE)
    {
        // Write a plausible CSV header line so the file looks authentic.
        static const char header[] = "timestamp,event,value\r\n";
        DWORD written;
        WriteFile(h, header, (DWORD)sizeof(header) - 1, &written, NULL);
        CloseHandle(h);
    }
}

/// Delete a file if it exists.
static VOID DeleteDecoyFile(LPCWSTR path)
{
    DeleteFileW(path);
}

// --------------------------------------------------------
//  Trap mode – decoy campaign artefact files
//  (DEADVAX Stage 3 checks for these; create them in Trap
//  mode so the malware believes its prior stages ran.)
// --------------------------------------------------------

static VOID CreateTrapDecoyFiles(VOID)
{
    WCHAR path[MAX_PATH + 1];

    // mapping.csv – checked by DEADVAX Batch Stage 3
    if (BuildTempPath(L"mapping.csv", path, MAX_PATH))
        CreateDecoyFile(path);

    // VBE marker – also checked by DEADVAX Stage 3
    // DEADVAX looks for any file whose name contains "VBE"
    if (BuildTempPath(L"VBE_marker.tmp", path, MAX_PATH))
        CreateDecoyFile(path);
}

static VOID RemoveTrapDecoyFiles(VOID)
{
    WCHAR path[MAX_PATH + 1];

    if (BuildTempPath(L"mapping.csv", path, MAX_PATH))
        DeleteDecoyFile(path);

    if (BuildTempPath(L"VBE_marker.tmp", path, MAX_PATH))
        DeleteDecoyFile(path);
}

// --------------------------------------------------------
//  PowerShell system-wide profile management
//
//  We install a profile.ps1 that shadows Get-WmiObject and
//  Get-CimInstance with PSCustomObjects returning mode-
//  appropriate hardware strings.  This solves the WMI
//  spoofing gap that exists because WmiPrvSE.exe injection
//  is unreliable (process mitigation or loader issue).
//
//  Backup: if a profile.ps1 already exists we rename it to
//  profile.obs_backup before writing ours, and restore it
//  on removal.
// --------------------------------------------------------

/// Write len bytes from buf to path, overwriting if exists.
static BOOL WriteFileContents(LPCWSTR path, LPCVOID buf, DWORD len)
{
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD written;
    BOOL ok = WriteFile(h, buf, len, &written, NULL) && written == len;
    CloseHandle(h);
    return ok;
}

/// Build the PowerShell profile script for the given mode.
/// Returns a heap-allocated UTF-8 string; caller must HeapFree.
static LPSTR BuildPsProfile(DWORD mode)
{
    BOOL defensive = (mode == OBS_MODE_DEFENSIVE);

    // Mode-specific string literals embedded directly
    LPCSTR sysMfg      = defensive ? "VMware, Inc."                          : "Dell Inc.";
    LPCSTR sysProd     = defensive ? "VMware Virtual Platform"               : "Precision 5560";
    LPCSTR biosVendor  = defensive ? "Phoenix Technologies LTD"              : "Dell Inc.";
    LPCSTR biosVer     = defensive ? "6.00"                                  : "1.22.0";
    LPCSTR biosDate    = defensive ? "07/02/2015"                            : "04/14/2023";
    LPCSTR bbMfg       = defensive ? "Intel Corporation"                     : "Dell Inc.";
    LPCSTR bbProd      = defensive ? "440BX Desktop Reference Platform"      : "0G9MWF";
    LPCSTR cpuName     = defensive ? "Intel(R) Xeon(R) CPU E5-2697 v4 @ 2.30GHz"
                                   : "11th Gen Intel(R) Core(TM) i7-1185G7 @ 3.00GHz";
    LPCSTR uuid        = defensive ? "564D1234-ABCD-EF01-2345-67890ABCDEF0"  : "44454C4C-0047-394D-574D-B8C04F473532";
    LPCSTR serialNum   = defensive ? "VMware-56 4d 12 34"                    : "7X8K9P2";
    LPCSTR diskModel   = defensive ? "VMware Virtual disk"                   : "SAMSUNG MZVL2512HCJQ-00B00";
    LPCSTR nicName     = defensive ? "VMware VMXNET3 Ethernet Adapter"       : "Intel(R) Wi-Fi 6E AX211 160MHz";
    LPCSTR gpuName     = defensive ? "VMware SVGA 3D"                        : "Intel(R) Iris(R) Xe Graphics";
    int    screenW     = defensive ? 800                                      : 1920;
    int    screenH     = defensive ? 600                                      : 1080;
    LPCSTR macOuiStr   = defensive ? "00:0C:29"                              : "00:1B:21";

    // Compute BIOS date in WMI format (YYYYMMDD000000.000000+000)
    // Defensive: 20150702  Trap: 20230414
    LPCSTR biosDateWmi = defensive ? "20150702000000.000000+000"
                                   : "20230414000000.000000+000";

    // Template – uses printf-style %s substitution
    static const char tmpl[] =
        "# Obscurize WMI Hook Profile – auto-generated, do not edit\r\n"
        "# Mode: %s\r\n"
        "\r\n"
        "$global:OBS_SysMfg     = '%s'\r\n"
        "$global:OBS_SysProd    = '%s'\r\n"
        "$global:OBS_BiosVendor = '%s'\r\n"
        "$global:OBS_BiosVer    = '%s'\r\n"
        "$global:OBS_BiosDate   = '%s'\r\n"
        "$global:OBS_BiosDateWmi= '%s'\r\n"
        "$global:OBS_BbMfg      = '%s'\r\n"
        "$global:OBS_BbProd     = '%s'\r\n"
        "$global:OBS_CpuName    = '%s'\r\n"
        "$global:OBS_UUID       = '%s'\r\n"
        "$global:OBS_Serial     = '%s'\r\n"
        "$global:OBS_DiskModel  = '%s'\r\n"
        "$global:OBS_NicName    = '%s'\r\n"
        "$global:OBS_GpuName    = '%s'\r\n"
        "\r\n"
        "$global:OrigGetWmi = Get-Command Get-WmiObject -CommandType Cmdlet\r\n"
        "Remove-Item -Path Function:\\Get-WmiObject -Force -ErrorAction SilentlyContinue\r\n"
        "\r\n"
        "function global:Get-WmiObject {\r\n"
        "    [CmdletBinding()]\r\n"
        "    param(\r\n"
        "        [Parameter(ValueFromPipeline=$true)][string]$Class,\r\n"
        "        [string]$Query,\r\n"
        "        [string]$Namespace = 'root\\cimv2',\r\n"
        "        [string]$ComputerName = '.'\r\n"
        "    )\r\n"
        "    if ($Class -eq 'Win32_BIOS' -or $Query -like '*Win32_BIOS*') {\r\n"
        "        return [PSCustomObject]@{\r\n"
        "            Manufacturer       = $global:OBS_BiosVendor\r\n"
        "            Name               = $global:OBS_BiosVer\r\n"
        "            Version            = \"$($global:OBS_BiosVendor)   - $($global:OBS_BiosVer)\"\r\n"
        "            SMBIOSBIOSVersion  = $global:OBS_BiosVer\r\n"
        "            ReleaseDate        = $global:OBS_BiosDateWmi\r\n"
        "            SerialNumber       = $global:OBS_Serial\r\n"
        "            SMBIOSMajorVersion = 2\r\n"
        "            SMBIOSMinorVersion = 7\r\n"
        "            SMBIOSPresent      = $true\r\n"
        "            PrimaryBIOS        = $true\r\n"
        "            Status             = 'OK'\r\n"
        "        }\r\n"
        "    }\r\n"
        "    elseif ($Class -eq 'Win32_ComputerSystem' -or $Query -like '*Win32_ComputerSystem*') {\r\n"
        "        $r = & $global:OrigGetWmi -Class Win32_ComputerSystem -Namespace $Namespace\r\n"
        "        $r.Manufacturer = $global:OBS_SysMfg\r\n"
        "        $r.Model = $global:OBS_SysProd\r\n"
        "        $domMode = try { (Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\ObscurizeConfig' -Name 'DomainMode' -EA Stop).DomainMode } catch { 0 }\r\n"
        "        $domName = try { (Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\ObscurizeConfig' -Name 'SpoofDomainName' -EA Stop).SpoofDomainName } catch { 'CORP.DEV' }\r\n"
        "        if ($domMode -eq 2) { $r.PartOfDomain = $true;  $r.Domain = $domName }\r\n"
        "        elseif ($domMode -eq 1) { $r.PartOfDomain = $false; $r.Domain = 'WORKGROUP' }\r\n"
        "        # else domMode=0: leave $r.PartOfDomain and $r.Domain as real WMI values\r\n"
        "        return $r\r\n"
        "    }\r\n"
        "    elseif ($Class -eq 'Win32_ComputerSystemProduct' -or $Query -like '*ComputerSystemProduct*') {\r\n"
        "        return [PSCustomObject]@{\r\n"
        "            Vendor             = $global:OBS_SysMfg\r\n"
        "            Name               = $global:OBS_SysProd\r\n"
        "            IdentifyingNumber  = $global:OBS_Serial\r\n"
        "            UUID               = $global:OBS_UUID\r\n"
        "            Version            = 'Not Specified'\r\n"
        "        }\r\n"
        "    }\r\n"
        "    elseif ($Class -eq 'Win32_BaseBoard' -or $Query -like '*Win32_BaseBoard*') {\r\n"
        "        return [PSCustomObject]@{\r\n"
        "            Manufacturer = $global:OBS_BbMfg\r\n"
        "            Product      = $global:OBS_BbProd\r\n"
        "            SerialNumber = $global:OBS_Serial\r\n"
        "            Version      = 'A00'\r\n"
        "            Status       = 'OK'\r\n"
        "        }\r\n"
        "    }\r\n"
        "    elseif ($Class -eq 'Win32_Processor' -or $Query -like '*Win32_Processor*') {\r\n"
        "        $r = & $global:OrigGetWmi -Class Win32_Processor -Namespace $Namespace\r\n"
        "        foreach ($p in $r) { $p.Name = $global:OBS_CpuName }\r\n"
        "        return $r\r\n"
        "    }\r\n"
        "    elseif ($Class -eq 'Win32_DiskDrive' -or $Query -like '*Win32_DiskDrive*') {\r\n"
        "        $r = & $global:OrigGetWmi -Class Win32_DiskDrive -Namespace $Namespace\r\n"
        "        foreach ($d in $r) {\r\n"
        "            if ($d.Model -match 'VMware|VBOX|Virtual') {\r\n"
        "                $d.Model = $global:OBS_DiskModel; $d.Caption = $global:OBS_DiskModel\r\n"
        "            }\r\n"
        "        }\r\n"
        "        return $r\r\n"
        "    }\r\n"
        "    elseif ($Class -eq 'Win32_NetworkAdapter' -or $Query -like '*Win32_NetworkAdapter*') {\r\n"
        "        $r = & $global:OrigGetWmi -Class Win32_NetworkAdapter -Namespace $Namespace\r\n"
        "        foreach ($a in $r) {\r\n"
        "            if ($a.Name -match 'VMware|vmxnet|Virtual') {\r\n"
        "                $a.Name = $global:OBS_NicName; $a.Description = $global:OBS_NicName\r\n"
        "            }\r\n"
        "        }\r\n"
        "        return $r\r\n"
        "    }\r\n"
        "    elseif ($Class -eq 'Win32_VideoController' -or $Query -like '*Win32_VideoController*') {\r\n"
        "        $r = & $global:OrigGetWmi -Class Win32_VideoController -Namespace $Namespace\r\n"
        "        if ($r.Name -match 'VMware|SVGA') {\r\n"
        "            $r.Name = $global:OBS_GpuName; $r.Description = $global:OBS_GpuName\r\n"
        "        }\r\n"
        "        $r.CurrentHorizontalResolution = %d\r\n"
        "        $r.CurrentVerticalResolution   = %d\r\n"
        "        return $r\r\n"
        "    }\r\n"
        "    elseif ($Class -eq 'Win32_NetworkAdapterConfiguration' -or $Query -like '*Win32_NetworkAdapterConfiguration*') {\r\n"
        "        $r = & $global:OrigGetWmi -Class Win32_NetworkAdapterConfiguration -Namespace $Namespace\r\n"
        "        $oui = '%s'\r\n"
        "        foreach ($a in $r) {\r\n"
        "            if ($a.MACAddress -ne $null) {\r\n"
        "                $parts = $a.MACAddress -split ':'\r\n"
        "                if ($parts.Count -eq 6) {\r\n"
        "                    $a.MACAddress = \"${oui}:$($parts[3]):$($parts[4]):$($parts[5])\"\r\n"
        "                }\r\n"
        "            }\r\n"
        "        }\r\n"
        "        return $r\r\n"
        "    }\r\n"
        "    else { & $global:OrigGetWmi @PSBoundParameters }\r\n"
        "}\r\n"
        "\r\n"
        "$global:OrigGetCim = Get-Command Get-CimInstance -CommandType Cmdlet -ErrorAction SilentlyContinue\r\n"
        "if ($global:OrigGetCim) {\r\n"
        "    Remove-Item -Path Function:\\Get-CimInstance -Force -ErrorAction SilentlyContinue\r\n"
        "    function global:Get-CimInstance {\r\n"
        "        [CmdletBinding()]\r\n"
        "        param(\r\n"
        "            [Parameter(ValueFromPipeline=$true)][string]$ClassName,\r\n"
        "            [string]$Query,\r\n"
        "            [string]$Namespace = 'root\\cimv2'\r\n"
        "        )\r\n"
        "        if ($ClassName) { return Get-WmiObject -Class $ClassName -Namespace $Namespace }\r\n"
        "        if ($Query)     { return Get-WmiObject -Query $Query -Namespace $Namespace }\r\n"
        "        & $global:OrigGetCim @PSBoundParameters\r\n"
        "    }\r\n"
        "}\r\n"
        "\r\n"
        "try { Remove-Item Alias:\\gwmi  -Force -EA SilentlyContinue } catch {}\r\n"
        "try { Remove-Item Alias:\\gcim  -Force -EA SilentlyContinue } catch {}\r\n"
        "try { Set-Alias -Name gwmi -Value Get-WmiObject  -Scope Global -Option AllScope -EA SilentlyContinue } catch {}\r\n"
        "try { Set-Alias -Name gcim -Value Get-CimInstance -Scope Global -Option AllScope -EA SilentlyContinue } catch {}\r\n";

    // Calculate required buffer size
    int needed = _scprintf(tmpl,
        defensive ? "Defensive" : "Trap",
        sysMfg, sysProd, biosVendor, biosVer, biosDate, biosDateWmi,
        bbMfg, bbProd, cpuName, uuid, serialNum, diskModel, nicName, gpuName,
        screenW, screenH, macOuiStr);
    if (needed <= 0) return NULL;

    LPSTR buf = (LPSTR)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)needed + 1);
    if (!buf) return NULL;

    sprintf_s(buf, (SIZE_T)needed + 1, tmpl,
        defensive ? "Defensive" : "Trap",
        sysMfg, sysProd, biosVendor, biosVer, biosDate, biosDateWmi,
        bbMfg, bbProd, cpuName, uuid, serialNum, diskModel, nicName, gpuName,
        screenW, screenH, macOuiStr);

    return buf;
}

static VOID InstallPowerShellProfile(DWORD mode)
{
    LPCWSTR profilePath = OBS_PS_PROFILE_PATH;
    LPCWSTR backupPath  = OBS_PS_PROFILE_BACKUP_PATH;

    // If a profile already exists and we haven't backed it up yet, back it up.
    if (GetFileAttributesW(profilePath) != INVALID_FILE_ATTRIBUTES &&
        GetFileAttributesW(backupPath) == INVALID_FILE_ATTRIBUTES)
    {
        MoveFileW(profilePath, backupPath);
    }

    LPSTR script = BuildPsProfile(mode);
    if (!script) return;

    WriteFileContents(profilePath, script, (DWORD)strlen(script));
    HeapFree(GetProcessHeap(), 0, script);
}

static VOID RemovePowerShellProfile(VOID)
{
    LPCWSTR profilePath = OBS_PS_PROFILE_PATH;
    LPCWSTR backupPath  = OBS_PS_PROFILE_BACKUP_PATH;

    DeleteFileW(profilePath);

    // Restore original profile if we backed one up.
    if (GetFileAttributesW(backupPath) != INVALID_FILE_ATTRIBUTES)
        MoveFileW(backupPath, profilePath);
}

// --------------------------------------------------------
//  Track which mode's artefacts are currently active
// --------------------------------------------------------

static DWORD s_activeArtefactMode = 0;  // 0 = none applied yet

// --------------------------------------------------------
//  Public API
// --------------------------------------------------------

VOID ApplyModeArtefacts(DWORD mode)
{
    // Remove previous mode's artefacts if switching.
    if (s_activeArtefactMode != 0 && s_activeArtefactMode != mode)
        RemoveModeArtefacts();

    if (mode == OBS_MODE_DEFENSIVE)
    {
        // Layer 1 – write physical VM registry artefacts.
        // (Layer 2 Agent hooks cover runtime interception.)
        InstallDefensiveRegistryArtefacts();
        InstallExtendedRegistryArtefacts(OBS_MODE_DEFENSIVE);
        InstallPowerShellProfile(OBS_MODE_DEFENSIVE);

        // In Defensive mode do NOT create the campaign decoy files.
        // Their absence is what triggers DEADVAX Stage 3 to abort,
        // which is exactly what we want on a defended host.
        // Ensure they are absent in case we're switching from Trap.
        RemoveTrapDecoyFiles();
    }
    else if (mode == OBS_MODE_TRAP)
    {
        // Remove Defensive artefacts (restore real hardware strings),
        // then write Trap-mode extended values.
        RemoveDefensiveRegistryArtefacts();
        InstallExtendedRegistryArtefacts(OBS_MODE_TRAP);
        InstallPowerShellProfile(OBS_MODE_TRAP);

        // Create campaign decoy files so malware proceeds past
        // its pre-execution artefact checks.
        CreateTrapDecoyFiles();
    }

    s_activeArtefactMode = mode;
}

VOID RemoveModeArtefacts(VOID)
{
    if (s_activeArtefactMode == OBS_MODE_DEFENSIVE)
    {
        RemoveDefensiveRegistryArtefacts();
    }
    else if (s_activeArtefactMode == OBS_MODE_TRAP)
    {
        RemoveTrapDecoyFiles();
        // No registry cleanup needed for Trap mode – we only removed keys,
        // so there is nothing Obscurize needs to restore.
    }

    // Always remove the PS profile regardless of mode.
    RemovePowerShellProfile();

    s_activeArtefactMode = 0;
}
