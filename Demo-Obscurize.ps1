#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Obscurize Active Spoof Demo
    Exercises every spoofed value Obscurize produces and shows pass/fail
    against expected values for the active mode.

.NOTES
    Run from an elevated PowerShell session AFTER the ObscurizeService is
    running and Obscurize is enabled.  Open a fresh terminal after starting
    the service so profile.ps1 is loaded.

    Two categories of checks:
      [WMI]    Intercepted by profile.ps1 - works in any PS session with
               the profile loaded.
      [HOOK]   Intercepted by the Agent DLL via P/Invoke - requires the
               Agent to be injected into this PowerShell process.
               If injection has not yet occurred these will show real values.
#>

# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

function Write-Header($text) {
    Write-Host ""
    Write-Host ("-" * 70) -ForegroundColor DarkGray
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host ("-" * 70) -ForegroundColor DarkGray
}

function Write-Check($label, $expected, $actual, $note = "") {
    $pass   = $actual -like "*$expected*"
    $status = if ($pass) { "[PASS]" } else { "[FAIL]" }
    $color  = if ($pass) { "Green"  } else { "Red"   }
    Write-Host ("  {0,-6} {1,-38} Expected: {2}" -f $status, $label, $expected) `
        -ForegroundColor $color
    if (-not $pass) {
        Write-Host ("         {0,-38} Got:      {1}" -f "", $actual) `
            -ForegroundColor Yellow
    }
}

function Write-Info($label, $value, $note = "") {
    $tag = if ($note) { "  [$note]" } else { "" }
    Write-Host ("  {0,-44} {1}{2}" -f $label, $value, $tag) -ForegroundColor White
}

# ---------------------------------------------------------------------------
#  Read service config from registry
# ---------------------------------------------------------------------------

$regPath = "HKLM:\SOFTWARE\ObscurizeConfig"

try {
    $cfg = Get-ItemProperty -Path $regPath -EA Stop
} catch {
    Write-Host "`n  [ERROR] HKLM:\SOFTWARE\ObscurizeConfig not found." -ForegroundColor Red
    Write-Host "          Is ObscurizeService installed and running?`n" -ForegroundColor Red
    exit 1
}

$enabled     = [bool]($cfg.Enabled)
$mode        = $cfg.Mode          # 1=Defensive  2=Trap
$domEnabled  = [bool]($cfg.DomainEnabled)
$spoofDomain = if ($cfg.SpoofDomainName) { $cfg.SpoofDomainName } else { "CORP.DEV" }
$spoofUser   = if ($cfg.SpoofUsername)   { $cfg.SpoofUsername   } else { "jsmith" }           # OBS_TRAP_USERNAME_DEFAULT
$spoofComp   = if ($cfg.SpoofCompName)   { $cfg.SpoofCompName   } else { "DESKTOP-J8K3M2" }   # OBS_TRAP_COMPNAME_DEFAULT

$modeStr = switch ($mode) { 1 { "DEFENSIVE" } 2 { "TRAP" } default { "UNKNOWN ($mode)" } }
$defMode = ($mode -eq 1)

$domStr = if ($domEnabled) { "ON  -> PartOfDomain: True, Domain: $spoofDomain" } `
                           else { "OFF -> PartOfDomain: False, Domain: WORKGROUP" }

Write-Host ""
Write-Host "  =======================================" -ForegroundColor Cyan
Write-Host "       OBSCURIZE SPOOF DEMO              " -ForegroundColor Cyan
Write-Host "  =======================================" -ForegroundColor Cyan
Write-Host ""
$enabledColor = if ($enabled) { "Green" } else { "Red" }
$enabledStr   = if ($enabled) { "YES"   } else { "NO - enable Obscurize first" }
Write-Host ("  Service Enabled : {0}" -f $enabledStr)   -ForegroundColor $enabledColor
$modeColor = if ($defMode) { "Cyan" } else { "Magenta" }
Write-Host ("  Active Mode     : {0}" -f $modeStr)      -ForegroundColor $modeColor
$domColor = if ($domEnabled) { "Green" } else { "DarkGray" }
Write-Host ("  Domain Toggle   : {0}" -f $domStr)       -ForegroundColor $domColor

if (-not $enabled) {
    Write-Host "`n  Obscurize is disabled. Enable it in the GUI and re-run.`n" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
#  P/Invoke type definitions  (HOOK category)
# ---------------------------------------------------------------------------

if (-not ([System.Management.Automation.PSTypeName]'ObsDemo').Type) { Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class ObsDemo {

    // GetUserNameW
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool GetUserNameW(StringBuilder buf, ref int size);

    // GetComputerNameExW
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool GetComputerNameExW(int nameType, StringBuilder buf, ref int size);

    // GlobalMemoryStatusEx
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORYSTATUSEX {
        public uint  dwLength;
        public uint  dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

    // EnumDisplaySettingsW - IntPtr avoids all DEVMODE union marshaling issues
    // Caller allocates 220 bytes of unmanaged memory, sets dmSize, reads results directly.
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool EnumDisplaySettingsW(string devName, int modeNum, IntPtr devMode);


    // NetGetJoinInformation
    [DllImport("netapi32.dll", CharSet=CharSet.Unicode)]
    public static extern int NetGetJoinInformation(string lpServer, out IntPtr lpNameBuffer, out int pBufferType);
    [DllImport("netapi32.dll")]
    public static extern int NetApiBufferFree(IntPtr buffer);
}
"@ -ErrorAction Stop
}

# ---------------------------------------------------------------------------
#  SECTION 1 - Identity  [HOOK]
# ---------------------------------------------------------------------------

Write-Header "1. IDENTITY  [HOOK - requires Agent injection]"

$sb = New-Object System.Text.StringBuilder 256
$sz = 256
[ObsDemo]::GetUserNameW($sb, [ref]$sz) | Out-Null
$gotUser = $sb.ToString()
$expUser = if ($defMode) { "admin" } else { $spoofUser }
Write-Check "GetUserNameW" $expUser $gotUser "HOOK"

$sb2 = New-Object System.Text.StringBuilder 256
$sz2 = 256
[ObsDemo]::GetComputerNameExW(1, $sb2, [ref]$sz2) | Out-Null   # 1 = ComputerNameDnsHostname
$gotComp = $sb2.ToString()
$expComp = if ($defMode) { "DESKTOP-ANALY5T" } else { $spoofComp }
Write-Check "GetComputerNameExW" $expComp $gotComp "HOOK"

# ---------------------------------------------------------------------------
#  SECTION 2 - Memory  [HOOK]
# ---------------------------------------------------------------------------

Write-Header "2. MEMORY  [HOOK - requires Agent injection]"

$mem = New-Object ObsDemo+MEMORYSTATUSEX
$mem.dwLength = [System.Runtime.InteropServices.Marshal]::SizeOf($mem)
[ObsDemo]::GlobalMemoryStatusEx([ref]$mem) | Out-Null
$ramGb  = [math]::Round($mem.ullTotalPhys / 1GB, 2)
$expRam = if ($defMode) { "2"  } else { "16" }
$expStr = if ($defMode) { "~2 GB" } else { "~16 GB" }
Write-Check "GlobalMemoryStatusEx (Total RAM)" $expRam "$ramGb" "HOOK"
Write-Info  "  Reported value" "$ramGb GB  (expected $expStr)"

# ---------------------------------------------------------------------------
#  SECTION 3 - Display Resolution  [HOOK]
# ---------------------------------------------------------------------------

Write-Header "3. DISPLAY RESOLUTION  [HOOK - requires Agent injection]"

# Allocate unmanaged memory for DEVMODE (220 bytes), set dmSize, call, read results.
# dmSize at offset 68 (ushort), dmPelsWidth at 172 (uint), dmPelsHeight at 176 (uint).
# Pass NULL device name (primary display). The hook now returns TRUE with spoofed
# values even when the VMware driver would otherwise return FALSE for ENUM_CURRENT_SETTINGS.
$marshal = [System.Runtime.InteropServices.Marshal]
$dmPtr   = $marshal::AllocHGlobal(220)
try {
    $marshal::Copy(([byte[]]::new(220)), 0, $dmPtr, 220)   # zero the buffer
    $marshal::WriteInt16($dmPtr, 68, [int16]220)            # dmSize = 220
    [ObsDemo]::EnumDisplaySettingsW($null, -1, $dmPtr) | Out-Null
    $resW = [uint32]$marshal::ReadInt32($dmPtr, 172)
    $resH = [uint32]$marshal::ReadInt32($dmPtr, 176)
} finally {
    $marshal::FreeHGlobal($dmPtr)
}
$resStr = "$resW x $resH"
$expRes = if ($defMode) { "800 x 600" } else { "1920 x 1080" }
Write-Check "EnumDisplaySettingsW" $expRes $resStr "HOOK"

# ---------------------------------------------------------------------------
#  SECTION 4 - Domain Join  [HOOK + WMI]
# ---------------------------------------------------------------------------

Write-Header "4. DOMAIN JOIN  [HOOK for Win32 callers / WMI via profile.ps1]"

$nameBuf = [IntPtr]::Zero
$bufType = 0
$ret = [ObsDemo]::NetGetJoinInformation($null, [ref]$nameBuf, [ref]$bufType)
if ($ret -eq 0 -and $nameBuf -ne [IntPtr]::Zero) {
    $joinName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($nameBuf)
    [ObsDemo]::NetApiBufferFree($nameBuf) | Out-Null
} else {
    $joinName = "(call failed: $ret)"
}
$joinType = switch ($bufType) { 2 { "Workgroup" } 3 { "Domain" } default { "Unknown ($bufType)" } }

if ($domEnabled) {
    Write-Check "NetGetJoinInformation (name)"       $spoofDomain "HOOK"  $joinName
    Write-Check "NetGetJoinInformation (type)"       "Domain"     "HOOK"  $joinType
} else {
    Write-Check "NetGetJoinInformation (name)"       "WORKGROUP"  $joinName  "HOOK"
    Write-Check "NetGetJoinInformation (type)"       "Workgroup"  $joinType  "HOOK"
}

$cs = Get-WmiObject Win32_ComputerSystem
if ($domEnabled) {
    Write-Check "Win32_ComputerSystem.PartOfDomain"  "True"        "$($cs.PartOfDomain)"  "WMI"
    Write-Check "Win32_ComputerSystem.Domain"        $spoofDomain  "$($cs.Domain)"        "WMI"
} else {
    Write-Check "Win32_ComputerSystem.PartOfDomain"  "False"       "$($cs.PartOfDomain)"  "WMI"
    Write-Check "Win32_ComputerSystem.Domain"        "WORKGROUP"   "$($cs.Domain)"        "WMI"
}

# ---------------------------------------------------------------------------
#  SECTION 5 - Hardware Identity  [WMI]
# ---------------------------------------------------------------------------

Write-Header "5. HARDWARE IDENTITY  [WMI - intercepted by profile.ps1]"

$expSysMfg  = if ($defMode) { "VMware, Inc."            } else { "Dell Inc."       }
$expSysProd = if ($defMode) { "VMware Virtual Platform"  } else { "Precision 5560"  }
Write-Check "Win32_ComputerSystem.Manufacturer" $expSysMfg  $cs.Manufacturer  "WMI"
Write-Check "Win32_ComputerSystem.Model"        $expSysProd $cs.Model         "WMI"

$bios = Get-WmiObject Win32_BIOS
$expBiosMfg = if ($defMode) { "Phoenix Technologies LTD" } else { "Dell Inc."  }
$expBiosVer = if ($defMode) { "6.00"                     } else { "1.22.0"     }
$expSerial  = if ($defMode) { "VMware-56 4d 12 34"       } else { "7X8K9P2"    }
Write-Check "Win32_BIOS.Manufacturer"       $expBiosMfg $bios.Manufacturer      "WMI"
Write-Check "Win32_BIOS.SMBIOSBIOSVersion"  $expBiosVer $bios.SMBIOSBIOSVersion "WMI"
Write-Check "Win32_BIOS.SerialNumber"       $expSerial  $bios.SerialNumber      "WMI"

$csp = Get-WmiObject Win32_ComputerSystemProduct
$expUUID   = if ($defMode) { "564D1234-ABCD-EF01-2345-67890ABCDEF0"    } else { "44454C4C-0047-394D-574D-B8C04F473532" }
$expVendor = if ($defMode) { "VMware, Inc."                            } else { "Dell Inc." }
Write-Check "Win32_ComputerSystemProduct.UUID"   $expUUID   $csp.UUID   "WMI"
Write-Check "Win32_ComputerSystemProduct.Vendor" $expVendor $csp.Vendor "WMI"

$bb = Get-WmiObject Win32_BaseBoard
$expBbMfg  = if ($defMode) { "Intel Corporation"               } else { "Dell Inc." }
$expBbProd = if ($defMode) { "440BX Desktop Reference Platform" } else { "0G9MWF"   }
Write-Check "Win32_BaseBoard.Manufacturer" $expBbMfg  $bb.Manufacturer "WMI"
Write-Check "Win32_BaseBoard.Product"      $expBbProd $bb.Product      "WMI"

$cpu = Get-WmiObject Win32_Processor | Select-Object -First 1
$expCpu = if ($defMode) { "Xeon" } else { "i7-1185G7" }
Write-Check "Win32_Processor.Name (keyword)" $expCpu $cpu.Name "WMI"
Write-Info  "  Reported CPU" $cpu.Name

# ---------------------------------------------------------------------------
#  SECTION 6 - Storage  [WMI]
# ---------------------------------------------------------------------------

Write-Header "6. STORAGE  [WMI - intercepted by profile.ps1]"

$disks = @(Get-WmiObject Win32_DiskDrive)
if ($disks.Count -eq 0) {
    Write-Host "  (no disk drives returned)" -ForegroundColor DarkGray
} else {
    foreach ($d in $disks) { Write-Info "  Win32_DiskDrive.Model" $d.Model "WMI" }
    $expDisk = if ($defMode) { "VMware Virtual disk" } else { "SAMSUNG MZVL2512HCJQ" }
    Write-Check "Disk model keyword" $expDisk ($disks[0].Model) "WMI"
}

# ---------------------------------------------------------------------------
#  SECTION 7 - Network Adapter  [WMI name / HOOK for MAC OUI]
# ---------------------------------------------------------------------------

Write-Header "7. NETWORK ADAPTER  [WMI name via profile.ps1 / MAC OUI via HOOK]"

$nics = @(Get-WmiObject Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true })
if ($nics.Count -eq 0) {
    $nics = @(Get-WmiObject Win32_NetworkAdapter |
              Where-Object { $_.MACAddress -ne $null } |
              Select-Object -First 3)
}
foreach ($n in $nics) { Write-Info "  Adapter Name (WMI)" $n.Name "WMI" }
Write-Host "  NOTE: profile.ps1 only renames adapters matching VMware|vmxnet|Virtual." -ForegroundColor DarkGray
Write-Host "        Intel E1000 (82574L) emulation is not renamed - MAC OUI is the reliable indicator." -ForegroundColor DarkGray

Write-Host ""
Write-Host "  MAC OUI check (HOOK - GetAdaptersAddresses / GetAdaptersInfo):" -ForegroundColor DarkGray
$macs = @(Get-WmiObject Win32_NetworkAdapterConfiguration |
          Where-Object { $_.MACAddress -ne $null } |
          Select-Object -ExpandProperty MACAddress)
$expOUI = if ($defMode) { "00:0C:29" } else { "00:1B:21" }
foreach ($mac in $macs) {
    $oui  = ($mac -split "[:\-]" | Select-Object -First 3) -join ":"
    $pass = $oui -ieq $expOUI
    $col  = if ($pass) { "Green" } else { "Yellow" }
    Write-Host ("    MAC: {0}  OUI: {1}  (expected {2})" -f $mac, $oui, $expOUI) -ForegroundColor $col
}
Write-Host "  NOTE: WMI MACAddress bypasses the GetAdaptersAddresses hook." -ForegroundColor DarkGray
Write-Host "        Run 'ipconfig /all' from an injected process to verify OUI." -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
#  SECTION 8 - GPU  [WMI]
# ---------------------------------------------------------------------------

Write-Header "8. GPU  [WMI - intercepted by profile.ps1]"

$gpu = Get-WmiObject Win32_VideoController | Select-Object -First 1
$expGpu = if ($defMode) { "VMware SVGA 3D" } else { "Intel(R) Iris(R) Xe Graphics" }
Write-Check "Win32_VideoController.Name" $expGpu $gpu.Name "WMI"
Write-Info  "  Resolution (not spoofed via WMI)" "$($gpu.CurrentHorizontalResolution) x $($gpu.CurrentVerticalResolution)" "WMI gap"

# ---------------------------------------------------------------------------
#  SECTION 9 - Registry BIOS artefacts  [always visible, no injection needed]
# ---------------------------------------------------------------------------

Write-Header "9. REGISTRY BIOS ARTEFACTS  [persistent, no injection needed]"

$biosRegPath = "HKLM:\HARDWARE\DESCRIPTION\System\BIOS"
try {
    $biosReg = Get-ItemProperty -Path $biosRegPath -EA Stop
    $expBiosVendor = if ($defMode) { "Phoenix"  } else { "Dell"      }   # VMware VMs use Phoenix BIOS
    $expRegMfg     = if ($defMode) { "VMware"   } else { "Dell"      }
    $expRegProd    = if ($defMode) { "VMware"   } else { "Precision" }
    Write-Check "BIOS\BIOSVendor"           $expBiosVendor $biosReg.BIOSVendor         "REG"
    Write-Check "BIOS\SystemManufacturer"   $expRegMfg     $biosReg.SystemManufacturer "REG"
    Write-Check "BIOS\SystemProductName"    $expRegProd $biosReg.SystemProductName    "REG"
    Write-Info  "  BIOSVersion"             $biosReg.BIOSVersion
    Write-Info  "  BIOSReleaseDate"         $biosReg.BIOSReleaseDate
} catch {
    Write-Host "  (could not read $biosRegPath)" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
#  SECTION 10 - Known gaps
# ---------------------------------------------------------------------------

Write-Header "10. KNOWN GAPS  [not currently spoofed]"

Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
$screenW = try { [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width  } catch { "?" }
$screenH = try { [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height } catch { "?" }

Write-Host "  GetSystemMetrics SM_CXSCREEN / SM_CYSCREEN" -ForegroundColor Yellow
Write-Host "    Real value: $screenW x $screenH" -ForegroundColor DarkYellow
Write-Host "    Fix: add GetSystemMetrics hook in Hooks.c" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Win32_VideoController.CurrentHorizontalResolution / CurrentVerticalResolution" -ForegroundColor Yellow
Write-Host "    Real value: $($gpu.CurrentHorizontalResolution) x $($gpu.CurrentVerticalResolution)" -ForegroundColor DarkYellow
Write-Host "    Fix: add resolution fields to Win32_VideoController block in ArtefactManager.c" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Win32_NetworkAdapterConfiguration.MACAddress (WMI path)" -ForegroundColor Yellow
Write-Host "    The MAC OUI hook covers GetAdaptersAddresses/GetAdaptersInfo but not WMI MAC." -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
#  Summary
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host ("-" * 70) -ForegroundColor DarkGray
Write-Host ("  Done.  Mode: {0}  |  Domain: {1}" -f $modeStr, $(if ($domEnabled) { "ON ($spoofDomain)" } else { "OFF (WORKGROUP)" })) -ForegroundColor Cyan
Write-Host ("-" * 70) -ForegroundColor DarkGray
Write-Host ""
Write-Host "  [PASS] = value matches expected spoof output" -ForegroundColor Green
Write-Host "  [FAIL] = value does not match (check injection or profile.ps1)" -ForegroundColor Red
Write-Host "  [WMI]  = intercepted by profile.ps1 (always works in PS)" -ForegroundColor DarkGray
Write-Host "  [HOOK] = requires Agent DLL injected into this PS process" -ForegroundColor DarkGray
Write-Host "  [REG]  = persistent registry write, no injection needed" -ForegroundColor DarkGray
Write-Host ""
