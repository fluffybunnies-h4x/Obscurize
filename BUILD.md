# Obscurize – Build & Deployment Guide

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Visual Studio 2026 | 18.x | Community edition is sufficient |
| MSVC v145 toolset | (VS installer) | C/C++ development workload |
| Windows 10 SDK | 10.0.x | Any recent SDK build |
| .NET Framework 4.8 Targeting Pack | (VS installer) | For ObscurizeGUI |

### Verify toolset selection
The projects use `<PlatformToolset>v145</PlatformToolset>` (VS 2026).
If you see "v145 toolset not found" errors, install the **MSVC v145** build
tools via the VS installer (C++ workload → Individual components).

---

## Repository Layout

```
Obscurize/
├── Obscurize.sln                  ← Open this in Visual Studio
├── output/                        ← All built binaries land here (auto-created)
│
├── ObscurizeShared/
│   ├── ObscurizeDef.h             ← C constants (modes, pipe name, spoof values)
│   └── ObscurizeConst.cs          ← C# mirror of ObscurizeDef.h (linked into GUI)
│
├── ObscurizeAgent/                ← Injected DLL (x86 + x64)
│   ├── Agent.c / .h
│   ├── Config.c / .h
│   ├── Hooks.c / .h               ← 20 Detours API hooks
│   ├── Spoof.c / .h               ← Lookup tables, artefact install/remove
│   ├── SmbiosSpoof.c / .h         ← Raw SMBIOS (RSMB) table patching
│   ├── ObscurizeAgent-x86.vcxproj ← builds ObscurizeAgent32.dll → output\
│   └── ObscurizeAgent-x64.vcxproj ← builds ObscurizeAgent64.dll → output\
│
├── ObscurizeService/              ← Windows Service EXE (x64)
│   ├── ServiceMain.c / .h
│   ├── AgentInjector.c / .h
│   ├── ProcessListener.c / .h
│   ├── ControlPipeListener.c / .h
│   ├── ArtefactManager.c / .h
│   ├── ObscurizeService.rc        ← embeds Agent DLLs from output\ as RCDATA
│   └── ObscurizeService.vcxproj  ← builds ObscurizeService.exe → output\
│
├── ObscurizeGUI/                  ← WinForms tray application (.NET 4.8)
│   ├── Program.cs
│   ├── TrayApplicationContext.cs
│   ├── TrayIconRenderer.cs
│   ├── StatusPoller.cs
│   ├── ControlPipeClient.cs
│   ├── MainWindow.cs
│   └── ObscurizeGUI.csproj
│
└── r77-rootkit/r77-rootkit-master/ ← Submodule – read-only reference
    ├── r77api/                     ← ntdll.h, r77mindef.h, r77win.h, r77header.h
    ├── r77/detours.h
    └── SlnBin/x86|x64/detours.lib  ← Pre-built Detours static libs
```

---

## Build Order (CRITICAL)

The build order matters because ObscurizeService embeds the Agent DLLs as
resources. They must exist in `output\` before the Service is compiled.

```
1. ObscurizeAgent-x86  →  output\ObscurizeAgent32.dll
2. ObscurizeAgent-x64  →  output\ObscurizeAgent64.dll
3. ObscurizeService    →  output\ObscurizeService.exe   (reads #1 and #2)
4. ObscurizeGUI        →  output\ObscurizeGUI.exe
```

Visual Studio respects this order automatically via the ProjectDependencies
entries in `Obscurize.sln`. Building the whole solution with **Build → Build
Solution** (Ctrl+Shift+B) in Release mode will follow the correct sequence.

---

## Building with Visual Studio 2026 (Recommended)

1. Open `Obscurize.sln`.
2. In the Configuration drop-down select **Release** / **Any CPU** (the
   solution platform; individual project platforms are fixed in the .sln).
3. Press **Ctrl+Shift+B** (Build Solution).
4. Verify all four projects succeed; binaries appear in `output\`.

---

## Building from the Command Line (MSBuild)

Open a **x64 Native Tools Command Prompt for VS 2026** (from the Start menu).

```cmd
cd /d C:\path\to\Obscurize

:: Create output directory
mkdir output 2>nul

:: 1. Agent DLL (32-bit)
msbuild ObscurizeAgent\ObscurizeAgent-x86.vcxproj ^
    /p:Configuration=Release /p:Platform=Win32 /t:Rebuild /m

:: 2. Agent DLL (64-bit)
msbuild ObscurizeAgent\ObscurizeAgent-x64.vcxproj ^
    /p:Configuration=Release /p:Platform=x64 /t:Rebuild /m

:: 3. Service EXE (64-bit) – embeds agent DLLs from output\
msbuild ObscurizeService\ObscurizeService.vcxproj ^
    /p:Configuration=Release /p:Platform=x64 /t:Rebuild /m

:: 4. GUI EXE (.NET 4.8)
msbuild ObscurizeGUI\ObscurizeGUI.csproj ^
    /p:Configuration=Release /t:Rebuild /m

:: Or build the whole solution in one command (respects dependency order):
:: msbuild Obscurize.sln /p:Configuration=Release /t:Rebuild /m
```

Expected output files:
```
output\
  ObscurizeAgent32.dll
  ObscurizeAgent64.dll
  ObscurizeService.exe
  ObscurizeGUI.exe
```

---

## Service Installation

All commands below require an **elevated (Administrator) Command Prompt**.

### Install the service

```cmd
sc create ObscurizeService ^
    binPath= "C:\Path\To\output\ObscurizeService.exe" ^
    start= auto ^
    DisplayName= "Obscurize Defensive Deception Service"

sc description ObscurizeService ^
    "Provides ring-3 API spoofing and deception artefact management."
```

### Start / Stop

```cmd
sc start ObscurizeService
sc stop  ObscurizeService
```

### Set startup mode (if changing from manual later)

```cmd
sc config ObscurizeService start= auto   :: start with Windows
sc config ObscurizeService start= demand :: start manually
```

### Remove the service

```cmd
sc stop   ObscurizeService
sc delete ObscurizeService
```

---

## Running the GUI

After the service is running, launch `output\ObscurizeGUI.exe`. It requires
elevation (declared in its manifest) so Windows will prompt for UAC.

The tray icon will show grey until the service is detected. Once connected,
use the context menu to:

- **Open Control Panel** – opens the main dark-theme window
- **Enable / Disable** – toggle the spoofing on/off
- **Mode → Defensive** – appear as a VM (malware self-terminates)
- **Mode → Trap** – appear as real hardware (malware executes fully)

---

## Verifying the Build

### Check service status via pipe

The quickest smoke-test is to confirm the control pipe is alive:

```powershell
# PowerShell – attempt a pipe connection
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.','ObscurizeCtrl','InOut')
$pipe.Connect(2000)
Write-Host "Pipe connected: $($pipe.IsConnected)"
$pipe.Dispose()
```

### Check registry config key

```cmd
reg query HKLM\SOFTWARE\ObscurizeConfig
```

Expected values after first service start:
```
Enabled        REG_DWORD  0x0   (or 0x1 if you enabled it)
Mode           REG_DWORD  0x1   (1=Defensive, 2=Trap)
SpoofUsername  REG_SZ     admin
```

### Check Agent injection

```powershell
# List processes that have the agent injected
# (processes with OBS_AGENT_SIGNATURE at PE offset 40)
Get-Process | ForEach-Object {
    try {
        $h = [System.Diagnostics.Process]::GetProcessById($_.Id).Handle
        Write-Host "$($_.Name) ($($_.Id))"
    } catch {}
}
```

For a more precise check, use Process Hacker or x64dbg to inspect the first
64 bytes of a target process's PE header — offset 0x28 (decimal 40) should
contain `0x4253` (OBS_AGENT_SIGNATURE) after injection.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| LNK1104: detours.lib not found | SlnBin path wrong | Confirm r77-rootkit submodule is present at `r77-rootkit\r77-rootkit-master\` |
| RC1015: cannot open file ObscurizeAgent32.dll | Agent DLLs not built yet | Build Agent-x86 and Agent-x64 first |
| C1083: ObscurizeDef.h not found | Include path not resolving | Open .vcxproj and verify `$(SolutionDir)ObscurizeShared` in AdditionalIncludeDirectories |
| Pipe connection refused (GUI grey) | Service not running | `sc start ObscurizeService` as Administrator |
| UAC prompt on every GUI launch | Expected — `requireAdministrator` manifest | Run once, pin to taskbar |
| Service fails to start (Error 5) | LocalSystem needs SeDebugPrivilege | Ensure service is configured as LocalSystem (default with `sc create`) |

---

## Quick Reference: Control Codes

| Code | Hex | Action |
|---|---|---|
| `OBS_CTRL_ENABLE`            | 0x0001 | Enable spoofing |
| `OBS_CTRL_DISABLE`           | 0x0002 | Disable spoofing |
| `OBS_CTRL_SET_MODE_DEFENSIVE`| 0x0003 | Switch to Defensive mode |
| `OBS_CTRL_SET_MODE_TRAP`     | 0x0004 | Switch to Trap mode |
| `OBS_CTRL_QUERY_STATUS`      | 0x0005 | Query current status (returns DWORD) |
| `OBS_CTRL_INJECT_ALL`        | 0x0006 | Force inject agent into all processes |
| `OBS_CTRL_DETACH_ALL`        | 0x0007 | Detach agent from all processes |

These can be sent manually with any named-pipe client for testing.

---

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────────┐
│  ObscurizeGUI.exe  (WinForms, .NET 4.8, tray icon)             │
│  • StatusPoller polls pipe every 2 s                            │
│  • ControlPipeClient sends DWORD control codes                  │
└──────────────┬──────────────────────────────────────────────────┘
               │ \\.\pipe\ObscurizeCtrl  (named pipe)
┌──────────────▼──────────────────────────────────────────────────┐
│  ObscurizeService.exe  (Windows Service, LocalSystem, x64)      │
│  • Injects Agent DLL into every new process (ProcessListener)   │
│  • Manages registry artefacts (ArtefactManager)                 │
│  • Reads/writes HKLM\SOFTWARE\ObscurizeConfig                   │
└──────────────┬──────────────────────────────────────────────────┘
               │ Reflective DLL injection (r77api InjectDll)
┌──────────────▼──────────────────────────────────────────────────┐
│  ObscurizeAgent32/64.dll  (injected into every user process)    │
│  • 20 Detours hooks on Win32 + NT APIs                          │
│  • Reads config from registry every 1 s                         │
│                                                                  │
│  Both modes:                                                     │
│  GetUserNameW/A            → mode-appropriate username          │
│  GetComputerNameExW/A      → mode-appropriate computer name     │
│  GlobalMemoryStatusEx      → 2 GB (Defensive) / 16 GB (Trap)   │
│  EnumDisplaySettingsW      → 800×600 (Def) / 1920×1080 (Trap)  │
│  GetAdaptersAddresses/Info → VMware OUI (Def) / Intel (Trap)   │
│  NtQueryValueKey           → VMware BIOS (Def) / Dell (Trap)   │
│  GetSystemFirmwareTable    → VMware RSMB (Def) / Dell (Trap)   │
│  CreateProcessW/A          → strips -NoProfile from PS spawns  │
│                                                                  │
│  Trap mode only:                                                 │
│  EnumServicesStatusExW/A   → filters VM service names           │
│  NtQuerySystemInformation  → filters VM process names           │
│  NtEnumerateKey/NtQueryKey → filters VM vendor registry keys    │
│                                                                  │
│  systeminfo.exe only (Trap mode):                               │
│  WriteFile / WriteConsoleA/W → patches stdout VM→Dell strings  │
└─────────────────────────────────────────────────────────────────┘
```
