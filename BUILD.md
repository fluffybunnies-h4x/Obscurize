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

VS 2022 (v170) does **not** ship the v145 toolset. It can be used only by
overriding the toolset on the command line
(`/p:PlatformToolset=v143`), which is untested and unsupported.

---

## Repository Layout

```
Obscurize/
├── Obscurize.sln                  ← Open this in Visual Studio
├── output/                        ← Agent DLL + Service staging dir
│
├── ObscurizeShared/
│   ├── ObscurizeDef.h             ← C constants (single source of truth)
│   ├── ObscurizeConst.cs          ← C# mirror of ObscurizeDef.h (linked into GUI)
│   └── Obscurize.ico              ← Shared app icon (Service .rc + GUI csproj)
│
├── ObscurizeAgent/                ← Injected DLL (x86 + x64)
│   ├── Agent.c / .h
│   ├── Config.c / .h
│   ├── Hooks.c / .h               ← 26 Detours API hooks
│   ├── Spoof.c / .h               ← Lookup tables, artefact install/remove
│   ├── SmbiosSpoof.c / .h         ← Raw SMBIOS (RSMB) table patching
│   ├── ObscurizeAgent-x86.vcxproj ← builds ObscurizeAgent32.dll → output\
│   └── ObscurizeAgent-x64.vcxproj ← builds ObscurizeAgent64.dll → output\
│
├── ObscurizeService/              ← Windows Service EXE (x64)
│   ├── ServiceMain.c / .h         ← SCM entry, control dispatch, session identity
│   ├── AgentInjector.c / .h
│   ├── ProcessListener.c / .h
│   ├── ControlPipeListener.c / .h
│   ├── ArtefactManager.c / .h
│   ├── ObscurizeService.rc        ← embeds Agent DLLs from output\ as RCDATA
│   └── ObscurizeService.vcxproj   ← builds ObscurizeService.exe → output\
│
├── ObscurizeGUI/                  ← WinForms tray application (.NET 4.8)
│   ├── Program.cs
│   ├── TrayApplicationContext.cs
│   ├── TrayIconRenderer.cs
│   ├── StatusPoller.cs
│   ├── ControlPipeClient.cs
│   ├── ServiceLocator.cs          ← finds the randomized service by binary name
│   ├── MainWindow.cs
│   ├── Properties/app.manifest    ← requireAdministrator
│   └── ObscurizeGUI.csproj
│
├── ObscurizeInitializer.ps1       ← One-shot deploy / uninstall script
├── Demo-Obscurize.ps1             ← Operator verification script
│
└── r77-rootkit/r77-rootkit-master/ ← Vendored read-only reference (NOT a submodule;
    ├── r77api/                       the files are tracked directly in this repo)
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
4. ObscurizeGUI        →  ObscurizeGUI\bin\Release\net48\ObscurizeGUI.exe
```

Visual Studio respects this order automatically via the ProjectDependencies
entries in `Obscurize.sln`. Building the whole solution in Release mode will
follow the correct sequence.

> **Note:** the Agent DLLs and `ObscurizeService.exe` are `.gitignore`d. They
> are generated build outputs that the service `.rc` embeds as the payload
> injected into every process — committing them would let a stale or tampered
> clone ship without a clean rebuild. Always build from source.

---

## Building with Visual Studio 2026 (Recommended)

1. Open `Obscurize.sln`.
2. In the Configuration drop-down select **Release** / **Any CPU**.
3. Press **Ctrl+Shift+B** (Build Solution).
4. Verify all four projects succeed.

Each project is pinned to its correct platform in the `.sln` regardless of
which solution platform you pick, so `Any CPU`, `x64`, and `x86` all produce
the same four binaries.

---

## Building from the Command Line

### Using devenv.com

```cmd
cd /d C:\path\to\Obscurize

"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\devenv.com" ^
    Obscurize.sln /Build "Release|Any CPU"
```

> **Use `devenv.com`, not `devenv.exe`.** The `.exe` is a GUI application and
> displays its help as a modal dialog when invoked from a shell. The `.com`
> is the console wrapper.

> **Valid solution configurations are `Release|Any CPU`, `Release|x64`, and
> `Release|x86` only.** Passing `"Release|Win32"` fails — `Win32` is a
> *project* platform (used by ObscurizeAgent-x86), not a solution platform.
> To build a single project, pass its full name with `/Project`, e.g.
> `/Project ObscurizeAgent-x86` (not `ObscurizeAgent`).

### Using MSBuild

Open a **x64 Native Tools Command Prompt for VS 2026** (from the Start menu).

```cmd
cd /d C:\path\to\Obscurize

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

> If invoking `MSBuild.exe` by full path without the VS environment, pass
> `-noAutoResponse` — the `MSBuild.rsp` in that directory injects extra args.

Expected output files:
```
output\
  ObscurizeAgent32.dll
  ObscurizeAgent64.dll
  ObscurizeService.exe

ObscurizeGUI\bin\Release\net48\
  ObscurizeGUI.exe
```

### Build hygiene

Release builds emit no PDB and no absolute source paths — neither the C/C++
projects nor the managed GUI (`<DebugType>none</DebugType>` plus `<PathMap>`
in `ObscurizeGUI.csproj`). Verify before distributing binaries:

```powershell
$s = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes("output\ObscurizeService.exe"))
if ($s -match '[A-Za-z]:\\Users\\') { "LEAK: $($Matches[0])" } else { "clean" }
```

---

## Deployment

### Recommended: ObscurizeInitializer.ps1

`ObscurizeInitializer.ps1` performs the whole install in one step. Copy
`ObscurizeService.exe` and `ObscurizeGUI.exe` into the install directory
(default `C:\ProgramData\Obscurize`), then run from an **elevated** PowerShell
session:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\ObscurizeInitializer.ps1
```

It registers the service, starts it, creates a logon task for the GUI
(elevated, no UAC prompt) and launches the GUI.

**The service name is randomized at install time** for OPSEC — the chosen
internal name, display name, and description are written to `service.cfg` in
the install directory. That file is `.gitignore`d and is what the uninstaller
and the GUI's `ServiceLocator` read to find the service. Override the
randomization explicitly if you need a fixed name:

```powershell
.\ObscurizeInitializer.ps1 -InstallPath "D:\Tools\Obscurize"
.\ObscurizeInitializer.ps1 -ServiceName "WinDiagSvc" -DisplayName "Windows Diagnostic Service"
.\ObscurizeInitializer.ps1 -Uninstall
.\ObscurizeInitializer.ps1 -Help
```

### Manual installation

For environments where the script cannot run. All commands require an
**elevated Command Prompt**. Substitute your own service name.

```cmd
sc create ObscurizeService ^
    binPath= "C:\ProgramData\Obscurize\ObscurizeService.exe" ^
    start= demand ^
    obj= LocalSystem ^
    DisplayName= "Obscurize Defensive Deception Service"

sc description ObscurizeService ^
    "Provides ring-3 API spoofing and deception artefact management."

sc start ObscurizeService
```

### Start / Stop

```cmd
sc start <ServiceName>
sc stop  <ServiceName>
```

### Startup mode

The service installs as `demand` (manual) by default so an unforeseen
compatibility issue cannot cause a boot loop. After validating stability:

```cmd
sc config <ServiceName> start= delayed-auto  :: recommended
sc config <ServiceName> start= auto          :: not recommended
sc config <ServiceName> start= demand        :: revert to manual
```

> Prefer `delayed-auto` over `auto` — it lets the kernel, AV, and core
> security services fully initialise before Obscurize begins injecting.

### Remove

```cmd
sc stop   <ServiceName>
sc delete <ServiceName>
```

Or `.\ObscurizeInitializer.ps1 -Uninstall`, which also removes the logon task,
the config key, VM artefact keys, `profile.ps1`, and the install directory.

---

## Running the GUI

After the service is running, launch `ObscurizeGUI.exe`. It requires elevation
(declared in its manifest) so Windows will prompt for UAC — it needs to write
to HKLM and reach the LocalSystem pipe.

The tray icon shows grey until the service is detected. Once connected:

- **Open Control Panel** – dark-theme main window
- **Enable / Disable** – toggle spoofing
- **Mode → Defensive** – appear as a VM (malware self-terminates)
- **Mode → Trap** – appear as real hardware (malware executes fully)

The control panel also shows the active (randomized) service identity, so you
do not need to open `service.cfg` to find the name for `sc config`.

---

## Verifying the Build

### Check the control pipe

```powershell
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.','ObscurizeCtrl','InOut')
$pipe.Connect(2000)
Write-Host "Pipe connected: $($pipe.IsConnected)"
$pipe.Dispose()
```

### Check the config registry key

The key lives at an OPSEC-camouflaged path, **not** `HKLM\SOFTWARE\Obscurize`:

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DeviceCache"
```

Values written on first service start:

| Value | Type | Meaning |
|---|---|---|
| `DeviceState` | DWORD | `0` = disabled, `1` = enabled |
| `CacheLevel` | DWORD | `1` = Defensive, `2` = Trap |
| `NetworkScope` | DWORD | `0` = domain hook off, `1` = WORKGROUP, `2` = domain-joined |
| `NetworkDomain` | SZ | Spoofed domain name |
| `UserSID` | SZ | Trap-mode pinned username (deleted in Defensive) |
| `HostBinding` | SZ | Trap-mode pinned computer name (deleted in Defensive) |
| `HardwarePrefix` | BINARY | 3-byte MAC OUI for Trap mode |

> **The key is hidden from registry *enumeration*** by the `NtEnumerateKey` /
> `NtQueryKey` hooks in every injected process, including `regedit.exe`. It
> will not appear when expanding the `CurrentVersion` tree. Direct path access
> is not hooked, so `reg query` with the full path (above) and regedit's
> address bar (Ctrl+L) both work.

### Check Agent injection

Injected processes carry `OBS_AGENT_SIGNATURE` in the PE header at offset
0x28 (decimal 40). Inspect with Process Hacker or x64dbg.

The most practical end-to-end check is `Demo-Obscurize.ps1`, which exercises
every active spoof and reports pass/fail against the expected values for the
current mode. Run it elevated, in a terminal opened **after** the service
started (so the Agent is injected and `profile.ps1` is loaded).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| devenv prints its help text and exits | Invalid solution config, or `devenv.exe` used | Use `devenv.com` with `"Release\|Any CPU"` — not `"Release\|Win32"` |
| "The parameter is incorrect" from devenv | Wrong `/Project` name | Use the full name, e.g. `ObscurizeAgent-x86` |
| LNK1104: detours.lib not found | SlnBin path wrong | Confirm `r77-rootkit\r77-rootkit-master\SlnBin\` is present |
| RC1015: cannot open ObscurizeAgent32.dll | Agent DLLs not built yet | Build Agent-x86 and Agent-x64 first |
| C1083: ObscurizeDef.h not found | Include path not resolving | Verify `$(SolutionDir)ObscurizeShared` in AdditionalIncludeDirectories |
| Pipe connection refused (GUI grey) | Service not running | `sc start <ServiceName>` as Administrator |
| UAC prompt on every GUI launch | Expected — `requireAdministrator` manifest | Use the logon task created by the initializer |
| Service fails to start (Error 5) | Needs SeDebugPrivilege | Ensure the service runs as LocalSystem |
| `Get-Service` shows VM services in Trap mode | Stale Agent build | Rebuild; plain `EnumServicesStatusW/A` hooks were added in v1.8.9 |

---

## Quick Reference: Control Codes

Send a 4-byte little-endian DWORD to `\\.\pipe\ObscurizeCtrl`.

| Code | Hex | Action |
|---|---|---|
| `OBS_CTRL_ENABLE`             | 0x0001 | Enable spoofing |
| `OBS_CTRL_DISABLE`            | 0x0002 | Disable spoofing |
| `OBS_CTRL_SET_MODE_DEFENSIVE` | 0x0003 | Defensive mode; clears pinned session identity |
| `OBS_CTRL_SET_MODE_TRAP`      | 0x0004 | Trap mode; pins session identity if unset |
| `OBS_CTRL_QUERY_STATUS`       | 0x0005 | Query status (reply DWORD) |
| `OBS_CTRL_INJECT_ALL`         | 0x0006 | Force inject into all processes |
| `OBS_CTRL_DETACH_ALL`         | 0x0007 | Detach from all processes |
| `OBS_CTRL_DOMAIN_OFF`         | 0x0008 | Domain hook off — real domain info returned |
| `OBS_CTRL_DOMAIN_WORKGROUP`   | 0x0009 | Force `WORKGROUP` / `PartOfDomain: False` |
| `OBS_CTRL_INJECT_PID`         | 0x000A | Agent→Service: inject into suspended PID (two DWORDs: code + PID) |
| `OBS_CTRL_DOMAIN_JOINED`      | 0x000B | Force `CORP.DEV` / `PartOfDomain: True` |

Status replies: `0x0001` disabled, `0x0002` Defensive, `0x0003` Trap,
`0xFFFF` error.

**Access control:** only `OBS_CTRL_QUERY_STATUS` is permitted from any
integrity level. Every mutating command requires a **High integrity**
(elevated) caller, verified via `ImpersonateNamedPipeClient`.
`OBS_CTRL_INJECT_PID` bypasses that check by design — the sending Agent runs
at medium integrity — but the server never impersonates for that code.

---

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────────┐
│  ObscurizeGUI.exe  (WinForms, .NET 4.8, tray icon)             │
│  • StatusPoller polls pipe every 2 s                            │
│  • ControlPipeClient sends DWORD control codes                  │
│  • ServiceLocator resolves the randomized service name          │
└──────────────┬──────────────────────────────────────────────────┘
               │ \\.\pipe\ObscurizeCtrl  (named pipe)
┌──────────────▼──────────────────────────────────────────────────┐
│  ObscurizeService.exe  (Windows Service, LocalSystem, x64)      │
│  • Injects Agent into every new process (100 ms poll)           │
│  • Synchronous pre-injection for wmic.exe                       │
│  • Manages registry artefacts + system-wide profile.ps1         │
│  • Config: HKLM\...\CurrentVersion\DeviceCache                  │
└──────────────┬──────────────────────────────────────────────────┘
               │ Reflective DLL injection (r77api InjectDll)
┌──────────────▼──────────────────────────────────────────────────┐
│  ObscurizeAgent32/64.dll  (injected into every user process)    │
│  • 26 Detours hooks on Win32 + NT APIs                          │
│  • Reads config from registry every 1 s                         │
│                                                                  │
│  Both modes:                                                     │
│  GetUserNameW/A            → mode-appropriate username          │
│  GetUserNameExW  (secur32) → DOMAIN\user for plain whoami       │
│  GetComputerNameExW/A      → mode-appropriate computer name     │
│  GlobalMemoryStatusEx      → 2 GB (Def) / 16 GB (Trap)          │
│  EnumDisplaySettingsW      → 800×600 (Def) / 1920×1080 (Trap)   │
│  GetSystemMetrics          → same resolutions                   │
│  GetAdaptersAddresses/Info → VMware OUI (Def) / Intel (Trap)    │
│  NtQueryValueKey           → VMware BIOS (Def) / Dell (Trap)    │
│  GetSystemFirmwareTable    → VMware RSMB (Def) / Dell (Trap)    │
│  CreateProcessW/A          → strips -NoProfile; wmic pre-inject │
│  NetGetJoinInformation     → domain join state (toggle-gated)   │
│  NtEnumerateKey/NtQueryKey → hides the Obscurize config key     │
│                                                                  │
│  Trap mode only:                                                 │
│  EnumServicesStatusExW/A   → filters VM service names           │
│  EnumServicesStatusW/A     → same, for Get-Service (managed)    │
│  NtQuerySystemInformation  → filters VM process names           │
│  NtEnumerateKey/NtQueryKey → also filters VM vendor keys        │
│                                                                  │
│  systeminfo.exe / wmic.exe only (Trap mode):                    │
│  WriteFile / WriteConsoleA/W → patches stdout VM→Dell strings,  │
│    plus Host Name, Processor, memory and domain fields          │
│                                                                  │
│  whoami.exe only:                                                │
│  LookupAccountSidW         → resolves the spoofed SID identity.  │
│    Deliberately NOT hooked process-wide: the security/COM stack  │
│    (e.g. systeminfo's WMI client) resolves the current-user SID  │
│    during connection setup and breaks if it is spoofed.          │
└─────────────────────────────────────────────────────────────────┘
```
