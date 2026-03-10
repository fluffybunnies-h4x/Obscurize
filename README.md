# Obscurize

A defensive deception tool that uses userland API hooking to manipulate what
a running process perceives about the host environment. Designed for two
distinct threat scenarios:

- **Defensive Mode** — makes a real host look like a sandboxed VM so that
  malware performing anti-analysis checks detects a controlled environment
  and self-terminates before executing its payload.
- **Trap Mode** — makes a honeypot VM look like genuine physical hardware so
  that malware passes its anti-analysis checks and executes fully, enabling
  observation and threat intelligence collection.

Spoofing is applied at runtime via an injected DLL — no system files are
modified, no kernel driver is required. All changes are reversed when the
service stops.

---

## Threat Model & Background

Modern malware routinely performs environment checks before executing its
payload. The DEADVAX campaign (Securonix, 2024) is a documented example:
it inspects the current username, available RAM, MAC address OUI, WMI BIOS
strings, and the presence of VMware / VirtualBox registry keys and artifact
files before proceeding. If the host looks like a sandbox, the malware exits
silently.

Obscurize exploits this behaviour in two directions:

| Scenario | Goal | What Obscurize does |
|---|---|---|
| Production host | Blend into malware's "don't execute" category | Present all the hallmarks of a sandbox (VM BIOS, low RAM, analysis username, VMware MAC OUI) |
| Honeypot VM | Blend into malware's "safe to execute" category | Strip all VM indicators, present real-hardware profile (Dell BIOS, 16 GB RAM, normal username, Intel MAC OUI) |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  ObscurizeGUI.exe  (.NET 4.8 WinForms, system tray)            │
│  • Status poller pings control pipe every 2 s                   │
│  • Tray icon: blue shield (Defensive) / amber (Trap) / grey     │
│  • Main window: live spoof-value display + event log            │
└──────────────┬──────────────────────────────────────────────────┘
               │  \\.\pipe\ObscurizeCtrl  (named pipe, DWORD codes)
┌──────────────▼──────────────────────────────────────────────────┐
│  ObscurizeService.exe  (Windows Service, LocalSystem, x64)      │
│  • Monitors new processes via EnumProcesses polling             │
│  • Reflectively injects Agent DLL into every user process       │
│  • Manages persistent registry / filesystem artefacts           │
│  • Config store: HKLM\SOFTWARE\ObscurizeConfig                  │
└──────────────┬──────────────────────────────────────────────────┘
               │  Reflective DLL injection (r77api InjectDll)
┌──────────────▼──────────────────────────────────────────────────┐
│  ObscurizeAgent32/64.dll  (injected into every user process)    │
│  • Microsoft Detours hooks on Win32 + NT APIs                   │
│  • Reads config from registry every 1 s                         │
│  • Hooks are installed/removed without restarting the process   │
└─────────────────────────────────────────────────────────────────┘
```

### Components

| Component | Language | Output |
|---|---|---|
| **ObscurizeAgent** | C (Win32) | `ObscurizeAgent32.dll` + `ObscurizeAgent64.dll` |
| **ObscurizeService** | C (Win32) | `ObscurizeService.exe` |
| **ObscurizeGUI** | C# / WinForms (.NET 4.8) | `ObscurizeGUI.exe` |
| **ObscurizeShared** | C header + C# file | Shared constants (no separate binary) |

---

## Spoofing Coverage

### Defensive Mode (appear as a VM / sandbox)

| Check intercepted | Spoofed value |
|---|---|
| `GetUserNameW/A` | `admin` |
| `GetComputerNameExW/A` | `DESKTOP-ANALY5T` |
| `GlobalMemoryStatusEx` | 2 048 MB physical RAM |
| `EnumDisplaySettingsW` | 800 × 600 resolution |
| `GetAdaptersAddresses` / `GetAdaptersInfo` | MAC OUI `00:0C:29` (VMware) |
| `NtQueryValueKey` (BIOS key) | VMware BIOS strings |
| `HKLM\HARDWARE\DESCRIPTION\System\BIOS` | VMware manufacturer / product |
| `HKLM\SOFTWARE\VMware Inc.\VMware Tools` | Created (presence check) |
| `HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions` | Created (presence check) |
| `%TEMP%\mapping.csv`, `VBE_marker.tmp` | **Not** created (absence triggers DEADVAX abort) |

### Trap Mode (appear as real hardware)

| Check intercepted | Spoofed value |
|---|---|
| `GetUserNameW/A` | Config-defined username |
| `GetComputerNameExW/A` | Config-defined computer name |
| `GlobalMemoryStatusEx` | 16 384 MB physical RAM |
| `EnumDisplaySettingsW` | 1920 × 1080 resolution |
| `GetAdaptersAddresses` / `GetAdaptersInfo` | MAC OUI `00:1B:21` (Intel) |
| `NtQueryValueKey` (BIOS key) | Dell BIOS strings |
| `EnumServicesStatusExW/A` | VM service names filtered out |
| `NtQuerySystemInformation` | VM process names filtered out |
| `NtEnumerateKey` / `NtQueryKey` | VM vendor registry subkeys filtered |
| VMware / VirtualBox registry keys | Removed |
| `%TEMP%\mapping.csv`, `VBE_marker.tmp` | Created (presence satisfies DEADVAX check) |

---

## Design Decisions

**Pure userland (Ring 3)** — No kernel driver is required. Hooks are installed
via Microsoft Detours (statically linked), the same library used by r77-rootkit.
This avoids driver signing requirements entirely for v1.

**Reflective injection** — The Agent DLL is embedded as an RCDATA resource
inside the Service EXE (IDs 101 and 102 for x86/x64). No Agent DLL file ever
appears on disk. Injection uses r77api's `InjectDll()` path via
`NtCreateThreadEx`.

**Process-wide coverage** — The Service's process listener polls `EnumProcesses`
every 100 ms and injects the Agent into any newly-spawned process, ensuring
malware is hooked from the moment it starts.

**Live config** — Each Agent instance polls `HKLM\SOFTWARE\ObscurizeConfig`
every 1 second. Mode and spoof-value changes propagate to all processes within
~1 second without any restart.

**Reversible** — On service stop, all injected agents are detached via the
stored function pointer in the PE header (r77-style header marker), all
artefact registry keys are deleted, and all decoy files are removed.

**r77-rootkit infrastructure** — The injection engine, PE header marking, NT
API definitions, and PEB walking utilities come directly from the
[r77-rootkit](https://github.com/bytecode77/r77-rootkit) project (used as a
read-only reference, not modified). Detours static libraries are taken from
r77's `SlnBin/` directory.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Windows 10 / 11 x64 | Target platform |
| Visual Studio 2026 | C/C++ and .NET workloads |
| MSVC v145 toolset | Included with VS 2026 |
| Windows 10 SDK | Any recent build |
| .NET Framework 4.8 Targeting Pack | Ships with Windows 10/11; VS installer option |

---

## Building

Open `Obscurize.sln` in Visual Studio 2026, set the configuration to
**Release**, and press **Ctrl+Shift+B**.

The solution enforces the correct build order via project dependencies:

```
ObscurizeAgent-x86  →  output\ObscurizeAgent32.dll
ObscurizeAgent-x64  →  output\ObscurizeAgent64.dll
ObscurizeService    →  output\ObscurizeService.exe   (embeds both DLLs)
ObscurizeGUI        →  output\ObscurizeGUI.exe
```

### Command-line build

From an **x64 Native Tools Command Prompt for VS 2026**:

```cmd
cd /d C:\path\to\Obscurize
mkdir output 2>nul

msbuild ObscurizeAgent\ObscurizeAgent-x86.vcxproj /p:Configuration=Release /p:Platform=Win32 /t:Rebuild /m
msbuild ObscurizeAgent\ObscurizeAgent-x64.vcxproj /p:Configuration=Release /p:Platform=x64  /t:Rebuild /m
msbuild ObscurizeService\ObscurizeService.vcxproj  /p:Configuration=Release /p:Platform=x64  /t:Rebuild /m
msbuild ObscurizeGUI\ObscurizeGUI.csproj           /p:Configuration=Release                  /t:Rebuild /m
```

See [BUILD.md](BUILD.md) for full details including service installation
commands, smoke-test procedures, and troubleshooting.

---

## Service Installation

Run the following from an elevated Command Prompt:

```cmd
sc create ObscurizeService ^
    binPath= "C:\path\to\output\ObscurizeService.exe" ^
    start= auto ^
    DisplayName= "Obscurize Defensive Deception Service"

sc start ObscurizeService
```

Then launch `output\ObscurizeGUI.exe` (UAC prompt expected — it needs
Administrator to reach the LocalSystem pipe and write to HKLM).

---

## Repository Layout

```
Obscurize/
├── Obscurize.sln
├── BUILD.md                        ← Detailed build & deployment guide
├── output/                         ← Build artefacts (git-ignored)
│
├── ObscurizeShared/
│   ├── ObscurizeDef.h              ← C constants (single source of truth)
│   └── ObscurizeConst.cs           ← C# mirror, linked directly into GUI
│
├── ObscurizeAgent/
│   ├── Agent.c / .h                ← DLL entry point, injection marker
│   ├── Config.c / .h               ← Registry config reader (1 s poll)
│   ├── Hooks.c / .h                ← All 14 Detours API hooks
│   ├── Spoof.c / .h                ← Lookup tables, artefact install/remove
│   ├── ObscurizeAgent-x86.vcxproj
│   └── ObscurizeAgent-x64.vcxproj
│
├── ObscurizeService/
│   ├── ServiceMain.c / .h          ← SCM entry point, control dispatcher
│   ├── AgentInjector.c / .h        ← Load DLLs from resources, inject/detach
│   ├── ProcessListener.c / .h      ← New-process detection loop
│   ├── ControlPipeListener.c / .h  ← Named pipe server
│   ├── ArtefactManager.c / .h      ← Registry keys + decoy files
│   ├── ObscurizeService.rc         ← Embeds Agent DLLs as RCDATA 101/102
│   └── ObscurizeService.vcxproj
│
├── ObscurizeGUI/
│   ├── Program.cs                  ← Single-instance mutex, Application.Run
│   ├── TrayApplicationContext.cs   ← NotifyIcon + context menu
│   ├── TrayIconRenderer.cs         ← Programmatic GDI+ shield icons
│   ├── StatusPoller.cs             ← Background 2 s pipe poll
│   ├── ControlPipeClient.cs        ← Named pipe client wrapper
│   ├── MainWindow.cs               ← Dark-theme control panel window
│   └── ObscurizeGUI.csproj
│
└── r77-rootkit/r77-rootkit-master/ ← Reference only (not modified)
    ├── r77api/                     ← Injection engine + NT API headers
    ├── r77/detours.h
    └── SlnBin/x86|x64/detours.lib
```

---

## Control Pipe Reference

The GUI and any external tooling communicate with the service via
`\\.\pipe\ObscurizeCtrl`. Send a 4-byte little-endian DWORD; the status
query also returns a 4-byte reply.

| Code | Value | Description |
|---|---|---|
| `OBS_CTRL_ENABLE` | `0x0B01` | Enable spoofing |
| `OBS_CTRL_DISABLE` | `0x0B02` | Disable spoofing |
| `OBS_CTRL_SET_MODE_DEFENSIVE` | `0x0B03` | Switch to Defensive mode |
| `OBS_CTRL_SET_MODE_TRAP` | `0x0B04` | Switch to Trap mode |
| `OBS_CTRL_QUERY_STATUS` | `0x0B05` | Query status (reply: 0=disabled, 1=defensive, 2=trap) |
| `OBS_CTRL_INJECT_ALL` | `0x0B06` | Force inject into all running processes |
| `OBS_CTRL_DETACH_ALL` | `0x0B07` | Detach from all processes |

---

## Limitations & Future Work

- **CPUID / RDTSC timing** — CPU-level VM detection bypasses all Win32/NT
  hooks. Addressed in a future v2 with a kernel driver (requires EV code
  signing or test-signing mode).
- **WMI COM path** — Some malware queries WMI via `IWbemServices` rather than
  reading the registry directly. A COM hook layer is planned for v2.
- **32-bit processes on 32-bit Windows** — Not a target platform; the service
  is x64-only. 32-bit agent injection on a 64-bit host works via the x86 DLL.
- **Secure Desktop / PPL processes** — Protected processes (antivirus, LSA)
  are excluded from injection by design.
