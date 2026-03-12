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
payload. The [DEAD#VAX campaign](https://www.securonix.com/blog/deadvax-threat-research-security-advisory/) (Securonix, 2026) is a documented example:
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
│  • Installs system-wide PowerShell profile.ps1 (WMI hook)       │
│  • Config store: HKLM\SOFTWARE\ObscurizeConfig                  │
└──────────────┬──────────────────────────────────────────────────┘
               │  Reflective DLL injection (r77api InjectDll)
┌──────────────▼──────────────────────────────────────────────────┐
│  ObscurizeAgent32/64.dll  (injected into every user process)    │
│  • Microsoft Detours hooks on Win32 + NT APIs (20 hooks total)  │
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

| Check intercepted | Method | Spoofed value |
|---|---|---|
| `GetUserNameW/A` | API hook | `admin` |
| `GetComputerNameExW/A` | API hook | `DESKTOP-ANALY5T` |
| `GlobalMemoryStatusEx` | API hook | 2 048 MB physical RAM |
| `EnumDisplaySettingsW` | API hook | 800 × 600 resolution |
| `GetAdaptersAddresses` / `GetAdaptersInfo` | API hook | MAC OUI `00:0C:29` (VMware) |
| `NtQueryValueKey` (BIOS registry key) | NT hook | VMware BIOS strings |
| `GetSystemFirmwareTable` (raw SMBIOS) | API hook | VMware manufacturer / product in RSMB table |
| `HKLM\HARDWARE\DESCRIPTION\System\BIOS` | Registry write | VMware manufacturer / product |
| `HKLM\SOFTWARE\VMware Inc.\VMware Tools` | Registry write | Created (presence check) |
| `HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions` | Registry write | Created (presence check) |
| `%TEMP%\mapping.csv`, `VBE_marker.tmp` | Filesystem | **Not** created (absence triggers DEADVAX abort) |

### Trap Mode (appear as real hardware)

| Check intercepted | Method | Spoofed value |
|---|---|---|
| `GetUserNameW/A` | API hook | Config-defined username (default: `jsmith`) |
| `GetComputerNameExW/A` | API hook | Config-defined computer name (default: `DESKTOP-J8K3M2`) |
| `GlobalMemoryStatusEx` | API hook | 16 384 MB physical RAM |
| `EnumDisplaySettingsW` | API hook | 1920 × 1080 resolution |
| `GetAdaptersAddresses` / `GetAdaptersInfo` | API hook | MAC OUI `00:1B:21` (Intel) |
| `NtQueryValueKey` (BIOS registry key) | NT hook | Dell BIOS strings |
| `GetSystemFirmwareTable` (raw SMBIOS) | API hook | Dell manufacturer / product in RSMB table |
| `EnumServicesStatusExW/A` | API hook | VM service names filtered out |
| `NtQuerySystemInformation` | NT hook | VM process names filtered out |
| `NtEnumerateKey` / `NtQueryKey` | NT hook | VM vendor registry subkeys filtered from `HKLM\SOFTWARE` |
| VMware / VirtualBox registry keys | Registry delete | Removed |
| `%TEMP%\mapping.csv`, `VBE_marker.tmp` | Filesystem | Created (presence satisfies DEADVAX check) |
| PowerShell `Get-WmiObject` / `Get-CimInstance` | profile.ps1 hook | Returns spoofed Dell hardware strings |
| `CreateProcessW/A` (PowerShell spawn) | API hook | Strips `-NoProfile` flag so profile.ps1 always loads |
| `systeminfo.exe` stdout | WriteConsoleW hook | Replaces VMware strings with Dell strings in terminal output |

#### PowerShell WMI Spoofing Detail

When a process spawns PowerShell with `-NoProfile` (a common TTP to bypass
profile-based hooks), the `CreateProcessW/A` hook silently strips the flag
before the child process starts. The system-wide
`C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1` installed by the
Service then intercepts `Get-WmiObject Win32_ComputerSystem`,
`Get-WmiObject Win32_BIOS`, and their `Get-CimInstance` equivalents,
returning Dell hardware strings instead of VMware values.

#### systeminfo.exe Stdout Patching Detail

`systeminfo.exe` is a common post-exploitation enumeration tool used by human
attackers after initial access. When the Agent is injected into a
`systeminfo.exe` process (detected at DLL load time by process name), it
hooks `WriteFile`, `WriteConsoleA`, and `WriteConsoleW` on `kernelbase.dll`
(the actual implementation, not the kernel32 forwarding stubs) to intercept
stdout writes. Three patterns are replaced before output reaches the terminal:

| Original string | Replacement |
|---|---|
| `VMware, Inc. VMW…` (BIOS version line) | `Dell Inc. 1.22.0, 04/14/2023` |
| `VMware20,1` (system model) | `Precision 5560` |
| `VMware, Inc.` (manufacturer) | `Dell Inc.` |

The hook only activates in `systeminfo.exe` to avoid overhead in all other
processes.

---

## API Hooks Reference

The Agent installs up to 20 Detours hooks per process. The WriteFile /
WriteConsoleA / WriteConsoleW hooks are only installed when the host process
is `systeminfo.exe`.

| Hook | DLL | Defensive | Trap |
|---|---|---|---|
| `GetUserNameW` | advapi32 | Returns `admin` | Returns config username |
| `GetUserNameA` | advapi32 | Returns `admin` | Returns config username |
| `GetComputerNameExW` | kernel32 | Returns `DESKTOP-ANALY5T` | Returns config computer name |
| `GetComputerNameExA` | kernel32 | Returns `DESKTOP-ANALY5T` | Returns config computer name |
| `GlobalMemoryStatusEx` | kernel32 | Reports 2 048 MB RAM | Reports 16 384 MB RAM |
| `EnumDisplaySettingsW` | user32 | Reports 800×600 | Reports 1920×1080 |
| `GetAdaptersAddresses` | iphlpapi | OUI `00:0C:29` (VMware) | OUI `00:1B:21` (Intel) |
| `GetAdaptersInfo` | iphlpapi | OUI `00:0C:29` (VMware) | OUI `00:1B:21` (Intel) |
| `EnumServicesStatusExW` | advapi32 | Pass-through | Filters VM service names |
| `EnumServicesStatusExA` | advapi32 | Pass-through | Filters VM service names |
| `NtQuerySystemInformation` | ntdll | Pass-through | Filters VM process names |
| `NtEnumerateKey` | ntdll | Pass-through | Filters VM vendor subkeys in `HKLM\SOFTWARE` |
| `NtQueryKey` | ntdll | Pass-through | Corrects SubKeys count after filtering |
| `NtQueryValueKey` | ntdll | VMware BIOS strings | Dell BIOS strings |
| `GetSystemFirmwareTable` | kernel32 | VMware strings in RSMB table | Dell strings in RSMB table |
| `CreateProcessW` | kernel32 | Strips `-NoProfile` from PowerShell spawns | Strips `-NoProfile` from PowerShell spawns |
| `CreateProcessA` | kernel32 | Strips `-NoProfile` from PowerShell spawns | Strips `-NoProfile` from PowerShell spawns |
| `WriteFile` | kernelbase | — | Patches systeminfo.exe stdout (VM→Dell strings) |
| `WriteConsoleA` | kernelbase | — | Patches systeminfo.exe stdout (VM→Dell strings) |
| `WriteConsoleW` | kernelbase | — | Patches systeminfo.exe stdout via ConPTY path |

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

**kernelbase.dll resolution for stdout hooks** — Modern Windows executables
import `WriteFile` and `WriteConsoleA/W` directly from `kernelbase.dll` via
the ApiSet contract, bypassing the `kernel32.dll` forwarding stubs. The
systeminfo hooks resolve from `kernelbase.dll` directly to ensure Detours
patches the actual implementation rather than an un-called stub.

**ConPTY / Windows Terminal handling** — When systeminfo.exe runs inside
Windows Terminal or a PowerShell ConPTY session, its UCRT detects a console
handle and calls `WriteConsoleW` (wide Unicode) rather than `WriteFile` or
`WriteConsoleA`. All three code paths are hooked to guarantee coverage
regardless of the invoking shell.

**-NoProfile bypass prevention** — Malware and post-exploitation frameworks
commonly invoke PowerShell with `-NoProfile -NonInteractive` to avoid
profile-based hooks. The `CreateProcessW/A` hook walks the command-line token
by token and silently removes any `-noprofile` / `-nop` / `-nopr` token
(case-insensitive prefix match, minimum 3 body characters) before the child
process is created.

**Reversible** — On service stop, all injected agents are detached via the
stored function pointer in the PE header (r77-style header marker), all
artefact registry keys are deleted, all decoy files are removed, and the
PowerShell profile.ps1 is restored from backup.

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

From a Developer Command Prompt or using `devenv.com`:

```cmd
cd /d C:\path\to\Obscurize
mkdir output 2>nul

"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.com" ^
    Obscurize.sln /Build "Release|Win32" /Project ObscurizeAgent

"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.com" ^
    Obscurize.sln /Build "Release|x64" /Project ObscurizeAgent

"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.com" ^
    Obscurize.sln /Build "Release|x64" /Project ObscurizeService

"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.com" ^
    Obscurize.sln /Build "Release|x64" /Project ObscurizeGUI
```

> **Note:** Use `devenv.com` (the console wrapper), not `devenv.exe`. The
> `.exe` variant is a GUI application and displays help as a modal dialog
> when invoked from the command line.

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
├── output/                         ← Build artefacts (git-ignored)
│
├── ObscurizeShared/
│   ├── ObscurizeDef.h              ← C constants (single source of truth)
│   └── ObscurizeConst.cs           ← C# mirror, linked directly into GUI
│
├── ObscurizeAgent/
│   ├── Agent.c / .h                ← DLL entry point, injection marker
│   ├── Config.c / .h               ← Registry config reader (1 s poll)
│   ├── Hooks.c / .h                ← All 20 Detours API hooks
│   ├── Spoof.c / .h                ← Lookup tables, artefact install/remove
│   ├── SmbiosSpoof.c / .h          ← Raw SMBIOS (RSMB) table patching
│   ├── ObscurizeAgent-x86.vcxproj
│   └── ObscurizeAgent-x64.vcxproj
│
├── ObscurizeService/
│   ├── ServiceMain.c / .h          ← SCM entry point, control dispatcher
│   ├── AgentInjector.c / .h        ← Load DLLs from resources, inject/detach
│   ├── ProcessListener.c / .h      ← New-process detection loop
│   ├── ControlPipeListener.c / .h  ← Named pipe server
│   ├── ArtefactManager.c / .h      ← Registry keys, decoy files, PS profile
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
| `OBS_CTRL_ENABLE` | `0x0001` | Enable spoofing |
| `OBS_CTRL_DISABLE` | `0x0002` | Disable spoofing |
| `OBS_CTRL_SET_MODE_DEFENSIVE` | `0x0003` | Switch to Defensive mode |
| `OBS_CTRL_SET_MODE_TRAP` | `0x0004` | Switch to Trap mode |
| `OBS_CTRL_QUERY_STATUS` | `0x0005` | Query status (reply: 0=disabled, 2=defensive, 3=trap) |
| `OBS_CTRL_INJECT_ALL` | `0x0006` | Force inject into all running processes |
| `OBS_CTRL_DETACH_ALL` | `0x0007` | Detach from all processes |

---

## Limitations & Future Work

- **CPUID / RDTSC timing** — CPU-level VM detection bypasses all Win32/NT
  hooks. Addressed in a future v2 with a kernel driver (requires EV code
  signing or test-signing mode).
- **WMI COM path (direct `IWbemServices`)** — The PowerShell profile hook
  covers `Get-WmiObject` / `Get-CimInstance`. Malware that queries WMI via
  raw COM (`CoCreateInstance` → `IWbemServices::ExecQuery`) in a non-PowerShell
  process will bypass the profile hook; the SMBIOS and registry hooks still
  apply via the WMI provider host (`WmiPrvSE.exe`), into which the Agent is
  also injected.
- **32-bit processes on 32-bit Windows** — Not a target platform; the service
  is x64-only. 32-bit agent injection on a 64-bit host works via the x86 DLL.
- **Secure Desktop / PPL processes** — Protected processes (antivirus, LSA)
  are excluded from injection by design.
