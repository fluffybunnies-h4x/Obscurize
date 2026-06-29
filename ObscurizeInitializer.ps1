# ============================================================
#  ObscurizeInitializer.ps1
#
#  One-shot setup script for Obscurize on a target system.
#  Run this once after copying the built binaries to the
#  install directory.  It will:
#
#    1. Verify ObscurizeService.exe and ObscurizeGUI.exe exist
#       at the install path.
#    2. Register (or update) ObscurizeService as a Windows
#       Service registered with DEMAND (manual) start for initial deployment.
#       Verify stable operation on the target system before switching to
#       automatic start: sc config ObscurizeService start= delayed-auto
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
#  Optional: specify a non-default install path:
#
#    .\ObscurizeInitializer.ps1 -InstallPath "D:\Tools\Obscurize"
#
# ============================================================

param(
    [string]$InstallPath = "C:\ProgramData\Obscurize"
)

# --- Elevation guard -------------------------------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "Relaunching as Administrator..." -ForegroundColor Yellow
    Start-Process powershell.exe `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -InstallPath `"$InstallPath`"" `
        -Verb RunAs
    exit
}

# --- Config ----------------------------------------------------------
$ServiceName    = "ObscurizeService"
$ServiceDisplay = "Obscurize Defensive Deception Service"
$ServiceExe     = Join-Path $InstallPath "ObscurizeService.exe"
$GuiExe         = Join-Path $InstallPath "ObscurizeGUI.exe"
$TaskFolder     = "\Obscurize\"
$TaskName       = "ObscurizeGUI"

Write-Host ""
Write-Host "  =======================================" -ForegroundColor Cyan
Write-Host "       OBSCURIZE INITIALIZER"             -ForegroundColor Cyan
Write-Host "  =======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Install path : $InstallPath" -ForegroundColor Gray
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
    Write-Host "        Service already registered - updating binary path." -ForegroundColor Yellow

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
    & sc.exe create $ServiceName binPath= "`"$ServiceExe`"" start= demand obj= LocalSystem DisplayName= "$ServiceDisplay" | Out-Null

    if ($LASTEXITCODE -ne 0)
    {
        Write-Host "        ERROR: sc.exe create failed (exit $LASTEXITCODE)." -ForegroundColor Red
        exit 1
    }

    Write-Host "        Service created." -ForegroundColor Green
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

$taskAction = New-ScheduledTaskAction -Execute $GuiExe
$taskTrigger = New-ScheduledTaskTrigger -AtLogOn

# Any member of BUILTIN\Administrators gets the GUI at logon,
# elevated, without a UAC prompt.
$taskPrincipal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest

$taskSettings = New-ScheduledTaskSettingsSet `
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
Write-Host "  ObscurizeService : demand (manual) start - start manually each boot until validated"         -ForegroundColor Gray
Write-Host "  ObscurizeGUI     : launches at logon for all Administrators" -ForegroundColor Gray
Write-Host ""
Write-Host "  Launching ObscurizeGUI now..." -ForegroundColor White
Write-Host ""

Start-Process -FilePath $GuiExe
