<#
.SYNOPSIS
  Run the BLACKGUARD server automatically on a Windows computer (scheduled task).

.DESCRIPTION
  Default: starts at YOUR logon, as you, with no console window (pythonw.exe), restarting
  on failure. No password is stored. Logs go to <data>\logs\blackguard.log.
  -AtStartup runs it at boot as SYSTEM instead (works with nobody logged on). The data
  directory must then be writable by SYSTEM; it is by default for folders under your profile.

  This script does not open firewall ports or change network settings. The server keeps its
  secure default of listening on 127.0.0.1 unless your .env says otherwise.

.EXAMPLE
  .\deploy\windows\Install-BlackguardServer.ps1             # install for the current user
  .\deploy\windows\Install-BlackguardServer.ps1 -AtStartup  # as SYSTEM at boot (run as Administrator)
  .\deploy\windows\Install-BlackguardServer.ps1 -Uninstall  # clean stop, then remove the task
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$Python = '',
    [switch]$AtStartup,
    [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$TaskName = 'BLACKGUARD Server'
$StartPy = Join-Path $InstallDir 'start.py'
if (-not (Test-Path $StartPy)) { throw "start.py not found in $InstallDir. Pass -InstallDir <path to the blackguard folder>." }

if (-not $Python) {
    $candidate = Get-Command pythonw.exe -ErrorAction SilentlyContinue
    if (-not $candidate) { $candidate = Get-Command python.exe -ErrorAction SilentlyContinue }
    if (-not $candidate) { throw 'Python 3.10+ not found on PATH. Install it from python.org or pass -Python <path to pythonw.exe>.' }
    $Python = $candidate.Source
}

if ($Uninstall) {
    $consolePython = $Python -replace 'pythonw\.exe$', 'python.exe'
    & $consolePython $StartPy stop | Out-Host       # clean stop (records a clean shutdown)
    Start-Sleep -Seconds 8
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Removed scheduled task '$TaskName'. Your data folder was not touched."
    exit 0
}

$version = & ($Python -replace 'pythonw\.exe$', 'python.exe') -c "import sys;print(sys.version_info[:2] >= (3,10))"
if ($version -ne 'True') { throw "Python 3.10 or newer is required ($Python)." }

$action = New-ScheduledTaskAction -Execute $Python -Argument "`"$StartPy`"" -WorkingDirectory $InstallDir
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
if ($AtStartup) {
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Limited
} else {
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
}
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Host "Installed and started '$TaskName' ($(if ($AtStartup) {'at startup as SYSTEM'} else {"at logon as $env:USERNAME"}))."
Write-Host "Check: python `"$StartPy`" diagnose     Logs: <data folder>\logs\blackguard.log"
Write-Host "Stop cleanly: python `"$StartPy`" stop"
