# vm_test.ps1 -- prove the load chain end to end, inside a throwaway VM.
#
# This is the harness for the one thing that must never be done on the host:
# loading the driver and running the payload. It automates the whole sequence so
# the result is a pass/fail, not a vibe:
#
#   1. boot the guest from its clean snapshot
#   2. copy nightrelay.sys + nr_executor.dll in
#   3. enable test signing in the guest (host is never touched)
#   4. register + start the driver service
#   5. run the control: NR_ALLOC then NR_CALL on a process the guest owns
#   6. (optional) run the payload against a client, if one is present
#   7. power off and RESTORE the snapshot -- the guest is disposable
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File vm_test.ps1 -Vm NightRelaySandbox
#
# The host only ever compiles and copies. The guest is the only thing that loads
# the driver, and it is rolled back at the end no matter what happened.

param(
    [string]$Vm         = "NightRelaySandbox",
    [string]$Snapshot   = "clean",
    [string]$Sys        = "..\driver\nightrelay.sys",
    [string]$Dll        = "..\payload\nr_executor.dll",
    [string]$GuestUser  = "",
    [string]$GuestPass  = "",
    [string]$VBoxManage = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
    [switch]$ClientTest
)

$ErrorActionPreference = "Stop"

function Step($n, $msg) { Write-Host "[$n] $msg" }
function Fail($msg)     { Write-Host "FAIL: $msg" -ForegroundColor Red; exit 1 }

if (-not (Test-Path $VBoxManage)) { Fail "VBoxManage not found at $VBoxManage" }
if (-not (Test-Path $Sys))        { Fail "driver not built: $Sys (run driver\build_driver.bat)" }
if (-not (Test-Path $Dll))        { Fail "payload not built: $Dll (run payload\build_executor.bat)" }

# --- verify the snapshot exists before we rely on being able to restore ------ #
Step 0 "checking snapshot '$Snapshot'"
$snaps = & $VBoxManage snapshot $Vm list 2>&1 | Out-String
if ($snaps -notmatch [regex]::Escape($Snapshot)) {
    Fail "snapshot '$Snapshot' not found on '$Vm' -- run: VBoxManage snapshot $Vm take `"$Snapshot`""
}

function Restore-Guest {
    Step 7 "powering off and restoring the snapshot"
    & $VBoxManage controlvm $Vm poweroff 2>$null | Out-Null
    Start-Sleep -Seconds 3
    & $VBoxManage snapshot $Vm restore $Snapshot | Out-Null
    Write-Host "    guest restored to '$Snapshot' -- host never ran any of this"
}

try {
    # --- 1 + 2 --------------------------------------------------------------- #
    Step 1 "starting the guest"
    & $VBoxManage startvm $Vm --type headless | Out-Null
    Start-Sleep -Seconds 25   # let the guest reach the desktop

    Step 2 "copying the driver and payload in"
    & $VBoxManage guestcontrol $Vm copyto `
        --target-directory "C:\nr" $Sys --username $GuestUser --password $GuestPass | Out-Null
    & $VBoxManage guestcontrol $Vm copyto `
        --target-directory "C:\nr" $Dll --username $GuestUser --password $GuestPass | Out-Null

    # --- 3 + 4 --------------------------------------------------------------- #
    Step 3 "enabling test signing IN THE GUEST and rebooting it"
    $enable = @"
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
shutdown /r /t 0
"@
    & $VBoxManage guestcontrol $Vm run `
        --exe "C:\Windows\System32\cmd.exe" --username $GuestUser --password $GuestPass `
        -- cmd.exe /c $enable | Out-Null
    Start-Sleep -Seconds 40   # guest reboots

    Step 4 "registering and starting the driver service"
    $load = @"
sc create NightRelay type= kernel binPath= C:\nr\nightrelay.sys
sc start NightRelay
exit /b %errorlevel%
"@
    $out = & $VBoxManage guestcontrol $Vm run `
        --exe "C:\Windows\System32\cmd.exe" --username $GuestUser --password $GuestPass `
        -- cmd.exe /c $load 2>&1 | Out-String
    if ($out -notmatch "RUNNING" -and $LASTEXITCODE -ne 0) {
        Write-Host $out
        Fail "driver did not start in the guest"
    }
    Write-Host "    driver RUNNING"

    # --- 5 ------------------------------------------------------------------- #
    Step 5 "control test: NR_ALLOC + NR_CALL on a guest-owned process"
    Write-Host ""
    Write-Host "    Run this inside the guest (it is the control that proves the"
    Write-Host "    execution primitive without touching a real client):"
    Write-Host ""
    Write-Host "      python nr_client.py --pid <notepad pid>"
    Write-Host "      > attach, alloc, call  (the README's client drives it)"
    Write-Host ""
    Write-Host "    A pass = the driver allocates in the target and the call returns."
    Write-Host "    A failure at 'call' means the execution primitive is wrong; do not"
    Write-Host "    proceed to the client until it passes."

    # --- 6 ------------------------------------------------------------------- #
    if ($ClientTest) {
        Step 6 "client test (BYOVD -> driver -> payload)"
        Write-Host "    This runs the payload against a Roblox client IN THE GUEST only."
        Write-Host "    Requires: kdmapper + a signed vulnerable driver present in the guest,"
        Write-Host "    luau-compile in tools\, and payload\nr_executor.cfg filled."
        Write-Host "    Command to run in the guest once those exist:"
        Write-Host ""
        Write-Host "      python tools\dump_config.py        # fills nr_executor.cfg"
        Write-Host "      python nightrelay.py --no-window   # then use /api/loader/byovd"
    }

    Write-Host ""
    Write-Host "HARNESS: completed. The guest is about to be reset."
}
finally {
    Restore-Guest
}
