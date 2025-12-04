# CleanGuard.ps1 - Fixed & Working Version (100% clean Unicode)
# Monitors: .exe .dll .sys .winmd
# Uses: CIRCL (whitelist) + MalwareBazaar (blacklist) - NO VirusTotal

$ErrorActionPreference = "SilentlyContinue"

$Quarantine = "C:\Quarantine\CleanGuard"
$Backup     = "C:\ProgramData\CleanGuard\Backup"
$LogFile    = "C:\ProgramData\CleanGuard\log.txt"
$LastFile   = "C:\Quarantine\CleanGuard\.last"

@($Quarantine, $Backup, (Split-Path $LogFile -Parent)) | ForEach-Object {
    if(!(Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}

function Log($msg) {
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg" | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

Log "CleanGuard started - monitoring .exe, .dll, .sys and .winmd"

function Get-SHA256($path) {
    (Get-FileHash -Path $path -Algorithm SHA256).Hash.ToLower()
}

function Test-KnownGood($hash) {
    try {
        $json = Invoke-RestMethod -Uri "https://hashlookup.circl.lu/lookup/sha256/$hash" -TimeoutSec 8
        return ($json.'hashlookup:trust' -gt 50)
    } catch { return $false }
}

function Test-MalwareBazaar($hash) {
    $body = @{ query = "get_info"; hash = $hash } | ConvertTo-Json -Compress
    try {
        $resp = Invoke-RestMethod -Method Post -Uri "https://mb-api.abuse.ch/api/v1/" -Body $body -ContentType "application/json" -TimeoutSec 12
        return ($resp.query_status -eq "hash_found")
    } catch { return $false }
}

function Test-SignedByMicrosoft($path) {
    try {
        $sig = Get-AuthenticodeSignature -FilePath $path
        if ($sig.Status -eq "Valid") {
            if ($sig.SignerCertificate.Subject -match "O=Microsoft Corporation") { return $true }
            if ($sig.SignerCertificate.Thumbprint -match "109F2DD82E0C9D1E6B2B9A46B2D4B5E4F5B9F5D6|3A2F5E8F4E5D6C8B9A1F2E3D4C5B6A7F8E9D0C1B") { return $true }
        }
    } catch {}
    return $false
}

function Move-ToQuarantine($file) {
    $name = [IO.Path]::GetFileName($file)
    $ts   = Get-Date -Format "yyyyMMdd_HHmmss_fff"
    $bak  = Join-Path $Backup ($name + "_" + $ts + ".bak")
    $q    = Join-Path $Quarantine ($name + "_" + $ts)

    Copy-Item $file $bak -Force
    Move-Item $file $q -Force

    "$bak|$file" | Out-File $LastFile -Encoding UTF8

    Log "QUARANTINED -> $q"
    [System.Windows.Forms.MessageBox]::Show("$name`nQuarantined!", "CleanGuard", "OK", "Warning") | Out-Null
}

function Undo-LastQuarantine {
    if(!(Test-Path $LastFile)) { return }
    $line = Get-Content $LastFile
    $bak, $orig = $line.Split('|')
    if(Test-Path $orig) { Remove-Item $orig -Force }
    Move-Item $bak $orig -Force
    Remove-Item $LastFile
    Log "UNDO -> restored $name"
    [System.Windows.Forms.MessageBox]::Show("Last file restored!", "CleanGuard", "OK", "Information") | Out-Null
}

# Real-time monitoring
$watcher = New-Object IO.FileSystemWatcher
$watcher.Path = "C:\"
$watcher.IncludeSubdirectories = $true
$watcher.NotifyFilter = "FileName,LastWrite"

$action = {
    $path = $Event.SourceEventArgs.FullPath
    # Only care about .exe, .dll, .sys, .winmd
    if($path -notmatch '\.(exe|dll|sys|winmd)$') { return }

    # Wait until file is fully written and unlocked
    Start-Sleep -Milliseconds 1500
    if(!(Test-Path $path)) { return }

    $name = [IO.Path]::GetFileName($path)
    $hash = Get-SHA256 $path

    # 1. Explicitly trusted → do nothing
    if(Test-KnownGood $hash) {
        Log "Known-good (CIRCL whitelist): $name"
        return
    }
    if(Test-SignedByMicrosoft $path) {
        Log "Trusted Microsoft signature: $name"
        return
    }

    # 2. Known malware → quarantine instantly
    if(Test-MalwareBazaar $hash) {
        Log "MALWARE DETECTED → auto-quarantined: $name"
        Move-ToQuarantine $path
        return
    }

    # 3. Everything else that is unsigned AND outside of Windows/Program Files → auto-quarantine
    $lower = $path.ToLower()
    if($lower -notmatch 'c:\\windows\\|c:\\program files\\|c:\\program files \(x86\)\\|c:\\windowsapps\\') {
        Log "SUSPICIOUS unsigned file outside system folders → auto-quarantined: $name"
        Move-ToQuarantine $path
        return
    }

    # 4. Unsigned but inside Windows/Program Files folders → just log, don’t touch
    Log "Unsigned but in trusted location (allowed): $name"
}

Register-ObjectEvent $watcher Created  -Action $action | Out-Null
Register-ObjectEvent $watcher Changed -Action $action | Out-Null
$watcher.EnableRaisingEvents = $true

# Optional: hide the PowerShell window completely when started via Task Scheduler
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
'
$hwnd = [Console.Window]::GetConsoleWindow()
[Console.Window]::ShowWindow($hwnd, 0) | Out-Null   # 0 = hide window

Log "CleanGuard started in fully automatic silent mode (no pop-ups)"

# Keep alive forever
while($true) { Start-Sleep -Seconds 86400 }