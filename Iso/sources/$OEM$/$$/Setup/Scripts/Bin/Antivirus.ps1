# DLL Injection Monitor
# High-security monitoring for DLL injection attacks
# Runs continuously by default, trusts nothing

# === CONFIGURATION ===
$quarantineFolder = "C:\Quarantine"
$logFile          = "$quarantineFolder\dll_monitor_log.txt"
$localDatabase    = "$quarantineFolder\dll_scanned.txt"
$scannedHashes    = @{}

# Essential Windows components whitelist
$essentialWhitelist = @(
    # ctfmon (text services)
    "msctf.dll",
    "msutb.dll",
    "ctfmon.exe",
    # explorer (shell/context menus)
    "explorer.exe",
    "shell32.dll",
    "shlwapi.dll",
    "comctl32.dll",
    "propsys.dll",
    "explorerframe.dll",
    "windows.storage.dll",
    "twinui.dll",
    "twinui.pcshell.dll",
    "thumbcache.dll",
    # notepad
    "notepad.exe",
    "comdlg32.dll",
    "uxtheme.dll",
    "dwmapi.dll",
    # powershell
    "powershell.exe",
    "microsoft.powershell.consolehost.ni.dll",
    "system.management.automation.ni.dll",
    "system.management.automation.dll",
    # 7-Zip
    "7z.exe",
    "7zfm.exe",
    "7zg.exe",
    "7z.dll",
    "7z.sfx",
    "7-zip.dll",
    "7-zip32.dll",
    # NVIDIA Control Panel whitelist
    "nvcplui.exe",
    "nvcpl.dll",
    "nvapi64.dll",
    "nvapi.dll",
    "nvshext.dll",
    "nvcuda.dll",
    "nvopencl.dll",
    "nvd3dum.dll",
    "nvwgf2um.dll",
    "nvoglv64.dll",
    "nvoglv32.dll",
    "nvumdshim.dll",
    "nvfatbinaryloader.dll"
) | ForEach-Object { $_.ToLower() }

# Process name patterns for exception matching
$essentialProcesses = @(
    "ctfmon",
    "explorer",
    "notepad",
    "powershell",
    "7z",
    "7zfm",
    "7zg"
)

# === LOGGING ===
function Write-Log {
    param([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] $message"
    Write-Host $entry -ForegroundColor Cyan
    if (-not (Test-Path $quarantineFolder)) { 
        New-Item -Path $quarantineFolder -ItemType Directory -Force | Out-Null 
    }
    if ((Test-Path $logFile) -and (Get-Item $logFile).Length -ge 10MB) {
        Rename-Item $logFile "$quarantineFolder\dll_monitor_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt" -Force
    }
    $entry | Out-File -FilePath $logFile -Append -Encoding UTF8
}

# === UNIFIED EXCEPTION CHECKER ===
function Test-IsWhitelistedFile {
    param([string]$fullPath, [string]$processName)
    
    $fileName = (Split-Path $fullPath -Leaf).ToLower()
    $pathLower = $fullPath.ToLower()
    
    # Check if it's an essential Windows/PowerShell/7-Zip process
    foreach ($proc in $essentialProcesses) {
        if ($processName -match $proc) {
            if ($essentialWhitelist -contains $fileName) {
                Write-Log "EXCEPTION: Allowing $fullPath for $processName"
                return $true
            }
            
            # PowerShell special case: allow all .NET Native Images
            if ($processName -match "powershell" -and $pathLower -match "\.ni\.dll$") {
                Write-Log "POWERSHELL EXCEPTION: Allowing .NET Native Image $fullPath"
                return $true
            }
            
            # PowerShell special case: allow core files
            if ($processName -match "powershell" -and $pathLower -match "powershell|system\.management\.automation") {
                Write-Log "POWERSHELL EXCEPTION: Allowing core file $fullPath"
                return $true
            }
            
            # 7-Zip special case: allow files in 7-Zip directory
            if ($processName -match "7z" -and $pathLower -match "\\7-zip\\") {
                Write-Log "7-ZIP EXCEPTION: Allowing 7-Zip directory file $fullPath"
                return $true
            }
        }
    }
    
    return $false
}

# === FILE ANALYSIS ===
function Get-DLLThreatScore {
    param([string]$filePath)
    
    $score = 0
    $reasons = @()
    
    try {
        # Check signature
        $sig = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
        if ($sig.Status -ne "Valid") {
            $score += 50
            $reasons += "Unsigned/Invalid signature"
        }
        
        # Check location (even System32 is suspicious now)
        $pathLower = $filePath.ToLower()
        if ($pathLower -match "\\temp\\|\\appdata\\|\\downloads\\|\\users\\.*\\desktop") {
            $score += 30
            $reasons += "Suspicious location"
        }
        
        # UWP/Windows Store apps are digitally signed by Microsoft
        if ($pathLower -match "\\windowsapps\\") {
            $score -= 40
            $reasons += "UWP/Windows Store app (Microsoft signed)"
        }
        
        # Even System32 files can be malicious - check hash against known good
        if ($pathLower -match "\\system32\\|\\syswow64\\") {
            # Don't auto-trust, but reduce score slightly
            $score -= 10
            $reasons += "System folder (still checking)"
        }
        
        # Check file metadata
        $file = Get-Item $filePath
        if ($file.CreationTime -gt (Get-Date).AddDays(-1)) {
            $score += 20
            $reasons += "Recently created (<24h)"
        }
        
        # Check if file is hidden or system
        if ($file.Attributes -match "Hidden") {
            $score += 25
            $reasons += "Hidden attribute"
        }
        
        return [PSCustomObject]@{
            Score = $score
            Reasons = ($reasons -join "; ")
            Hash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash.ToLower()
        }
    }
    catch {
        Write-Log "Error analyzing $filePath : $_"
        return $null
    }
}

# === QUARANTINE ===
function Set-FileOwnership {
    param([string]$filePath)
    try {
        takeown /F $filePath /A >$null 2>&1
        icacls $filePath /grant "Administrators:F" /T /C /Q >$null 2>&1
        return $true
    }
    catch {
        Write-Log "Failed to take ownership: $filePath"
        return $false
    }
}

function Stop-ProcessUsingFile {
    param([string]$filePath)
    
    Get-Process | ForEach-Object {
        $proc = $_
        try {
            if ($proc.Modules.FileName -contains $filePath) {
                Write-Log "Terminating process: $($proc.Name) (PID $($proc.Id))"
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            # Some processes can't be enumerated
        }
    }
}

function Quarantine-SuspiciousDLL {
    param([string]$filePath, [string]$reason, [int]$score)
    
    Write-Host ">>> THREAT DETECTED: $filePath (Score: $score)" -ForegroundColor Red
    Write-Host ">>> Reason: $reason" -ForegroundColor Yellow
    Write-Log "QUARANTINE: $filePath | Score: $score | $reason"
    
    try {
        $dest = Join-Path $quarantineFolder (Split-Path $filePath -Leaf)
        $counter = 1
        while (Test-Path $dest) {
            $dest = Join-Path $quarantineFolder "$counter-$(Split-Path $filePath -Leaf)"
            $counter++
        }
        
        Set-FileOwnership $filePath
        Stop-ProcessUsingFile $filePath
        Move-Item -Path $filePath -Destination $dest -Force -ErrorAction Stop
        Write-Log "Moved to quarantine: $dest"
    }
    catch {
        Write-Log "Quarantine failed: $_"
    }
}

# === PROCESS MONITORING ===
function Monitor-LoadedDLLs {
    Write-Log "Starting DLL injection monitoring (continuous mode)..."
    
    $lastScan = @{}
    
    while ($true) {
        Get-Process | ForEach-Object {
            $proc = $_
            $procName = $proc.Name.ToLower()
            
            try {
                $proc.Modules | Where-Object { $_.FileName -like "*.dll" } | ForEach-Object {
                    $dllPath = $_.FileName
                    $dllName = Split-Path $dllPath -Leaf
                    $key = "$($proc.Id)-$dllPath"
                    
                    # Skip if already scanned recently
                    if ($lastScan.ContainsKey($key)) {
                        return
                    }
                    
                    if (Test-IsWhitelistedFile -fullPath $dllPath -processName $procName) {
                        $lastScan[$key] = $true
                        return
                    }
                    
                    # Check if previously scanned
                    if ($scannedHashes.ContainsKey($dllPath)) {
                        $lastScan[$key] = $true
                        return
                    }
                    
                    $result = Get-DLLThreatScore -filePath $dllPath
                    if ($null -eq $result) {
                        return
                    }
                    
                    $scannedHashes[$dllPath] = $result.Hash
                    
                    if ($result.Score -ge 50) {
                        Quarantine-SuspiciousDLL -filePath $dllPath -reason $result.Reasons -score $result.Score
                    }
                    else {
                        Write-Log "SAFE: $dllName in $($proc.Name) (Score: $($result.Score))"
                    }
                    
                    $lastScan[$key] = $true
                }
            }
            catch {
                # Process exited or access denied
            }
        }
        
        Start-Sleep -Seconds 5
    }
}

# === FILESYSTEM WATCHER ===
function Monitor-NewDLLs {
    Write-Log "Starting filesystem monitoring for new DLL files..."
    
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 }
    
    foreach ($drive in $drives) {
        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = $drive.Root
        $watcher.Filter = "*.dll"
        $watcher.IncludeSubdirectories = $true
        $watcher.EnableRaisingEvents = $true
        
        $action = {
            $path = $Event.SourceEventArgs.FullPath
            $changeType = $Event.SourceEventArgs.ChangeType
            
            Write-Log "NEW DLL DETECTED: $path ($changeType)"
            
            Start-Sleep -Milliseconds 500
            
            if (Test-Path $path) {
                $result = Get-DLLThreatScore -filePath $path
                if ($null -eq $result) {
                    return
                }
                
                if ($result.Score -ge 50) {
                    Quarantine-SuspiciousDLL -filePath $path -reason $result.Reasons -score $result.Score
                }
                else {
                    Write-Log "NEW DLL SAFE: $path (Score: $($result.Score))"
                }
            }
        }
        
        Register-ObjectEvent -InputObject $watcher -EventName Created -Action $action | Out-Null
        Write-Log "Monitoring drive: $($drive.Name)"
    }
}

# === MAIN ===
if (-not (Test-Path $quarantineFolder)) {
    New-Item -Path $quarantineFolder -ItemType Directory -Force | Out-Null
}

# Load previous scan results
if (Test-Path $localDatabase) {
    Get-Content $localDatabase | ForEach-Object {
        $parts = $_ -split '\|'
        if ($parts.Length -ge 2) {
            $scannedHashes[$parts[0]] = $parts[1]
        }
    }
    Write-Log "Loaded $($scannedHashes.Count) previous scan results"
}

Write-Log "=== DLL Injection Monitor Started (Continuous Mode) ==="
Write-Log "Quarantine folder: $quarantineFolder"
Write-Log "Trust policy: Zero trust - everything checked"
Write-Log "Exceptions: ctfmon, explorer, notepad, PowerShell, 7-Zip"

# Start monitoring in background jobs
$dllJob = Start-Job -ScriptBlock ${function:Monitor-LoadedDLLs}
$fsJob = Start-Job -ScriptBlock ${function:Monitor-NewDLLs}

Write-Log "Monitoring jobs started. Press Ctrl+C to stop."

try {
    while ($true) {
        # Receive output from jobs
        Receive-Job -Job $dllJob -ErrorAction SilentlyContinue
        Receive-Job -Job $fsJob -ErrorAction SilentlyContinue
        
        # Save database periodically
        $scannedHashes.GetEnumerator() | ForEach-Object {
            "$($_.Key)|$($_.Value)"
        } | Out-File -FilePath $localDatabase -Force
        
        Start-Sleep -Seconds 10
    }
}
finally {
    Write-Log "Stopping monitoring jobs..."
    Stop-Job -Job $dllJob, $fsJob
    Remove-Job -Job $dllJob, $fsJob
}
