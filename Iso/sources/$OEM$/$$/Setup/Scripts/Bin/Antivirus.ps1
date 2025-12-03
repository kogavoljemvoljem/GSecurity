# Anti-Virus DLL Scanner with Intelligent Whitelisting
# Monitors for DLL injection while intelligently excluding trusted vendor files

# === CONFIGURATION ===
$logFile = ".\dll_monitor_log.txt"
$localDatabase = ".\dll_hashes.csv"

# Create files if they don't exist
if (-not (Test-Path $logFile)) {
    New-Item -Path $logFile -ItemType File | Out-Null
}
if (-not (Test-Path $localDatabase)) {
    "Hash,ThreatScore" | Out-File -FilePath $localDatabase -Encoding utf8
}

# === WHITELIST DEFINITIONS ===

# Microsoft core components (Always Safe)
$microsoftWhitelist = @(
    "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
    "advapi32.dll", "msvcrt.dll", "ole32.dll", "shell32.dll",
    "comctl32.dll", "comdlg32.dll", "ws2_32.dll", "crypt32.dll",
    "wintrust.dll", "version.dll", "shlwapi.dll", "oleaut32.dll",
    "rpcrt4.dll", "secur32.dll", "wininet.dll", "urlmon.dll",
    "bcrypt.dll", "ncrypt.dll", "cryptsp.dll", "rsaenh.dll",
    "cryptbase.dll", "bcryptprimitives.dll", "msvcp_win.dll",
    "ucrtbase.dll", "kernelbase.dll", "win32u.dll", "gdi32full.dll",
    "msvcp140.dll", "vcruntime140.dll", "api-ms-win"
) | ForEach-Object { $_.ToLower() }

# NVIDIA Graphics drivers
$nvidiaWhitelist = @(
    "nvcuda.dll", "nvapi.dll", "nvapi64.dll", "nvcuvid.dll",
    "nvd3dum.dll", "nvoglv64.dll", "nvopencl.dll", "nvfbc64.dll",
    "nvcpl.dll", "nvdispco6442513.dll", "nvmcumd.dll", "nvwgf2umx.dll"
) | ForEach-Object { $_.ToLower() }

# AMD Radeon drivers
$amdWhitelist = @(
    "aticfx64.dll", "atioglxx.dll", "atiumd64.dll", "amdihk64.dll",
    "atiadlxx.dll", "amdave64.dll", "amdhcp64.dll"
) | ForEach-Object { $_.ToLower() }

# Intel Graphics drivers
$intelWhitelist = @(
    "ig9icd64.dll", "igc64.dll", "igdml64.dll", "igdfcl64.dll",
    "igdgmm64.dll", "igd10iumd64.dll", "igd11dxva64.dll"
) | ForEach-Object { $_.ToLower() }

# Realtek Audio drivers
$realtekWhitelist = @(
    "rtkaudioservice64.exe", "rtkaudugservice64.exe", "rtkaudiomanager.exe",
    "rtkapo64.dll", "rtkapi64.dll", "rtkaudioapi64.dll"
) | ForEach-Object { $_.ToLower() }

# Dolby Audio
$dolbyWhitelist = @(
    "dolbydax2api.exe", "dax3api.exe", "dax3_api_proxy.exe",
    "dolbydax2trayicon.exe", "dolbyaposvc.exe",
    "dax2_api.dll", "dax3_api.dll", "dolbyapo2.dll",
    "dolbyaposvc64.dll", "dolbyapomgr64.dll", "dax2audioapo.dll",
    "dax3_api_proxy.dll", "dlbapo64.dll", "dolbyapo100.dll"
) | ForEach-Object { $_.ToLower() }

# 7-Zip Compression Tool
$sevenZipWhitelist = @(
    "7z.exe", "7zfm.exe", "7zg.exe",
    "7-zip.dll", "7z.dll"
) | ForEach-Object { $_.ToLower() }

# CTFMon (Text Services Framework)
$ctfmonWhitelist = @(
    "msctf.dll", "ctfmon.exe"
) | ForEach-Object { $_.ToLower() }

# Windows Explorer
$explorerWhitelist = @(
    "explorerframe.dll", "thumbcache.dll", "windows.storage.dll"
) | ForEach-Object { $_.ToLower() }

# PowerShell
$powershellWhitelist = @(
    "system.management.automation.dll", "microsoft.powershell.commands.utility.dll"
) | ForEach-Object { $_.ToLower() }

# Notepad
$notepadWhitelist = @(
    "notepad.exe", "textinputframework.dll"
) | ForEach-Object { $_.ToLower() }

# Rainmeter
$rainmeterWhitelist = @(
    "rainmeter.dll", "rainmeter.exe"
) | ForEach-Object { $_.ToLower() }

# Wallpaper Engine
$wallpaperEngineWhitelist = @(
    "wallpaper32.exe", "wallpaper64.exe", "ui32.exe",
    "cef.dll", "libcef.dll"
) | ForEach-Object { $_.ToLower() }

# MLWApp
$mlwappWhitelist = @(
    "mlwapp.dll", "mlwapp.exe"
) | ForEach-Object { $_.ToLower() }

# === LOGGING FUNCTION ===
function Write-Log {
    param([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $message"
    Add-Content -Path $logFile -Value $logMessage
}

# === VENDOR WHITELIST FUNCTIONS ===

function Test-IsNvidiaFile {
    param([string]$fullPath, [string]$processName)
    
    # If the process loading it is nvidia-related
    if ($processName -match "nvcpl|nvidia") {
        $fileName = (Split-Path $fullPath -Leaf).ToLower()
        if ($nvidiaWhitelist -contains $fileName) {
            return $true
        }
    }
    
    # Allow any DLL from NVIDIA directory
    $pathLower = $fullPath.ToLower()
    if ($pathLower -match "\\nvidia\\|\\nvidiagames\\|\\nvidia corporation\\") {
        return $true
    }
    
    # Allow files in System32 if they match nvidia whitelist
    $fileName = (Split-Path $fullPath -Leaf).ToLower()
    if ($nvidiaWhitelist -contains $fileName) {
        return $true
    }
    
    return $false
}

function Test-IsAMDFile {
    param([string]$fullPath, [string]$processName)
    
    if ($processName -match "amd|radeon") {
        $fileName = (Split-Path $fullPath -Leaf).ToLower()
        if ($amdWhitelist -contains $fileName) {
            return $true
        }
    }
    
    $pathLower = $fullPath.ToLower()
    if ($pathLower -match "\\amd\\|\\radeon\\") {
        return $true
    }
    
    $fileName = (Split-Path $fullPath -Leaf).ToLower()
    if ($amdWhitelist -contains $fileName) {
        return $true
    }
    
    return $false
}

function Test-IsIntelFile {
    param([string]$fullPath, [string]$processName)
    
    if ($processName -match "igfx|intel") {
        $fileName = (Split-Path $fullPath -Leaf).ToLower()
        if ($intelWhitelist -contains $fileName) {
            return $true
        }
    }
    
    $pathLower = $fullPath.ToLower()
    if ($pathLower -match "\\intel\\") {
        return $true
    }
    
    $fileName = (Split-Path $fullPath -Leaf).ToLower()
    if ($intelWhitelist -contains $fileName) {
        return $true
    }
    
    return $false
}

function Test-IsRealtekFile {
    param([string]$fullPath, [string]$processName)
    
    if ($processName -match "rtk|realtek") {
        $fileName = (Split-Path $fullPath -Leaf).ToLower()
        if ($realtekWhitelist -contains $fileName) {
            return $true
        }
    }
    
    $pathLower = $fullPath.ToLower()
    if ($pathLower -match "\\realtek\\") {
        return $true
    }
    
    $fileName = (Split-Path $fullPath -Leaf).ToLower()
    if ($realtekWhitelist -contains $fileName) {
        return $true
    }
    
    return $false
}

function Test-IsDolbyFile {
    param([string]$fullPath, [string]$processName)
    
    if ($processName -match "dolby") {
        $fileName = (Split-Path $fullPath -Leaf).ToLower()
        if ($dolbyWhitelist -contains $fileName) {
            return $true
        }
    }
    
    $pathLower = $fullPath.ToLower()
    if ($pathLower -match "\\dolby\\") {
        return $true
    }
    
    $fileName = (Split-Path $fullPath -Leaf).ToLower()
    if ($dolbyWhitelist -contains $fileName) {
        return $true
    }
    
    return $false
}

function Test-Is7ZipFile {
    param([string]$fullPath, [string]$processName)
    
    if ($processName -match "7z") {
        $fileName = (Split-Path $fullPath -Leaf).ToLower()
        if ($sevenZipWhitelist -contains $fileName) {
            return $true
        }
    }
    
    $pathLower = $fullPath.ToLower()
    if ($pathLower -match "\\7-zip\\") {
        return $true
    }
    
    $fileName = (Split-Path $fullPath -Leaf).ToLower()
    if ($sevenZipWhitelist -contains $fileName) {
        return $true
    }
    
    return $false
}

function Test-IsCtfmonFile {
    param([string]$fullPath, [string]$processName)
    
    if ($processName -eq "ctfmon") {
        $fileName = (Split-Path $fullPath -Leaf).ToLower()
        if ($ctfmonWhitelist -contains $fileName) {
            return $true
        }
    }
    return $false
}

function Test-IsExplorerFile {
    param([string]$fullPath, [string]$processName)
    
    if ($processName -eq "explorer") {
        $fileName = (Split-Path $fullPath -Leaf).ToLower()
        if ($explorerWhitelist -contains $fileName) {
            return $true
        }
    }
    return $false
}

function Test-IsPowerShellFile {
    param([string]$fullPath, [string]$processName)
    
    if ($processName -match "powershell") {
        $fileName = (Split-Path $fullPath -Leaf).ToLower()
        if ($powershellWhitelist -contains $fileName) {
            return $true
        }
    }
    
    $pathLower = $fullPath.ToLower()
    if ($pathLower -match "\.ni\.dll$") {
        return $true
    }
    
    if ($pathLower -match "powershell|system\.management\.automation") {
        return $true
    }
    
    return $false
}

function Test-IsNotepadFile {
    param([string]$fullPath, [string]$processName)
    
    if ($processName -eq "notepad") {
        $fileName = (Split-Path $fullPath -Leaf).ToLower()
        if ($notepadWhitelist -contains $fileName) {
            return $true
        }
    }
    return $false
}

function Test-IsRainmeterFile {
    param([string]$fullPath, [string]$processName)
    
    if ($processName -eq "rainmeter") {
        $fileName = (Split-Path $fullPath -Leaf).ToLower()
        if ($rainmeterWhitelist -contains $fileName) {
            return $true
        }
    }
    
    $pathLower = $fullPath.ToLower()
    if ($pathLower -match "\\rainmeter\\") {
        return $true
    }
    
    return $false
}

function Test-IsMLWAppFile {
    param([string]$fullPath, [string]$processName)
    
    if ($processName -eq "mlwapp") {
        return $true
    }
    
    $pathLower = $fullPath.ToLower()
    if ($pathLower -match "\\mlwapp\\") {
        return $true
    }
    
    return $false
}

function Test-IsWallpaperEngineFile {
    param([string]$fullPath, [string]$processName)
    
    if ($processName -match "wallpaper") {
        $fileName = (Split-Path $fullPath -Leaf).ToLower()
        if ($wallpaperEngineWhitelist -contains $fileName) {
            return $true
        }
    }
    
    $pathLower = $fullPath.ToLower()
    if ($pathLower -match "\\wallpaper engine\\") {
        return $true
    }
    
    return $false
}

function Test-IsMicrosoftFile {
    param([string]$fullPath, [string]$processName)
    
    $fileName = (Split-Path $fullPath -Leaf).ToLower()
    
    # Check if file matches Microsoft whitelist
    if ($microsoftWhitelist -contains $fileName) {
        return $true
    }
    
    # Check if filename starts with whitelisted prefixes
    foreach ($item in $microsoftWhitelist) {
        if ($fileName -like "$item*") {
            return $true
        }
    }
    
    $pathLower = $fullPath.ToLower()
    if ($pathLower -match "\\windows\\system32\\|\\windows\\syswow64\\") {
        try {
            $signature = Get-AuthenticodeSignature -FilePath $fullPath -ErrorAction SilentlyContinue
            if ($signature.Status -eq "Valid" -and $signature.SignerCertificate.Subject -match "Microsoft") {
                return $true
            }
        }
        catch {
            # Signature check failed, treat as suspicious
            return $false
        }
    }
    
    return $false
}

# === THREAT ANALYSIS FUNCTION ===
function Get-DLLThreatScore {
    param([string]$filePath)
    
    if (-not (Test-Path $filePath)) {
        return $null
    }
    
    $score = 0
    $reasons = @()
    
    try {
        # Get file info
        $fileInfo = Get-Item $filePath -ErrorAction Stop
        $fileName = $fileInfo.Name.ToLower()
        
        # Calculate hash
        $hash = (Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop).Hash
        
        # Check digital signature
        try {
            $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction SilentlyContinue
            if ($signature.Status -ne "Valid") {
                $score += 40
                $reasons += "No valid digital signature"
            }
        }
        catch {
            $score += 40
            $reasons += "Signature check failed"
        }
        
        # Check suspicious names
        $suspiciousPatterns = @(
            "inject", "hook", "patch", "crack", "keygen", "loader"
        )
        
        foreach ($pattern in $suspiciousPatterns) {
            if ($fileName -like "*$pattern*") {
                $score += 50
                $reasons += "Suspicious filename pattern: $pattern"
                break
            }
        }
        
        # Check file age
        if ($fileInfo.CreationTime -gt (Get-Date).AddDays(-7)) {
            $score += 20
            $reasons += "Recently created (less than 7 days old)"
        }
        
        return @{
            Hash = $hash
            Score = $score
            Reasons = $reasons -join ", "
        }
    }
    catch {
        Write-Log "ERROR: Failed to analyze $filePath - $_"
        return $null
    }
}

# === QUARANTINE FUNCTION ===
function Quarantine-SuspiciousDLL {
    param(
        [string]$filePath,
        [string]$reason,
        [int]$score
    )
    
    $quarantineDir = ".\Quarantine"
    if (-not (Test-Path $quarantineDir)) {
        New-Item -Path $quarantineDir -ItemType Directory | Out-Null
    }
    
    $fileName = Split-Path $filePath -Leaf
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $quarantinePath = Join-Path $quarantineDir "${timestamp}_${fileName}"
    
    try {
        Copy-Item -Path $filePath -Destination $quarantinePath -Force
        Write-Log "QUARANTINED: $filePath (Score: $score, Reason: $reason)"
        Write-Host "ALERT: Suspicious DLL quarantined: $fileName" -ForegroundColor Red
        Write-Host "  Location: $filePath" -ForegroundColor Yellow
        Write-Host "  Threat Score: $score" -ForegroundColor Yellow
        Write-Host "  Reason: $reason" -ForegroundColor Yellow
        Write-Host "  Quarantine Location: $quarantinePath" -ForegroundColor Green
    }
    catch {
        Write-Log "ERROR: Failed to quarantine $filePath - $_"
    }
}

# === MAIN MONITORING FUNCTION ===
function Monitor-LoadedDLLs {
    Write-Log "Starting DLL injection monitoring (continuous mode) - scanning all drives..."
    
    $lastScan = @{}
    
    Write-Host "Performing initial full system scan..." -ForegroundColor Yellow
    
    # Get all drives (fixed, removable, and network)
    $allDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { 
        $_.Used -ne $null -or $_.Free -ne $null 
    }
    
    foreach ($drive in $allDrives) {
        $drivePath = "$($drive.Name):\"
        Write-Host "Scanning drive: $drivePath" -ForegroundColor Cyan
        Write-Log "Starting scan of drive: $drivePath"
        
        try {
            # Recursively scan for all DLLs on this drive
            Get-ChildItem -Path $drivePath -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $dllPath = $_.FullName
                $dllName = $_.Name
                
                # Skip if already scanned
                if ($lastScan.ContainsKey($dllPath)) {
                    return
                }
                
                $lastScan[$dllPath] = $true
                
                # Check vendor whitelists (silently)
                if (Test-IsMicrosoftFile -fullPath $dllPath -processName "") {
                    return
                }
                
                if (Test-IsPowerShellFile -fullPath $dllPath -processName "") {
                    return
                }
                
                if (Test-IsRainmeterFile -fullPath $dllPath -processName "") {
                    return
                }
                
                if (Test-IsMLWAppFile -fullPath $dllPath -processName "") {
                    return
                }
                
                if (Test-IsWallpaperEngineFile -fullPath $dllPath -processName "") {
                    return
                }
                
                if (Test-IsNvidiaFile -fullPath $dllPath -processName "") {
                    return
                }
                
                if (Test-IsAMDFile -fullPath $dllPath -processName "") {
                    return
                }
                
                if (Test-IsIntelFile -fullPath $dllPath -processName "") {
                    return
                }
                
                if (Test-IsRealtekFile -fullPath $dllPath -processName "") {
                    return
                }
                
                if (Test-IsDolbyFile -fullPath $dllPath -processName "") {
                    return
                }
                
                if (Test-Is7ZipFile -fullPath $dllPath -processName "") {
                    return
                }
                
                if (Test-IsCtfmonFile -fullPath $dllPath -processName "") {
                    return
                }
                
                if (Test-IsExplorerFile -fullPath $dllPath -processName "") {
                    return
                }
                
                if (Test-IsNotepadFile -fullPath $dllPath -processName "") {
                    return
                }
                
                # Analyze threat for non-whitelisted DLLs
                $analysis = Get-DLLThreatScore -filePath $dllPath
                if ($analysis -and $analysis.Score -ge 50) {
                    Quarantine-SuspiciousDLL -filePath $dllPath -reason $analysis.Reasons -score $analysis.Score
                }
                else {
                    # Log safe DLLs to database
                    if ($analysis) {
                        "$($analysis.Hash),$($analysis.Score)" | Out-File -FilePath $localDatabase -Append -Encoding utf8
                    }
                }
            }
        }
        catch {
            Write-Log "ERROR: Failed to scan drive $drivePath - $_"
        }
    }
    
    Write-Host "Initial full system scan complete. Starting continuous memory monitoring..." -ForegroundColor Green
    Write-Log "Initial scan complete. Starting continuous memory monitoring..."
    
    while ($true) {
        Get-Process | ForEach-Object {
            $proc = $_
            $procName = $proc.Name.ToLower()
            
            try {
                $proc.Modules | Where-Object { $_.FileName -like "*.dll" } | ForEach-Object {
                    $dllPath = $_.FileName
                    $dllName = Split-Path $dllPath -Leaf
                    $key = "$($proc.Id)-$dllPath"
                    
                    if ($lastScan.ContainsKey($key)) {
                        return
                    }
                    
                    $lastScan[$key] = $true
                    
                    # Check vendor whitelists (silently)
                    if (Test-IsMicrosoftFile -fullPath $dllPath -processName $procName) {
                        return
                    }
                    
                    if (Test-IsPowerShellFile -fullPath $dllPath -processName $procName) {
                        return
                    }
                    
                    if (Test-IsRainmeterFile -fullPath $dllPath -processName $procName) {
                        return
                    }
                    
                    if (Test-IsMLWAppFile -fullPath $dllPath -processName $procName) {
                        return
                    }
                    
                    if (Test-IsWallpaperEngineFile -fullPath $dllPath -processName $procName) {
                        return
                    }
                    
                    if (Test-IsNvidiaFile -fullPath $dllPath -processName $procName) {
                        return
                    }
                    
                    if (Test-IsAMDFile -fullPath $dllPath -processName $procName) {
                        return
                    }
                    
                    if (Test-IsIntelFile -fullPath $dllPath -processName $procName) {
                        return
                    }
                    
                    if (Test-IsRealtekFile -fullPath $dllPath -processName $procName) {
                        return
                    }
                    
                    if (Test-IsDolbyFile -fullPath $dllPath -processName $procName) {
                        return
                    }
                    
                    if (Test-Is7ZipFile -fullPath $dllPath -processName $procName) {
                        return
                    }
                    
                    if (Test-IsCtfmonFile -fullPath $dllPath -processName $procName) {
                        return
                    }
                    
                    if (Test-IsExplorerFile -fullPath $dllPath -processName $procName) {
                        return
                    }
                    
                    if (Test-IsNotepadFile -fullPath $dllPath -processName $procName) {
                        return
                    }
                    
                    # Analyze threat for non-whitelisted DLLs
                    $analysis = Get-DLLThreatScore -filePath $dllPath
                    if ($analysis -and $analysis.Score -ge 50) {
                        Quarantine-SuspiciousDLL -filePath $dllPath -reason $analysis.Reasons -score $analysis.Score
                    }
                    else {
                        # Log safe DLLs to database
                        if ($analysis) {
                            "$($analysis.Hash),$($analysis.Score)" | Out-File -FilePath $localDatabase -Append -Encoding utf8
                        }
                    }
                }
            }
            catch {
                # Some system processes can't be accessed
            }
        }
        
        # Clean up old scan cache every 100 iterations
        if ($lastScan.Count -gt 10000) {
            $lastScan.Clear()
            Write-Log "Cleared scan cache"
        }
        
        Start-Sleep -Seconds 5
    }
}

# === STARTUP ===
Write-Host "==================================================" -ForegroundColor Green
Write-Host "  Anti-Virus DLL Injection Monitor" -ForegroundColor Cyan
Write-Host "  with Intelligent Vendor Whitelisting" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Whitelisted Vendors:" -ForegroundColor Yellow
Write-Host "  Microsoft: Core Windows components" -ForegroundColor Cyan
Write-Host "  NVIDIA/AMD/Intel: Graphics drivers" -ForegroundColor Cyan
Write-Host "  Realtek/Dolby: Audio drivers" -ForegroundColor Cyan
Write-Host "  7-Zip: Compression tool" -ForegroundColor Cyan
Write-Host "  Common Apps: Explorer, CTFMon, PowerShell, Notepad" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Starting continuous monitoring..." -ForegroundColor Green
Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
Write-Host ""

Monitor-LoadedDLLs
