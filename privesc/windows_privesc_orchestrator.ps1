# Windows Privilege Escalation Orchestrator
# Automates running multiple Windows privilege escalation enumeration tools
# Uses existing tools instead of recreating functionality

param(
    [switch]$SkipDownload,
    [string]$OutputDir = "privesc_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [switch]$Verbose
)

# Color functions for output
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Green
    Add-Content -Path "$OutputDir\orchestrator.log" -Value "[$(Get-Date)] [INFO] $Message"
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
    Add-Content -Path "$OutputDir\orchestrator.log" -Value "[$(Get-Date)] [WARNING] $Message"
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
    Add-Content -Path "$OutputDir\orchestrator.log" -Value "[$(Get-Date)] [ERROR] $Message"
}

function Write-Critical {
    param([string]$Message)
    Write-Host "[CRITICAL] $Message" -ForegroundColor Red -BackgroundColor Yellow
    Add-Content -Path "$OutputDir\orchestrator.log" -Value "[$(Get-Date)] [CRITICAL] $Message"
}

function Show-Banner {
    Write-Host @"
================================================================
    Windows Privilege Escalation Automation Orchestrator
    Leveraging: WinPEAS, PowerUp, PrivescCheck, Sherlock, Watson
================================================================
"@ -ForegroundColor Cyan
}

# Tool URLs and configurations
$ToolsConfig = @{
    WinPEAS = @{
        URL = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe"
        FileName = "winPEASx64.exe"
        Type = "Executable"
    }
    PowerUp = @{
        URL = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1"
        FileName = "PowerUp.ps1"
        Type = "PowerShell"
    }
    PrivescCheck = @{
        URL = "https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1"
        FileName = "PrivescCheck.ps1"
        Type = "PowerShell"
    }
    Sherlock = @{
        URL = "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock/sherlock.py"
        FileName = "Sherlock.ps1"
        Type = "PowerShell"
        AltURL = "https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1"
    }
    Watson = @{
        URL = "https://github.com/rasta-mouse/Watson/releases/latest/download/Watson.exe"
        FileName = "Watson.exe"
        Type = "Executable"
    }
    Seatbelt = @{
        URL = "https://github.com/GhostPack/Seatbelt/releases/latest/download/Seatbelt.exe"
        FileName = "Seatbelt.exe"
        Type = "Executable"
    }
}

# Setup environment
function Initialize-Environment {
    Write-Info "Setting up environment..."
    
    # Create output directories
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    New-Item -ItemType Directory -Path "$OutputDir\tools" -Force | Out-Null
    New-Item -ItemType Directory -Path "$OutputDir\winpeas" -Force | Out-Null
    New-Item -ItemType Directory -Path "$OutputDir\powerup" -Force | Out-Null
    New-Item -ItemType Directory -Path "$OutputDir\privesccheck" -Force | Out-Null
    New-Item -ItemType Directory -Path "$OutputDir\sherlock" -Force | Out-Null
    New-Item -ItemType Directory -Path "$OutputDir\watson" -Force | Out-Null
    New-Item -ItemType Directory -Path "$OutputDir\seatbelt" -Force | Out-Null
    New-Item -ItemType Directory -Path "$OutputDir\manual_checks" -Force | Out-Null
    
    Write-Info "Output directory created: $OutputDir"
}

# Download tools
function Get-Tools {
    if ($SkipDownload) {
        Write-Info "Skipping tool downloads..."
        return
    }
    
    Write-Info "Downloading privilege escalation tools..."
    
    foreach ($tool in $ToolsConfig.Keys) {
        $config = $ToolsConfig[$tool]
        $filePath = "$OutputDir\tools\$($config.FileName)"
        
        if (Test-Path $filePath) {
            Write-Info "$tool already exists, skipping download"
            continue
        }
        
        try {
            Write-Info "Downloading $tool..."
            
            # Try primary URL first
            try {
                Invoke-WebRequest -Uri $config.URL -OutFile $filePath -UseBasicParsing
                Write-Info "$tool downloaded successfully"
            }
            catch {
                # Try alternative URL if available
                if ($config.AltURL) {
                    Write-Warning "Primary URL failed, trying alternative for $tool..."
                    Invoke-WebRequest -Uri $config.AltURL -OutFile $filePath -UseBasicParsing
                    Write-Info "$tool downloaded from alternative URL"
                }
                else {
                    throw
                }
            }
        }
        catch {
            Write-Error "Failed to download $tool`: $($_.Exception.Message)"
        }
    }
}

# Run WinPEAS
function Invoke-WinPEAS {
    Write-Info "Running WinPEAS (comprehensive enumeration)..."
    $winpeasPath = "$OutputDir\tools\winPEASx64.exe"
    
    if (Test-Path $winpeasPath) {
        try {
            $process = Start-Process -FilePath $winpeasPath -ArgumentList "cmd" -RedirectStandardOutput "$OutputDir\winpeas\winpeas_output.txt" -RedirectStandardError "$OutputDir\winpeas\winpeas_errors.txt" -NoNewWindow -PassThru
            
            # Set timeout of 10 minutes
            if (-not $process.WaitForExit(600000)) {
                $process.Kill()
                Write-Warning "WinPEAS timed out after 10 minutes"
            }
            
            # Extract critical findings
            if (Test-Path "$OutputDir\winpeas\winpeas_output.txt") {
                Select-String -Path "$OutputDir\winpeas\winpeas_output.txt" -Pattern "CRITICAL|HIGH|99%" | Out-File "$OutputDir\winpeas\critical_findings.txt"
            }
            
            Write-Info "WinPEAS completed. Check $OutputDir\winpeas\ for results"
        }
        catch {
            Write-Error "Failed to run WinPEAS: $($_.Exception.Message)"
        }
    }
    else {
        Write-Error "WinPEAS not found at $winpeasPath"
    }
}

# Run PowerUp
function Invoke-PowerUp {
    Write-Info "Running PowerUp (PowerShell privilege escalation checks)..."
    $powerupPath = "$OutputDir\tools\PowerUp.ps1"
    
    if (Test-Path $powerupPath) {
        try {
            $output = @"
# PowerUp Execution Results
# Generated: $(Get-Date)

"@
            
            # Import and run PowerUp
            . $powerupPath
            
            $output += "`n=== Invoke-AllChecks ===`n"
            $output += Invoke-AllChecks | Out-String
            
            $output | Out-File "$OutputDir\powerup\powerup_output.txt"
            
            Write-Info "PowerUp completed. Check $OutputDir\powerup\ for results"
        }
        catch {
            Write-Error "Failed to run PowerUp: $($_.Exception.Message)"
        }
    }
    else {
        Write-Error "PowerUp not found at $powerupPath"
    }
}

# Run PrivescCheck
function Invoke-PrivescCheck {
    Write-Info "Running PrivescCheck (detailed Windows enumeration)..."
    $privescPath = "$OutputDir\tools\PrivescCheck.ps1"
    
    if (Test-Path $privescPath) {
        try {
            . $privescPath
            
            # Run with different report types
            Invoke-PrivescCheck -Report PrivescCheck -Format TXT -OutputFile "$OutputDir\privesccheck\privesccheck_report.txt"
            Invoke-PrivescCheck -Extended -Report PrivescCheck -Format TXT -OutputFile "$OutputDir\privesccheck\privesccheck_extended.txt"
            
            Write-Info "PrivescCheck completed. Check $OutputDir\privesccheck\ for results"
        }
        catch {
            Write-Error "Failed to run PrivescCheck: $($_.Exception.Message)"
        }
    }
    else {
        Write-Error "PrivescCheck not found at $privescPath"
    }
}

# Run Sherlock
function Invoke-Sherlock {
    Write-Info "Running Sherlock (Windows exploit suggester)..."
    $sherlockPath = "$OutputDir\tools\Sherlock.ps1"
    
    if (Test-Path $sherlockPath) {
        try {
            . $sherlockPath
            Find-AllVulns | Out-File "$OutputDir\sherlock\sherlock_output.txt"
            
            Write-Info "Sherlock completed. Check $OutputDir\sherlock\ for results"
        }
        catch {
            Write-Error "Failed to run Sherlock: $($_.Exception.Message)"
        }
    }
    else {
        Write-Error "Sherlock not found at $sherlockPath"
    }
}

# Run Watson
function Invoke-Watson {
    Write-Info "Running Watson (Windows exploit suggester)..."
    $watsonPath = "$OutputDir\tools\Watson.exe"
    
    if (Test-Path $watsonPath) {
        try {
            $process = Start-Process -FilePath $watsonPath -RedirectStandardOutput "$OutputDir\watson\watson_output.txt" -RedirectStandardError "$OutputDir\watson\watson_errors.txt" -NoNewWindow -PassThru
            
            if (-not $process.WaitForExit(120000)) {
                $process.Kill()
                Write-Warning "Watson timed out after 2 minutes"
            }
            
            Write-Info "Watson completed. Check $OutputDir\watson\ for results"
        }
        catch {
            Write-Error "Failed to run Watson: $($_.Exception.Message)"
        }
    }
    else {
        Write-Error "Watson not found at $watsonPath"
    }
}

# Run Seatbelt
function Invoke-Seatbelt {
    Write-Info "Running Seatbelt (comprehensive host enumeration)..."
    $seatbeltPath = "$OutputDir\tools\Seatbelt.exe"
    
    if (Test-Path $seatbeltPath) {
        try {
            # Run different Seatbelt checks
            $checks = @("All", "User", "System", "Remote")
            
            foreach ($check in $checks) {
                $outputFile = "$OutputDir\seatbelt\seatbelt_$($check.ToLower()).txt"
                $process = Start-Process -FilePath $seatbeltPath -ArgumentList "-group=$check" -RedirectStandardOutput $outputFile -RedirectStandardError "$OutputDir\seatbelt\seatbelt_errors.txt" -NoNewWindow -PassThru
                
                if (-not $process.WaitForExit(180000)) {
                    $process.Kill()
                    Write-Warning "Seatbelt $check timed out after 3 minutes"
                }
            }
            
            Write-Info "Seatbelt completed. Check $OutputDir\seatbelt\ for results"
        }
        catch {
            Write-Error "Failed to run Seatbelt: $($_.Exception.Message)"
        }
    }
    else {
        Write-Error "Seatbelt not found at $seatbeltPath"
    }
}

# Manual checks using built-in Windows commands
function Invoke-ManualChecks {
    Write-Info "Running manual Windows privilege escalation checks..."
    
    $output = @"
=== WINDOWS MANUAL PRIVILEGE ESCALATION CHECKS ===
Generated: $(Get-Date)
Computer: $env:COMPUTERNAME
User: $env:USERNAME
Domain: $env:USERDOMAIN

=== SYSTEM INFORMATION ===
"@
    
    try {
        $output += "`n" + (systeminfo | Out-String)
        
        $output += "`n=== CURRENT USER PRIVILEGES ===`n"
        $output += whoami /priv | Out-String
        
        $output += "`n=== USER GROUPS ===`n"
        $output += whoami /groups | Out-String
        
        $output += "`n=== LOCAL USERS ===`n"
        $output += net user | Out-String
        
        $output += "`n=== LOCAL ADMINISTRATORS ===`n"
        $output += net localgroup administrators | Out-String
        
        $output += "`n=== INSTALLED PROGRAMS ===`n"
        $output += Get-WmiObject -Class Win32_Product | Select-Object Name, Version | Out-String
        
        $output += "`n=== RUNNING SERVICES ===`n"
        $output += Get-Service | Where-Object {$_.Status -eq "Running"} | Out-String
        
        $output += "`n=== SCHEDULED TASKS ===`n"
        $output += schtasks /query /fo LIST /v | Out-String
        
        $output += "`n=== NETWORK CONNECTIONS ===`n"
        $output += netstat -ano | Out-String
        
        $output += "`n=== FIREWALL STATUS ===`n"
        $output += netsh advfirewall show allprofiles | Out-String
        
        $output += "`n=== REGISTRY AUTORUN LOCATIONS ===`n"
        $autorunKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        
        foreach ($key in $autorunKeys) {
            $output += "`n$key`:`n"
            try {
                $output += Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | Out-String
            }
            catch {
                $output += "Cannot access registry key`n"
            }
        }
        
        $output | Out-File "$OutputDir\manual_checks\manual_enumeration.txt"
        
        Write-Info "Manual checks completed"
    }
    catch {
        Write-Error "Failed during manual checks: $($_.Exception.Message)"
    }
}

# Check common privilege escalation vectors
function Test-CommonVectors {
    Write-Info "Checking common Windows privilege escalation vectors..."
    
    $findings = @()
    
    # Check for unquoted service paths
    try {
        $services = Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -notmatch '^".*"$' -and $_.PathName -match '.* .*'}
        if ($services) {
            $findings += "[CRITICAL] Unquoted service paths found:"
            foreach ($service in $services) {
                $findings += "  - $($service.Name): $($service.PathName)"
            }
        }
    }
    catch {
        $findings += "[ERROR] Could not check unquoted service paths"
    }
    
    # Check for writable service binaries
    try {
        $services = Get-WmiObject -Class Win32_Service
        foreach ($service in $services) {
            if ($service.PathName -match '^"?([^"]*\.exe)') {
                $exePath = $matches[1]
                if (Test-Path $exePath) {
                    try {
                        $acl = Get-Acl $exePath
                        $writeAccess = $acl.Access | Where-Object {$_.FileSystemRights -match "Write|FullControl" -and $_.AccessControlType -eq "Allow"}
                        if ($writeAccess) {
                            $findings += "[HIGH] Writable service binary: $exePath ($($service.Name))"
                        }
                    }
                    catch {}
                }
            }
        }
    }
    catch {
        $findings += "[ERROR] Could not check service binary permissions"
    }
    
    # Check for AlwaysInstallElevated
    try {
        $hklm = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
        $hkcu = Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
        
        if ($hklm.AlwaysInstallElevated -eq 1 -and $hkcu.AlwaysInstallElevated -eq 1) {
            $findings += "[CRITICAL] AlwaysInstallElevated is enabled!"
        }
    }
    catch {
        $findings += "[INFO] Could not check AlwaysInstallElevated registry keys"
    }
    
    # Check for stored credentials
    try {
        $cmdkey = cmdkey /list 2>$null
        if ($cmdkey -match "Target:") {
            $findings += "[HIGH] Stored credentials found via cmdkey"
        }
    }
    catch {}
    
    # Output findings
    $findings | Out-File "$OutputDir\manual_checks\common_vectors.txt"
    
    foreach ($finding in $findings) {
        if ($finding -match "CRITICAL") {
            Write-Critical $finding
        }
        elseif ($finding -match "HIGH") {
            Write-Warning $finding
        }
        else {
            Write-Info $finding
        }
    }
}

# Generate consolidated report
function New-ConsolidatedReport {
    Write-Info "Generating consolidated report..."
    
    $report = @"
================================================================
    WINDOWS PRIVILEGE ESCALATION AUTOMATION REPORT
================================================================
Scan Date: $(Get-Date)
Target: $env:COMPUTERNAME
User: $env:USERNAME
Domain: $env:USERDOMAIN
Output Directory: $OutputDir

=== TOOLS EXECUTED ===
✓ WinPEAS - Comprehensive Windows enumeration
✓ PowerUp - PowerShell privilege escalation checks
✓ PrivescCheck - Detailed Windows privilege escalation enumeration
✓ Sherlock - Windows exploit suggester
✓ Watson - Windows exploit suggester (.NET)
✓ Seatbelt - Host enumeration for situational awareness
✓ Manual Checks - Custom Windows enumeration

=== CRITICAL FINDINGS SUMMARY ===
Check the following files for detailed analysis:
- $OutputDir\winpeas\critical_findings.txt
- $OutputDir\manual_checks\common_vectors.txt
- $OutputDir\powerup\powerup_output.txt

=== RECOMMENDED ANALYSIS ORDER ===
1. Review critical findings from WinPEAS
2. Check common vectors analysis for immediate wins
3. Examine PowerUp output for service/registry issues
4. Review PrivescCheck extended report
5. Check Sherlock/Watson for applicable exploits
6. Cross-reference findings across all tools

=== OUTPUT FILES ===
"@
    
    Get-ChildItem -Path $OutputDir -Recurse -File | ForEach-Object {
        $report += "`n$($_.FullName)"
    }
    
    $report += @"

=== NEXT STEPS ===
1. Analyze all generated reports
2. Prioritize findings by criticality and exploitability
3. Test identified privilege escalation vectors
4. Document successful exploitation methods
5. Consider defense evasion techniques if needed

=== COMMON ATTACK VECTORS TO INVESTIGATE ===
- Unquoted service paths
- Weak service permissions
- Registry autoruns
- Scheduled tasks with weak permissions
- AlwaysInstallElevated registry setting
- Stored credentials
- DLL hijacking opportunities
- Token impersonation possibilities

================================================================
"@
    
    $report | Out-File "$OutputDir\consolidated_report.txt"
    Write-Info "Consolidated report generated: $OutputDir\consolidated_report.txt"
}

# Main execution function
function Main {
    Show-Banner
    
    # Check execution policy
    $executionPolicy = Get-ExecutionPolicy
    if ($executionPolicy -eq "Restricted") {
        Write-Warning "PowerShell execution policy is Restricted. Some tools may not work properly."
        Write-Info "Consider running: Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process"
    }
    
    Initialize-Environment
    Get-Tools
    
    Write-Info "Starting automated Windows privilege escalation enumeration..."
    
    # Run all tools
    Invoke-WinPEAS
    Invoke-PowerUp
    Invoke-PrivescCheck
    Invoke-Sherlock
    Invoke-Watson
    Invoke-Seatbelt
    Invoke-ManualChecks
    Test-CommonVectors
    
    New-ConsolidatedReport
    
    Write-Host @"

================================================================
    WINDOWS PRIVILEGE ESCALATION ENUMERATION COMPLETED
================================================================
Results saved in: $OutputDir
Main report: $OutputDir\consolidated_report.txt
Review critical findings and prioritize testing!
================================================================
"@ -ForegroundColor Green
}

# Execute main function
Main
