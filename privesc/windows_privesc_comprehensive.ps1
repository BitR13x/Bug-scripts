# Windows Privilege Escalation Comprehensive Automation Script
# Uses only built-in Windows tools and PowerShell cmdlets
# No external tool downloads required

param(
    [string]$OutputDir = "privesc_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [switch]$Verbose,
    [switch]$SkipNetworkEnum,
    [switch]$QuickScan
)

# Global variables
$Script:Findings = @()
$Script:CriticalFindings = @()
$Script:HighFindings = @()

# Color functions for output
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Green
    Add-Content -Path "$OutputDir\scan.log" -Value "[$(Get-Date)] [INFO] $Message"
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
    Add-Content -Path "$OutputDir\scan.log" -Value "[$(Get-Date)] [WARNING] $Message"
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
    Add-Content -Path "$OutputDir\scan.log" -Value "[$(Get-Date)] [ERROR] $Message"
}

function Write-Critical {
    param([string]$Message)
    Write-Host "[CRITICAL] $Message" -ForegroundColor Red -BackgroundColor Yellow
    Add-Content -Path "$OutputDir\scan.log" -Value "[$(Get-Date)] [CRITICAL] $Message"
    $Script:CriticalFindings += $Message
}

function Write-High {
    param([string]$Message)
    Write-Host "[HIGH] $Message" -ForegroundColor Magenta
    Add-Content -Path "$OutputDir\scan.log" -Value "[$(Get-Date)] [HIGH] $Message"
    $Script:HighFindings += $Message
}

function Show-Banner {
    Write-Host @"
================================================================
    Windows Privilege Escalation Comprehensive Scanner
    Built-in Tools Only - No External Dependencies
================================================================
Target: $env:COMPUTERNAME
User: $env:USERNAME\$env:USERDOMAIN
Date: $(Get-Date)
================================================================
"@ -ForegroundColor Cyan
}

# Initialize environment
function Initialize-Environment {
    Write-Info "Initializing scan environment..."
    
    # Create output directories
    $directories = @(
        $OutputDir,
        "$OutputDir\system_info",
        "$OutputDir\user_enum",
        "$OutputDir\service_enum",
        "$OutputDir\registry_enum",
        "$OutputDir\file_enum",
        "$OutputDir\network_enum",
        "$OutputDir\process_enum",
        "$OutputDir\privilege_enum",
        "$OutputDir\exploit_checks"
    )
    
    foreach ($dir in $directories) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    
    Write-Info "Output directory created: $OutputDir"
}

# System Information Enumeration
function Get-SystemInformation {
    Write-Info "Gathering system information..."
    
    $systemInfo = @{
        ComputerName = $env:COMPUTERNAME
        Username = $env:USERNAME
        Domain = $env:USERDOMAIN
        OS = (Get-WmiObject -Class Win32_OperatingSystem)
        Computer = (Get-WmiObject -Class Win32_ComputerSystem)
        BIOS = (Get-WmiObject -Class Win32_BIOS)
        TimeZone = (Get-WmiObject -Class Win32_TimeZone)
        Environment = Get-ChildItem Env:
    }
    
    # Basic system info
    $output = @"
=== SYSTEM INFORMATION ===
Computer Name: $($systemInfo.ComputerName)
Current User: $($systemInfo.Username)
Domain: $($systemInfo.Domain)
OS: $($systemInfo.OS.Caption) $($systemInfo.OS.Version)
Architecture: $($systemInfo.OS.OSArchitecture)
Install Date: $($systemInfo.OS.InstallDate)
Last Boot: $($systemInfo.OS.LastBootUpTime)
System Type: $($systemInfo.Computer.SystemType)
Total RAM: $([math]::Round($systemInfo.Computer.TotalPhysicalMemory/1GB,2)) GB
Manufacturer: $($systemInfo.Computer.Manufacturer)
Model: $($systemInfo.Computer.Model)

=== HOTFIXES ===
"@
    
    # Get installed hotfixes
    try {
        $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending
        foreach ($hotfix in $hotfixes) {
            $output += "$($hotfix.HotFixID) - $($hotfix.Description) - $($hotfix.InstalledOn)`n"
        }
    }
    catch {
        $output += "Could not retrieve hotfix information`n"
    }
    
    $output += "`n=== ENVIRONMENT VARIABLES ===`n"
    foreach ($env in $systemInfo.Environment) {
        $output += "$($env.Name) = $($env.Value)`n"
    }
    
    $output | Out-File "$OutputDir\system_info\basic_info.txt"
    
    # Check for interesting system info
    if ($systemInfo.OS.Caption -match "Windows 7|Windows Server 2008") {
        Write-Critical "Running on legacy OS: $($systemInfo.OS.Caption) - High exploit potential"
    }
    
    if ($systemInfo.Computer.Domain -eq "WORKGROUP") {
        Write-Info "System is not domain-joined"
    } else {
        Write-Info "System is domain-joined: $($systemInfo.Computer.Domain)"
    }
}

# User and Group Enumeration
function Get-UserEnumeration {
    Write-Info "Enumerating users and groups..."
    
    $output = "=== USER AND GROUP ENUMERATION ===`n`n"
    
    # Current user privileges
    $output += "=== CURRENT USER PRIVILEGES ===`n"
    try {
        $privileges = whoami /priv
        $output += $privileges | Out-String
        
        # Check for dangerous privileges
        $dangerousPrivs = @(
            "SeDebugPrivilege",
            "SeBackupPrivilege", 
            "SeRestorePrivilege",
            "SeTakeOwnershipPrivilege",
            "SeLoadDriverPrivilege",
            "SeImpersonatePrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeTcbPrivilege"
        )
        
        foreach ($priv in $dangerousPrivs) {
            if ($privileges -match $priv) {
                Write-Critical "Dangerous privilege found: $priv"
            }
        }
    }
    catch {
        $output += "Could not retrieve user privileges`n"
    }
    
    $output += "`n=== CURRENT USER GROUPS ===`n"
    try {
        $groups = whoami /groups
        $output += $groups | Out-String
        
        # Check for admin groups
        if ($groups -match "Administrators|Domain Admins|Enterprise Admins") {
            Write-Critical "User is member of administrative group!"
        }
    }
    catch {
        $output += "Could not retrieve user groups`n"
    }
    
    # Local users
    $output += "`n=== LOCAL USERS ===`n"
    try {
        $localUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True"
        foreach ($user in $localUsers) {
            $output += "Name: $($user.Name), Disabled: $($user.Disabled), Lockout: $($user.Lockout), PasswordRequired: $($user.PasswordRequired)`n"
        }
    }
    catch {
        $output += "Could not retrieve local users`n"
    }
    
    # Local groups
    $output += "`n=== LOCAL GROUPS ===`n"
    try {
        $localGroups = Get-WmiObject -Class Win32_Group -Filter "LocalAccount=True"
        foreach ($group in $localGroups) {
            $output += "Group: $($group.Name) - $($group.Description)`n"
            
            # Get group members
            try {
                $members = net localgroup "$($group.Name)" 2>$null
                if ($members) {
                    $output += "  Members: $($members -join ', ')`n"
                }
            }
            catch {}
        }
    }
    catch {
        $output += "Could not retrieve local groups`n"
    }
    
    $output | Out-File "$OutputDir\user_enum\users_groups.txt"
}

# Service Enumeration and Privilege Escalation Checks
function Get-ServiceEnumeration {
    Write-Info "Enumerating services for privilege escalation opportunities..."
    
    $output = "=== SERVICE ENUMERATION ===`n`n"
    
    # Get all services
    $services = Get-WmiObject -Class Win32_Service
    
    $output += "=== ALL SERVICES ===`n"
    foreach ($service in $services) {
        $output += "Name: $($service.Name)`n"
        $output += "  Display Name: $($service.DisplayName)`n"
        $output += "  State: $($service.State)`n"
        $output += "  Start Mode: $($service.StartMode)`n"
        $output += "  Path: $($service.PathName)`n"
        $output += "  Service Account: $($service.StartName)`n`n"
    }
    
    $output | Out-File "$OutputDir\service_enum\all_services.txt"
    
    # Check for unquoted service paths
    Write-Info "Checking for unquoted service paths..."
    $unquotedServices = @()
    
    foreach ($service in $services) {
        if ($service.PathName -and $service.PathName -notmatch '^".*"$' -and $service.PathName -match '.* .*') {
            $unquotedServices += $service
            Write-High "Unquoted service path: $($service.Name) - $($service.PathName)"
        }
    }
    
    if ($unquotedServices.Count -gt 0) {
        $unquotedOutput = "=== UNQUOTED SERVICE PATHS ===`n`n"
        foreach ($service in $unquotedServices) {
            $unquotedOutput += "Service: $($service.Name)`n"
            $unquotedOutput += "Path: $($service.PathName)`n"
            $unquotedOutput += "Start Mode: $($service.StartMode)`n"
            $unquotedOutput += "State: $($service.State)`n`n"
        }
        $unquotedOutput | Out-File "$OutputDir\service_enum\unquoted_services.txt"
    }
    
    # Check service permissions
    Write-Info "Checking service permissions..."
    $weakServices = @()
    
    foreach ($service in $services) {
        try {
            # Check if we can modify the service
            $serviceName = $service.Name
            $sc = sc.exe qc $serviceName 2>$null
            
            if ($sc -match "SERVICE_CHANGE_CONFIG|SERVICE_ALL_ACCESS") {
                $weakServices += $service
                Write-High "Weak service permissions: $serviceName"
            }
        }
        catch {}
    }
    
    # Check for services running as SYSTEM with weak file permissions
    Write-Info "Checking for writable service binaries..."
    $writableServices = @()
    
    foreach ($service in $services) {
        if ($service.PathName) {
            # Extract executable path
            $exePath = $service.PathName -replace '"', '' -replace ' .*$', ''
            
            if (Test-Path $exePath) {
                try {
                    $acl = Get-Acl $exePath -ErrorAction SilentlyContinue
                    if ($acl) {
                        $writeAccess = $acl.Access | Where-Object {
                            $_.FileSystemRights -match "Write|FullControl" -and 
                            $_.AccessControlType -eq "Allow" -and
                            ($_.IdentityReference -match "Everyone|Users|Authenticated Users|$env:USERNAME")
                        }
                        
                        if ($writeAccess) {
                            $writableServices += $service
                            Write-Critical "Writable service binary: $($service.Name) - $exePath"
                        }
                    }
                }
                catch {}
            }
        }
    }
}

# Registry Enumeration
function Get-RegistryEnumeration {
    Write-Info "Enumerating registry for privilege escalation opportunities..."
    
    $output = "=== REGISTRY ENUMERATION ===`n`n"
    
    # Check AlwaysInstallElevated
    Write-Info "Checking AlwaysInstallElevated..."
    try {
        $hklmValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
        $hkcuValue = Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
        
        if ($hklmValue.AlwaysInstallElevated -eq 1 -and $hkcuValue.AlwaysInstallElevated -eq 1) {
            Write-Critical "AlwaysInstallElevated is enabled! MSI packages will run as SYSTEM"
            $output += "CRITICAL: AlwaysInstallElevated is enabled`n"
        } else {
            $output += "AlwaysInstallElevated: Not enabled`n"
        }
    }
    catch {
        $output += "AlwaysInstallElevated: Could not check`n"
    }
    
    # Check AutoRun locations
    Write-Info "Checking AutoRun registry locations..."
    $autorunKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"
    )
    
    $output += "`n=== AUTORUN ENTRIES ===`n"
    foreach ($key in $autorunKeys) {
        try {
            $entries = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            if ($entries) {
                $output += "`n$key`:`n"
                $entries.PSObject.Properties | Where-Object {$_.Name -notmatch "PS"} | ForEach-Object {
                    $output += "  $($_.Name) = $($_.Value)`n"
                    
                    # Check if the executable is writable
                    $exePath = $_.Value -replace '"', '' -replace ' .*$', ''
                    if (Test-Path $exePath) {
                        try {
                            $acl = Get-Acl $exePath -ErrorAction SilentlyContinue
                            $writeAccess = $acl.Access | Where-Object {
                                $_.FileSystemRights -match "Write|FullControl" -and 
                                $_.AccessControlType -eq "Allow"
                            }
                            if ($writeAccess) {
                                Write-High "Writable AutoRun executable: $exePath"
                            }
                        }
                        catch {}
                    }
                }
            }
        }
        catch {
            $output += "$key`: Could not access`n"
        }
    }
    
    # Check for stored credentials in registry
    Write-Info "Checking for stored credentials in registry..."
    $credKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
        "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"
    )
    
    $output += "`n=== POTENTIAL STORED CREDENTIALS ===`n"
    foreach ($key in $credKeys) {
        try {
            $creds = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            if ($creds) {
                $output += "`n$key`:`n"
                $creds.PSObject.Properties | Where-Object {$_.Name -match "password|pwd|pass|cred"} | ForEach-Object {
                    $output += "  $($_.Name) = $($_.Value)`n"
                    Write-High "Potential credential found in registry: $key - $($_.Name)"
                }
            }
        }
        catch {}
    }
    
    $output | Out-File "$OutputDir\registry_enum\registry_analysis.txt"
}

# File System Enumeration
function Get-FileSystemEnumeration {
    Write-Info "Enumerating file system for privilege escalation opportunities..."
    
    $output = "=== FILE SYSTEM ENUMERATION ===`n`n"
    
    # Check for writable directories in PATH
    Write-Info "Checking PATH directories for write access..."
    $pathDirs = $env:PATH -split ';'
    $writablePaths = @()
    
    $output += "=== PATH DIRECTORY PERMISSIONS ===`n"
    foreach ($dir in $pathDirs) {
        if (Test-Path $dir) {
            try {
                $acl = Get-Acl $dir -ErrorAction SilentlyContinue
                $writeAccess = $acl.Access | Where-Object {
                    $_.FileSystemRights -match "Write|FullControl" -and 
                    $_.AccessControlType -eq "Allow" -and
                    ($_.IdentityReference -match "Everyone|Users|Authenticated Users|$env:USERNAME")
                }
                
                if ($writeAccess) {
                    $writablePaths += $dir
                    Write-High "Writable PATH directory: $dir"
                    $output += "WRITABLE: $dir`n"
                } else {
                    $output += "Protected: $dir`n"
                }
            }
            catch {
                $output += "Error checking: $dir`n"
            }
        }
    }
    
    # Check for interesting files
    Write-Info "Searching for interesting files..."
    $interestingFiles = @()
    $searchPaths = @("C:\", "C:\Users", "C:\Windows\Temp", "C:\Temp")
    $filePatterns = @("*.config", "*.xml", "*.txt", "*.log", "*.bak", "*.old", "*.ini")
    
    $output += "`n=== INTERESTING FILES ===`n"
    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            foreach ($pattern in $filePatterns) {
                try {
                    $files = Get-ChildItem -Path $path -Filter $pattern -Recurse -ErrorAction SilentlyContinue | Select-Object -First 50
                    foreach ($file in $files) {
                        $output += "$($file.FullName)`n"
                        
                        # Check for potential credentials in file names
                        if ($file.Name -match "password|credential|config|backup") {
                            Write-Info "Potentially interesting file: $($file.FullName)"
                        }
                    }
                }
                catch {}
            }
        }
    }
    
    $output | Out-File "$OutputDir\file_enum\filesystem_analysis.txt"
}

# Network Enumeration
function Get-NetworkEnumeration {
    if ($SkipNetworkEnum) {
        Write-Info "Skipping network enumeration..."
        return
    }
    
    Write-Info "Enumerating network configuration..."
    
    $output = "=== NETWORK ENUMERATION ===`n`n"
    
    # Network interfaces
    $output += "=== NETWORK INTERFACES ===`n"
    try {
        $interfaces = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled}
        foreach ($interface in $interfaces) {
            $output += "Interface: $($interface.Description)`n"
            $output += "  IP Address: $($interface.IPAddress -join ', ')`n"
            $output += "  Subnet Mask: $($interface.IPSubnet -join ', ')`n"
            $output += "  Gateway: $($interface.DefaultIPGateway -join ', ')`n"
            $output += "  DNS: $($interface.DNSServerSearchOrder -join ', ')`n`n"
        }
    }
    catch {
        $output += "Could not retrieve network interfaces`n"
    }
    
    # Active connections
    $output += "=== ACTIVE CONNECTIONS ===`n"
    try {
        $connections = netstat -ano
        $output += $connections | Out-String
    }
    catch {
        $output += "Could not retrieve network connections`n"
    }
    
    # Firewall status
    $output += "`n=== FIREWALL STATUS ===`n"
    try {
        $firewall = netsh advfirewall show allprofiles
        $output += $firewall | Out-String
    }
    catch {
        $output += "Could not retrieve firewall status`n"
    }
    
    # Network shares
    $output += "`n=== NETWORK SHARES ===`n"
    try {
        $shares = Get-WmiObject -Class Win32_Share
        foreach ($share in $shares) {
            $output += "Share: $($share.Name) - $($share.Path) - $($share.Description)`n"
        }
    }
    catch {
        $output += "Could not retrieve network shares`n"
    }
    
    $output | Out-File "$OutputDir\network_enum\network_analysis.txt"
}

# Process Enumeration
function Get-ProcessEnumeration {
    Write-Info "Enumerating running processes..."
    
    $output = "=== PROCESS ENUMERATION ===`n`n"
    
    # Running processes
    try {
        $processes = Get-Process | Sort-Object CPU -Descending
        $output += "=== RUNNING PROCESSES ===`n"
        foreach ($process in $processes) {
            $output += "PID: $($process.Id), Name: $($process.ProcessName), CPU: $($process.CPU), Memory: $($process.WorkingSet)`n"
        }
    }
    catch {
        $output += "Could not retrieve process list`n"
    }
    
    # Services and their processes
    $output += "`n=== SERVICE PROCESSES ===`n"
    try {
        $services = Get-WmiObject -Class Win32_Service | Where-Object {$_.ProcessId -gt 0}
        foreach ($service in $services) {
            $output += "Service: $($service.Name), PID: $($service.ProcessId), Account: $($service.StartName)`n"
        }
    }
    catch {
        $output += "Could not retrieve service processes`n"
    }
    
    $output | Out-File "$OutputDir\process_enum\process_analysis.txt"
}

# Scheduled Tasks Enumeration
function Get-ScheduledTasksEnumeration {
    Write-Info "Enumerating scheduled tasks..."
    
    $output = "=== SCHEDULED TASKS ENUMERATION ===`n`n"
    
    try {
        # Get scheduled tasks using schtasks
        $tasks = schtasks /query /fo LIST /v
        $output += $tasks | Out-String
        
        # Check for writable task files
        $taskFiles = Get-ChildItem -Path "C:\Windows\System32\Tasks" -Recurse -ErrorAction SilentlyContinue
        $output += "`n=== TASK FILES ===`n"
        foreach ($file in $taskFiles) {
            try {
                $acl = Get-Acl $file.FullName -ErrorAction SilentlyContinue
                $writeAccess = $acl.Access | Where-Object {
                    $_.FileSystemRights -match "Write|FullControl" -and 
                    $_.AccessControlType -eq "Allow"
                }
                if ($writeAccess) {
                    Write-High "Writable scheduled task file: $($file.FullName)"
                    $output += "WRITABLE: $($file.FullName)`n"
                }
            }
            catch {}
        }
    }
    catch {
        $output += "Could not retrieve scheduled tasks`n"
    }
    
    $output | Out-File "$OutputDir\process_enum\scheduled_tasks.txt"
}

# Check for common privilege escalation exploits
function Test-CommonExploits {
    Write-Info "Checking for common Windows privilege escalation exploits..."
    
    $output = "=== COMMON EXPLOIT CHECKS ===`n`n"
    
    # Get OS version for exploit matching
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = $os.Version
    $osBuild = $os.BuildNumber
    
    $output += "OS Version: $($os.Caption) $osVersion (Build $osBuild)`n`n"
    
    # Check for known vulnerable versions
    $exploits = @{
        "MS16-032" = @{
            Description = "Secondary Logon Handle Privilege Escalation"
            Affected = @("10.0.10240", "10.0.10586", "6.1.7601", "6.3.9600")
            CVE = "CVE-2016-0099"
        }
        "MS16-135" = @{
            Description = "Win32k Elevation of Privilege"
            Affected = @("10.0.14393", "10.0.10586", "10.0.10240")
            CVE = "CVE-2016-7255"
        }
        "MS17-017" = @{
            Description = "GDI Palette Objects Local Privilege Escalation"
            Affected = @("10.0.14393", "10.0.10586", "10.0.10240", "6.1.7601", "6.3.9600")
            CVE = "CVE-2017-8464"
        }
        "MS15-051" = @{
            Description = "Windows ClientCopyImage Win32k Exploit"
            Affected = @("6.1.7601", "6.3.9600")
            CVE = "CVE-2015-1701"
        }
        "MS14-058" = @{
            Description = "Win32k.sys Privilege Escalation"
            Affected = @("6.1.7601", "6.3.9600")
            CVE = "CVE-2014-4113"
        }
    }
    
    $output += "=== POTENTIAL EXPLOITS ===`n"
    foreach ($exploit in $exploits.Keys) {
        $info = $exploits[$exploit]
        foreach ($version in $info.Affected) {
            if ($osVersion -like "$version*") {
                Write-Critical "Potential exploit: $exploit - $($info.Description) ($($info.CVE))"
                $output += "VULNERABLE: $exploit - $($info.Description) - $($info.CVE)`n"
                break
            }
        }
    }
    
    $output | Out-File "$OutputDir\exploit_checks\exploit_analysis.txt"
}

# Generate summary report
function New-SummaryReport {
    Write-Info "Generating summary report..."
    
    $report = @"
================================================================
    WINDOWS PRIVILEGE ESCALATION COMPREHENSIVE SCAN REPORT
================================================================
Scan Date: $(Get-Date)
Target: $env:COMPUTERNAME
User: $env:USERNAME
Domain: $env:USERDOMAIN
Output Directory: $OutputDir

=== SCAN SUMMARY ===
Total Critical Findings: $($Script:CriticalFindings.Count)
Total High Findings: $($Script:HighFindings.Count)

=== CRITICAL FINDINGS ===
"@
    
    foreach ($finding in $Script:CriticalFindings) {
        $report += "$finding`n"
    }
    
    $report += "`n=== HIGH FINDINGS ===`n"
    foreach ($finding in $Script:HighFindings) {
        $report += "$finding`n"
    }
    
    $report += @"

=== ENUMERATION COMPLETED ===
✓ System Information
✓ User and Group Enumeration
✓ Service Enumeration
✓ Registry Analysis
✓ File System Analysis
✓ Network Configuration
✓ Process Analysis
✓ Scheduled Tasks
✓ Common Exploit Checks

=== RECOMMENDED NEXT STEPS ===
1. Review all critical and high findings
2. Test identified privilege escalation vectors
3. Check for additional manual enumeration opportunities
4. Verify exploit applicability
5. Document successful privilege escalation methods

=== OUTPUT FILES ===
"@
    
    Get-ChildItem -Path $OutputDir -Recurse -File | ForEach-Object {
        $report += "$($_.FullName)`n"
    }
    
    $report += @"

=== COMMON ATTACK VECTORS TO INVESTIGATE ===
- Unquoted service paths with writable directories
- Services with weak permissions
- Writable service binaries
- AlwaysInstallElevated registry setting
- Dangerous user privileges (SeDebugPrivilege, SeImpersonatePrivilege, etc.)
- Writable scheduled task files
- Stored credentials in registry/files
- Kernel exploits based on OS version
- DLL hijacking opportunities
- Token impersonation possibilities

================================================================
"@
    
    $report | Out-File "$OutputDir\SUMMARY_REPORT.txt"
    Write-Info "Summary report generated: $OutputDir\SUMMARY_REPORT.txt"
}

# Main execution function
function Start-PrivescScan {
    Show-Banner
    
    # Check if running as admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if ($isAdmin) {
        Write-Warning "Running as Administrator - some privilege escalation checks may not be relevant"
    }
    
    Initialize-Environment
    
    Write-Info "Starting comprehensive Windows privilege escalation enumeration..."
    
    # Execute all enumeration functions
    Get-SystemInformation
    Get-UserEnumeration
    Get-ServiceEnumeration
    Get-RegistryEnumeration
    Get-FileSystemEnumeration
    
    if (-not $SkipNetworkEnum) {
        Get-NetworkEnumeration
    }
    
    Get-ProcessEnumeration
    Get-ScheduledTasksEnumeration
    Test-CommonExploits
    
    New-SummaryReport
    
    Write-Host @"

================================================================
    WINDOWS PRIVILEGE ESCALATION SCAN COMPLETED
================================================================
Results saved in: $OutputDir
Summary report: $OutputDir\SUMMARY_REPORT.txt

Critical Findings: $($Script:CriticalFindings.Count)
High Findings: $($Script:HighFindings.Count)

Review the summary report and investigate all findings!
================================================================
"@ -ForegroundColor Green
}

# Execute the scan
Start-PrivescScan
