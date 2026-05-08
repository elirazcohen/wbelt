function Invoke-SystemHealth {
# assigning variables for CPU, RAM and Drives and the log file
$Logs = "$PSScriptRoot\SystemHealth_log.txt"
$stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 
$CPU = Get-Counter "\Processor(_Total)\% Processor Time"
$RAM = Get-CimInstance Win32_OperatingSystem
$Drives = Get-Volume | Where-Object { $_.DriveLetter -ne $null }

 # --- LOG SIZE PROTECTION ---
$maxSizeMB = 5

if (Test-Path $Logs) {

$fileSizeMB = (Get-Item $Logs).Length / 1MB

if ($fileSizeMB -gt $maxSizeMB) {

$lastLines = Get-Content $Logs -Tail 1000

Set-Content -Path $Logs -Value $lastLines

Write-Host "Log exceeded $maxSizeMB MB, trimmed to last 1000 lines." -ForegroundColor Yellow
}
}
# Calculating RAM with error handling in case it fails
try {
$TotalGB = [math]::Round($RAM.TotalVisibleMemorySize / 1MB, 2)
$FreeGB  = [math]::Round($RAM.FreePhysicalMemory / 1MB, 2)
$RAMUsedGB = $TotalGB - $FreeGB


if ($RAMUsedGB / $TotalGB * 100 -gt 80) {
# Outputting and logging Warning of RAM usage 
Write-Host "[$stamp] WARNING: RAM usage high ($RAMUsedGB GB / $TotalGB GB)" -ForegroundColor Red
Add-Content -Path $Logs -Value "[$stamp] WARNING: RAM usage high ($RAMUsedGB GB / $TotalGB GB)`n"
# Checking if RAM usage is normal
} else {
Write-Host "RAM usage normal ($RAMUsedGB GB / $TotalGB GB)" -ForegroundColor Green
}
# Checking for failure in case getting RAM usage fails
} catch {
Write-Host "FAILED to get RAM usage"
Add-Content -Path $Logs -Value "[$stamp] FAILED to get RAM usage"
} 
# Calculating CPU
try {
$CPUUsage = [math]::Round($CPU.CounterSamples[0].CookedValue, 2)
Write-Host "CPU Usage: $CPUUsage %" -ForegroundColor Cyan
if ($CPUUsage -gt 80) {
# Outputting and logging warning of high CPU usage
Write-Host "WARNING: CPU usage HIGH | CPU Usage: $CPUUsage %"
Add-Content -Path $Logs -Value "[$stamp] WARNING: CPU usage HIGH | CPU Usage: $CPUUsage %"
}
} catch {
# Outputting and logging failure of getting CPU usage
Write-Host "FAILED to get CPU usage"
Add-Content -Path $Logs -Value "[$stamp] FAILED to get CPU usage"
} 
# Looping through each drive and showing used and free space with error handling in case it fails
try {
foreach ($drive in $Drives) {
$DriveUsedGB = [math]::Round(($drive.Size - $drive.SizeRemaining)/1GB, 2)
$DriveFreeGB = [math]::Round($drive.SizeRemaining/1GB, 2)

Write-Host "Drive $($drive.DriveLetter): Used = $DriveUsedGB GB, Free = $DriveFreeGB GB" -ForegroundColor Yellow

# Warning the user of low space on drives and logging it to file
if ($drive.SizeRemaining -lt 10GB) {
Write-Host "WARNING: Low space on drive $($drive.DriveLetter)" -ForegroundColor DarkRed
Add-Content -Path $Logs -Value "[$stamp] WARNING: Low space on drive $($drive.DriveLetter) `n"
} else {
# Putting an else in case there is enough space on drives
Write-Host "There is enough space on drive $($drive.DriveLetter)" -ForegroundColor DarkGreen
}
}
# Checking for failure of getting disk usage on drives
} catch {
Write-Host "FAILED to get disk usage on drives"
Add-Content -Path $Logs -Value "[$stamp] FAILED to get space usage"
}
}

Function Invoke-Portscan {
$ports = 443, 80, 53
$targets = "google.com", "youtube.com", "microsoft.com"

foreach ($target in $targets) {
Write-Host "`nScanning $target..." -ForegroundColor Cyan


#--------------Resolve DNS----------------

$IPs = Resolve-DnsName $target | Where-Object { $_.Type -eq "A" }

$IP = ($IPs | Select-Object -First 1).IPAddress

Write-Host "IP Address: $IP"

#---------------Scan ports---------------
foreach ($port in $ports) {

$results = Test-NetConnection $target -Port $port

if ($results.TcpTestSucceeded) {
Write-Host "[OPEN]  $target : $port" -ForegroundColor Green
} else {
Write-Host "[CLOSED] $target : $port" -ForegroundColor Red
}
}
}
}
#-------- LAN SCANNER --------
Function invoke-LANscan {
# Permanent log file in InstalledScripts folder
$logFile = "$PSScriptRoot\network_scan.txt"
Add-Content -Path $logFile -Value "`n---- LAN Scan Started: $(Get-Date) ----`n"
# starting message for the LAN scanning
Write-Host "`nStarting LAN scan..." -ForegroundColor Yellow

# assigning arp -a for MAC addresses
$ARPTable = arp -a
# looping through IPs
for ($i = 1; $i -le 254; $i++) {

$IP = "192.168.1.$i"


if (Test-Connection -ComputerName $IP -Count 2 -Quiet -ErrorAction SilentlyContinue) {

# Try to resolve hostname, fallback to "Unknown"
try {

$hostname = ([System.Net.Dns]::GetHostEntry($IP)).HostName

} catch {

$hostname = "Unknown"

}

$ARPTable = arp -a

$MACLine = $ARPTable | Select-String $IP

if ($MACLine) {
    $Parts = $MACLine.ToString().Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)
    $MAC = $Parts[1]
} else {
    $MAC = "Unknown"
}

# printing info to the console
Write-Host "$IP - $($MAC) $hostname is ONLINE" -ForegroundColor Green
# logging output to a file
Add-Content -Path $logFile -Value "$IP - $($MAC) $hostname is ONLINE`n"
}
} 
# printing a friendly message to the console for a successful completed scan
Write-Host "`nScan complete." -ForegroundColor Cyan
}


function scan-services {
param ([string[]]$services)
# Default services if none are passed
if (-not $services) {
$services = "CryptSvc", "wuauserv", "bits", "WinRM"
}
$log = "$PSScriptRoot\service_log.txt"
$cryptsvclogs = "$PSScriptRoot\Cryptsvc_log.txt"
foreach ($svc in $services) {
$service = Get-Service -Name $svc -ErrorAction SilentlyContinue
# Service not found
if ($null -eq $service) {
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$LogEntry = "[$timestamp] | $svc | Not found"
Write-Host "$svc not found." -ForegroundColor Yellow
Add-Content -Path $cryptsvclogs -Value "$LogEntry`n"
continue
}
# SPECIAL HANDLING FOR CryptSvc
if ($svc -eq "CryptSvc") {
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$LogEntry = "[$timestamp] | $svc | $($service.Status)"
if ($service.Status -ne "Running") {
Write-Host "WARNING: CryptSvc is stopped. Manual intervention recommended." -ForegroundColor Red
} else {
Write-Host "CryptSvc is running" -ForegroundColor Green
}
Add-Content -Path $cryptsvclogs -Value "$LogEntry`n"
continue  # Skip normal restart for CryptSvc
}

# NORMAL SERVICES (auto restart)
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$LogEntry = "[$timestamp] | $svc | $($service.Status)"
if ($service.Status -ne "Running") {
try {
Restart-Service $svc -Force
Write-Host "$svc restarted successfully" -ForegroundColor Cyan
$LogEntry = "[$timestamp] | $svc | restarted"
} catch {
Write-Host "FAILED TO RESTART $svc" -ForegroundColor Red
$LogEntry = "[$timestamp] | $svc | FAILED to restart"
}
} else {
Write-Host "$svc is running" -ForegroundColor Green
}
# Log to main services log
Add-Content -Path $log -Value "$LogEntry`n"
}
}



function Scan-Events {
$Logfile = "$PSScriptRoot\WindowsEventLog.txt"
$Time = (Get-Date).AddDays(-1)

# Get events from last 24 hours with error handling
try {
$Events = Get-WinEvent -LogName System | Where-Object { $_.TimeCreated -ge $Time }

# Group events by level
$GroupedEvents = $Events | Group-Object LevelDisplayName

# Loop through each group and print counts
foreach ($item in $GroupedEvents) {
$timestamp = Get-Date
Write-Host "$($item.Name): $($item.Count)" -ForegroundColor Green
Add-Content -Path $Logfile -Value "[$timestamp] $($item.Name): $($item.Count)"
}
} catch {
Write-Host "FAILED to get event logs" -ForegroundColor Red
Add-Content -Path $Logfile -value "[$timestamp] FAILED to get event logs" 
}
Start-Sleep -Seconds 60
} 

function invoke-SystemInfo {
# assigning variables for Get-CimInstance to get Windows's operating system info and to get uptime
$os = Get-CimInstance Win32_OperatingSystem
$uptime = (get-date) - $os.LastBootUpTime

# Printing computer info with [PSCustomObject] for readability
[PSCustomObject]@{
ComputerName = $os.CSName
OS = $os.Caption
Version = $os.Version
# Formatting uptime as days and hours for quick readability
Uptime = "$($uptime.Days)d $($uptime.Hours)h"
} 
}
function Run-NetworkDiagnosis {
# defining targeted websites to diagnose and the router's IP and the ports
$log = "$PSScriptRoot/Network-Diagnosis_logs.txt"
$router = "192.168.1.1"
$targets = $router, "google.com", "youtube.com", "discord.com"

$ports = 80, 443, 22
# printing a friendly message to check the DNS
Write-Host "=== DNS CHECK ==="
# looping through the targeted websites and router
foreach ($target in $targets) {
# error handling in case it fails
try {
Resolve-DnsName $target -ErrorAction Stop | Out-Null
Write-Host "$target DNS OK"
}
catch {
Write-Host "ERROR: DNS failed for $target"
Write-Error "fix:
1. Check WiFi/Ethernet is connected
2. Restart router"
Add-Content -Path $log -Value "ERROR: DNS failed for $target
fix:
1. Check WiFi/Ethernet is connected
2. Restart router`n"
}
}
# printing a friendly message of the start of the ping checking
Write-Host "`n=== PING CHECK ==="
# looping through targeted websites and router
foreach ($target in $targets) {
$ping = Test-Connection $target -Count 2 -ErrorAction SilentlyContinue

if ($ping) {
$avg = ($ping | Measure-Object -Property ResponseTime -Average).Average
$avg = [math]::Round($avg)

Write-Host "$target average ping: $avg ms"
# conditional statements are added to see if the condition is true and the ping is slow
if ($avg -ge 50) {
Write-Host "WARNING: $target is slow"
Write-Error "Check router internet light
Move closer to router/use Ethernet
Restart router"
Add-Content -Path $log -Value "WARNING: $target is slow
1. Check router internet light
2. Move closer to router/use Ethernet
3. Restart router"
}
}
else {
Write-Host "ERROR: $target not reachable"
}
}
# printing a friendly message of the start of the ports check
Write-Host "`n=== PORT CHECK (ROUTER ONLY) ==="
# looping through ports
foreach ($port in $ports) {
# defining results to know the results of the check
$result = Test-NetConnection -ComputerName $router -Port $port -WarningAction SilentlyContinue
# conditional statements are added to know if the results are available
if ($result.TcpTestSucceeded) {
Write-Host "Router port $port OPEN"
}
else {
Write-Host "Router port $port CLOSED"
Write-Error "fix:
1. Try opening in browser:
http://192.168.1.1
https://192.168.1.1
If it doesn’t open:
2. make sure you're on the same WiFi network
restart router
check correct IP (run ipconfig → Default Gateway)
If still failing:
3. router may disable remote/admin access (normal in some setups)"
Add-Content -Path $log -Value "Router port $port CLOSED
fix:
1. Try opening in browser:
http://192.168.1.1
https://192.168.1.1
If it doesn’t open:
2. make sure you're on the same WiFi network
restart router
check correct IP (run ipconfig → Default Gateway)
If still failing:
3. router may disable remote/admin access (normal in some setups)"
}
}
}
