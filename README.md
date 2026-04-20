# PowerShell Sysadmin Toolkit
A collection of Windows automation and network diagnostic scripts built to monitor system health, manage services, and scan networks — all with structured logging and error handling.

Built independently as a self-taught project to automate real sysadmin tasks.

---

## Scripts

### System Monitoring

**`System_Health_Script.ps1`**
All-in-one health check. Monitors CPU usage, RAM consumption, and disk space across all drives. Fires warnings when thresholds are exceeded and includes automatic log rotation to prevent log files from growing indefinitely.

**`system_info_script.ps1`**
Pulls system information (hostname, OS version, uptime) using WMI/CIM and formats it cleanly for quick readability.
kept private as it contains info of the device such as (device's ID)

**`Windows_Event_Logger.ps1`**
Queries Windows Event Logs from the last 24 hours, groups events by severity level, and logs counts to a timestamped file.

### Service Management

**`critical_service_restarter.ps1`**
Monitors critical Windows services and automatically restarts stopped ones. Includes special handling for CryptSvc — flags it for manual intervention instead of auto-restarting.


### Network & Security

**`cyber_toolkit.ps1`**
Port scanner and LAN scanner combined. Tests common ports against target domains and sweeps the local subnet for live devices, resolving hostnames and MAC addresses.
Kept private as it contains network-specific configuration (IPs, hostnames, MAC addresses).
Ports can be seen as they were posted in the screenshot in output-demo.png


---

## Features

- Timestamped logging to persistent log files
- Try/catch error handling throughout
- Log size protection and auto-trimming
- Color-coded console output
- Modular functions

---

## About

Self-taught. Built these tools to understand how Windows systems and networks actually work — not just how to click through GUIs. 
