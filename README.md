![image](https://github.com/user-attachments/assets/d3ddf94c-e630-4c1c-bab6-4cdf16f72470)

# PowerShell-Win-Troubleshoot-Toolkit

Modern cybersecurity relies on three essential components: speed, visibility, and automation. This repository provides ready-to-execute PowerShell utilities that equip Security Operations Centers (SOCs) and Windows administrators with immediate capabilities: rapidly collecting evidence, promptly identifying anomalies, and initiating trusted remediation workflows without installing third-party dependencies.

This resource benefits junior computer science students seeking to practice blue-team fundamentals and troubleshoot technical issues, as well as experienced responders who require lightweight tools during incident bridge calls. Each script is thoroughly commented, parameter-driven, and designed for production safety, enabling users to implement them confidently.

<details>
  <summary><strong>📚 Table of Contents: Click to drop-down</strong></summary>
</p>
  
[Guide](#guide)  </p>
[Script-Catalogue](#script-catalogue)
1. [EventLogs](#eventlogs)
2. [SFC-and-DISM](#sfc-and-dism)
3. [Connections](#connections)
4. [System-Snapshot](#system-snapshot)
5. [Detect](#detect)
6. [Listening-Ports](#listening-ports)
7. [Audit](#audit)
8. [Defender-Scan](#defender-scan)
9. [Network](#network)
10. [FirewallRules](#firewallrules)  </p>

[Conclusion](#conclusion)

</details>


---

## Guide
### 📚 Quick‑Start-Guide

1. **Clone the repository** – Fetches the toolkit to your workstation so you can inspect or modify the scripts locally.

   ```powershell
   git clone https://github.com/<you>/win‑troubleshoot‑powershell.git
   cd win‑troubleshoot‑powershell\Scripts
   ```
2. **Unblock local execution** – Windows protects you from running unsigned code. Setting the policy **only for your user** keeps the OS secure while allowing these scripts to run:

   ```powershell
   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
   ```
3. **Run any helper** – Each script is self‑contained. For example, export the last 12 hours of System & Security logs to `D:\Logs`:

   ```powershell
   ./Collect-EventLogs.ps1 -HoursBack 12 -Logs 'System','Security' -OutputDir 'D:\Logs'
   ```
4. **Review the output** – Most scripts write either a table to the screen or an artefact (CSV / JSON / TXT) you can attach to a ticket or drop into a SIEM pipeline.

> *Tip:* All parameters have sensible defaults; launch a script with `-Help` to see them.

---

![Animated_example_demonstrating_use_of_snippet_in_PowerShell_ISE](https://github.com/user-attachments/assets/e554b1ee-1255-4947-8e5f-78bd072df777)


## Script-Catalogue

## EventLogs
### 1️⃣ Collect‑EventLogs

When incidents occur, the first question is, *“What happened, and when?”* This script automates forensic evidence collection by exporting Windows Event Logs for any specified time window. Instead of manually navigating through Event Viewer and saving EVTX files, you will receive organized CSV files that can be easily imported into Excel, Log Parser, or your SIEM for timeline analysis.
 
**How it works**

> * Accepts **`HoursBack`**, **`Logs`** (array of log names), and **`OutputDir`**.
> * Creates the destination folder if it doesn’t exist.
> * Uses **`Get‑WinEvent`** with a hashtable filter for efficiency (no slow `Where‑Object`).
> * Selects the most actionable fields (timestamp, event ID, severity, message).
> * Exports each log type to its own CSV for clean segregation.

**Usage Example**

```powershell
./Collect-EventLogs.ps1 -HoursBack 24 -Logs 'System','Application' -OutputDir 'C:\IR\Logs'
```

### Code

```powershell
param(
    [int]      $HoursBack = 24,
    [string[]] $Logs      = @('System','Application','Security'),
    [string]   $OutputDir = (Join-Path $PWD 'EventLogs')
)
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}
$start = (Get-Date).AddHours(-$HoursBack)

foreach ($log in $Logs) {
    Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $start } |
        Select TimeCreated, Id, LevelDisplayName, Message |
        Export-Csv -NoTypeInformation -Path (Join-Path $OutputDir "$log.csv")
}
Write-Host "✔ Logs exported to $OutputDir"
```

---

## SFC-and-DISM
### 2️⃣ Run SFC and DISM Scans

System file corruption poses a significant risk to system reliability. This script effectively integrates two native Microsoft repair tools: System File Checker (SFC) and Deployment Image Servicing and Management (DISM). It captures their combined output in a timestamped log, which enhances the ability to conduct post-compromise integrity checks and assist in troubleshooting unexplained operating system errors. This approach ensures a thorough and systematic evaluation of the system's integrity.

**How it works**

> * Builds a log directory on‑the‑fly to preserve historical runs.
> * Executes `sfc /scannow` to repair active system files.
> * Follows up with `DISM /RestoreHealth` to patch the underlying Windows image.
> * Pipes all console output through **`Tee‑Object`** so you see progress live *and* keep a text record.

**Usage Example**

```powershell
./Run-SFCandDISM.ps1 -LogDir 'D:\HealthChecks'
```


### Code

```powershell
param([string]$LogDir = (Join-Path $PWD 'HealthChecks'))
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir | Out-Null
}
$log = Join-Path $LogDir ("HealthCheck_{0:yyyyMMdd_HHmm}.txt" -f (Get-Date))

"=== SFC ==="  | Tee-Object $log
sfc /scannow   | Tee-Object $log -Append
"=== DISM ===" | Tee-Object $log -Append
DISM /Online /Cleanup-Image /RestoreHealth | Tee-Object $log -Append

Write-Host "✔ Repair complete – see $log"
```

---

## Connections
### 3️⃣ Get‑ActiveConnections

## Conclusion-Ex

Malware often hides by attaching itself in plain sight and piggybacking on legitimate processes. This script displays all established outbound TCP connections, identifying each with the corresponding process name and the user who initiated it. This allows analysts to identify unauthorized beacons or channels used for data exfiltration quickly.

**How it works**

> * Queries `Get‑NetTCPConnection` for **`State = Established`**.
> * Resolves Process ID to friendly names using `Get‑Process`.
> * Retrieves the owning username via CIM’s `Win32_Process.GetOwner()`.
> * Outputs an alphabetised table ready for copy‑paste into a report or pasted into Grid View.

**Usage Example**

```powershell
./Get-ActiveConnections.ps1 | Out-GridView
```


### Code

```powershell
Get-NetTCPConnection -State Established | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    $user = (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.OwningProcess)").GetOwner().User
    [pscustomobject]@{
        Local   = "$($_.LocalAddress):$($_.LocalPort)"
        Remote  = "$($_.RemoteAddress):$($_.RemotePort)"
        State   = $_.State
        Process = $proc.ProcessName
        User    = $user
    }
} | Sort Remote | Format-Table -AutoSize
```

---

## System-Snapshot
## 4️⃣ Get‑SystemHealthSnapshot

Prior to initiating troubleshooting efforts, it is essential to establish a baseline. This script captures **real-time CPU load**, **memory usage**, **available disk space**, and **the count of pending Windows updates**—all in a single execution. It is advisable to run this script at both the commencement and conclusion of a support ticket to effectively demonstrate the impact of your remediation actions.

**How it works**

> * Samples CPU with `Get‑Counter '\Processor(_Total)\% Processor Time'` (three 1‑second polls averaged).
> * Pulls memory stats from `Win32_OperatingSystem`, converting KB to GB for human readability.
> * Enumerates drives via `Get‑PSDrive -PSProvider FileSystem`, rounding free space.
> * If the **PSWindowsUpdate** module exists, `Get‑WindowsUpdate` counts pending patches; otherwise, it skips silently.
> * Outputs everything as a tidy formatted list — perfect for screenshots or copy‑paste into an incident timeline.

**Usage Example**

```powershell
./Get-SystemHealthSnapshot.ps1 | Tee-Object '.\health-before.txt'
```

*(Run it again after fixes and `Compare-Object` the two logs to quantify improvement.)*

---

### Code

```powershell
$cpu = (Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 3).CounterSamples.CookedValue |
        Measure-Object -Average | Select-Object -ExpandProperty Average
$mem = Get-CimInstance Win32_OperatingSystem
$disk = Get-PSDrive -PSProvider FileSystem | Select Name,@{n='Free(GB)';e={[math]::Round($_.Free/1GB,1)}}

[pscustomobject]@{
    Timestamp       = Get-Date
    CPU_Load_Percent= [math]::Round($cpu,1)
    RAM_Used_GB     = [math]::Round(($mem.TotalVisibleMemorySize-$mem.FreePhysicalMemory)/1MB,2)
    Pending_Updates = (Get-WindowsUpdate -MicrosoftUpdate -IgnoreReboot -ErrorAction SilentlyContinue).Count
    Disk_Free       = ($disk | Out-String).Trim()
} | Format-List
```
---

## Detect
### 5️⃣ Detect‑BruteForceLogons

An increase in failed login attempts is a recognized indicator of a potential security breach. This script analyzes Security Event ID 4625 over the past *N* hours, aggregates the data by **Source IP and Account**, and identifies any entities that surpass a predefined threshold. It is particularly effective for alerting security teams through platforms such as Microsoft Sentinel, Splunk, or via email notifications.

**How it works**

> * Queries the Security log via `Get‑WinEvent` using a precise hashtable filter (fast!).
> * Pulls **Source Network Address** and **Account Name** via lightweight regex.
> * Groups results and filters where attempts ≥ `Threshold`.
> * Exports a CSV so you can pivot or join against threat‑intel feeds.

**Usage Example**

```powershell
./Detect-BruteForceLogons.ps1 -HoursBack 12 -Threshold 15 -Report '.\bruteforce.csv'
```
### Code

```powershell
param(
  [int]$HoursBack = 24,
  [int]$Threshold = 10,
  [string]$Report = (Join-Path $PWD 'BruteForceReport.csv')
)
$start = (Get-Date).AddHours(-$HoursBack)
$events = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625; StartTime=$start }

$patternIP      = '(?<=Source Network Address:\s+)(\d{1,3}(?:\.\d{1,3}){3})'
$patternAccount = '(?<=Account Name:\s+)(\S+)'

$data = $events | ForEach-Object {
    $ip  = [regex]::Match($_.Message, $patternIP).Value
    $acc = [regex]::Match($_.Message, $patternAccount).Value
    if ($ip) { [pscustomobject]@{ IP=$ip; Account=$acc } }
} | Group-Object IP,Account | Where-Object Count -ge $Threshold |
    Select-Object @{n='IP';       e={$_.Name.Split(',')[0]}},
                  @{n='Account';  e={$_.Name.Split(',')[1]}},
                  @{n='Attempts'; e={$_.Count}}

$data | Export-Csv -NoTypeInformation -Path $Report
Write-Host "✔ Report written to $Report"
```

---

## Listening-Ports
### 6️⃣ Get‑ListeningPorts

Understanding what *listening* is on your network is as important as knowing what *talking is. This utility lists all TCP and UDP ports in the LISTEN state, connects each port to its corresponding process, and displays the executable path. It's a fast way to identify shadow IT or services initiated by malware.

**How it works**

> * Combines `Get‑NetTCPConnection -State Listen` and `Get‑NetUDPEndpoint` results.
> * Resolves `OwningProcess` to process name & binary path via `Get‑Process`.
> * Outputs a sortable table you can ship to CSV or Grid View.

**Usage Example**

```powershell
./Get-ListeningPorts.ps1 | Export-Csv '.\listening.csv' -NoTypeInformation
```
### Code

```powershell
$tcp = Get-NetTCPConnection -State Listen
$udp = Get-NetUDPEndpoint
($tcp + $udp) | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [pscustomobject]@{
        Protocol = $_.GetType().Name -replace 'Net','' -replace 'Endpoint',''
        Local    = "$($_.LocalAddress):$($_.LocalPort)"
        PID      = $_.OwningProcess
        Process  = $proc.ProcessName
        Path     = $proc.Path
    }
} | Sort-Object Local | Format-Table -AutoSize
```

---

## Audit
### 7️⃣ Audit‑LocalAdminMembers

Local administrator sprawl presents significant opportunities for lateral movement by attackers. This script systematically enumerates the local Administrators group, differentiates between default and non-default accounts, and identifies any unexpected discrepancies. Doing so enables organizations to reinforce privilege boundaries prior to potential exploitation by malicious actors.

**How it works**

> * Calls `Get‑LocalGroupMember -Group 'Administrators'` (Windows 10/11 & Server 2016+).
> * Compares against a hard‑coded safe list (`Administrator`, `Domain Admins`, etc.).
> * Prints a flag (⚠ Review) next to unknown members.

**Usage Example**

```powershell
./Audit-LocalAdminMembers.ps1 | Out-File '.\admin-audit.txt'
```

### Code

```powershell
$default = 'Administrator','Domain Admins','SYSTEM','Administrators'
Get-LocalGroupMember -Group 'Administrators' | ForEach-Object {
    [pscustomobject]@{
        Member = $_.Name
        Type   = $_.ObjectClass
        Note   = if ($default -contains $_.Name) { 'Default' } else { '⚠ Review' }
    }
} | Format-Table -AutoSize
```

---

## Defender-Scan
### 8️⃣ Invoke‑WindowsDefenderScan

During incident response, an immediate antivirus scan is often necessary without navigating through the graphical user interface (GUI). This utility facilitates the initiation of either a **Quick** or **Full** Microsoft Defender scan, monitors its completion, and presents any identified findings. This functionality allows for the effective escalation of issues or their resolution with confidence.

**How it works**

> * Starts the scan with `Start‑MpScan`.
> * Polls `Get‑MpComputerStatus` until scan flags clear.
> * Pulls threat objects from `Get‑MpThreat` and prints a table if any are found.

**Usage Example**

```powershell
./Invoke-WindowsDefenderScan.ps1 -ScanType Full
```

### Code

```powershell
param([ValidateSet('Quick','Full')][string]$ScanType='Quick')
Start-MpScan -ScanType $ScanType
Write-Host "Scanning ($ScanType)…"
while ((Get-MpComputerStatus).PerformingQuickScan -or (Get-MpComputerStatus).PerformingFullScan) {
    Start-Sleep 5
}
$threats = Get-MpThreat
if ($threats) {
    $threats | Format-Table
} else {
    Write-Host "✔ No threats detected."
}
```

---
 
## Network
## 9️⃣ Test‑NetworkConnectivity

Is the issue related to the host, the network, or the destination? This script concurrently assesses the reachability of critical hosts, including gateways, DNS servers, and SaaS endpoints, by integrating both ping latency and traceroute hop count. This approach provides a clear overview of system health, enabling efficient escalation to NetOps when necessary.

**How it works**

> * Reads targets from `-Targets` parameter or `targets.txt` if present.
> * Uses `Test‑Connection` for fast latency sampling.
> * Falls back to `Test‑NetConnection -TraceRoute` when ping fails, capturing hop length.
> * Outputs a mini‑dashboard table (Reachable ✔ / ✖, Avg RTT, Hops).

**Usage Example**

```powershell
./Test-NetworkConnectivity.ps1 -Targets '8.8.8.8','1.1.1.1','microsoft.com'
```
### Code

```powershell
param([string[]]$Targets = (Test-Path './targets.txt') ? (Get-Content './targets.txt') : @('8.8.8.8'))
$results = foreach ($t in $Targets) {
    if (Test-Connection -Quiet -Count 4 -ComputerName $t) {
        $avg = (Test-Connection -Count 4 $t | Measure-Object -Property ResponseTime -Average).Average
        [pscustomobject]@{ Target=$t; Reachable=$true; AvgRTT_ms=[math]::Round($avg,1); Hops='—' }
    } else {
        $hops = (Test-NetConnection $t -TraceRoute).TraceRoute.Length
        [pscustomobject]@{ Target=$t; Reachable=$false; AvgRTT_ms='—'; Hops=$hops }
    }
}
$results | Format-Table -AutoSize
```

---

## FirewallRules
### 🔟 Export‑WindowsFirewallRules

Firewalls drift over time. This exporter systematically converts all Windows Firewall rules into a structured JSON format. This transformation facilitates the comparison of baselines, enables integration with Git, and allows for seamless sharing with auditors. It is advisable to utilize this tool before and after policy changes to demonstrate effective compliance with the principle of least privilege.

**How it works**

> * Loops through `Get‑NetFirewallRule`, enriching with port filters via `Get‑NetFirewallPortFilter`.
> * Builds a PSCustomObject with key rule properties (Name, Direction, Action, Profile, Program, Ports).
> * Serialises the array to prettified JSON (UTF‑8) for cross‑platform parsing.

**Usage Example**

```powershell
./Export-WindowsFirewallRules.ps1 -OutFile '.\firewall-backup.json'
```
### Code

```powershell
param([string]$OutFile = (Join-Path $PWD 'FirewallRules.json'))

$rules = Get-NetFirewallRule | ForEach-Object {
    $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_ -ErrorAction SilentlyContinue
    [pscustomobject]@{
        Name      = $_.Name
        Direction = $_.Direction
        Action    = $_.Action
        Profile   = $_.Profile
        Enabled   = $_.Enabled
        Program   = $_.ApplicationName
        Service   = $_.ServiceName
        Protocol  = $port.Protocol
        LocalPort = $port.LocalPort
        RemotePort= $port.RemotePort
    }
}

$rules | ConvertTo-Json -Depth 4 | Out-File -FilePath $OutFile -Encoding utf8
Write-Host "✔ Firewall rules exported to $OutFile"
```

---

## Conclusion

This toolkit showcases practical PowerShell scripts. With these new skills, you will be equipped to integrate with enterprise SIEMs like Microsoft Sentinel or Splunk. Each script is thoroughly documented and demonstrates how adopting an automation mindset can help cybersecurity and IT professionals work faster and more effectively—a core competency for modern Cybersecurity Analysts. Engineers are encouraged to clone, fork, or submit a pull request; after all, security is a team sport!


> **Next Steps:** Star ⭐ the repo if you find it useful, or raise an issue if you’d like new features. Happy hunting — and automate *all* the things! 🔍

🔍 — Happy hunting and automate *all* the things! 
