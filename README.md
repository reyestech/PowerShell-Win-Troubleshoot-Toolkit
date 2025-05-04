# PowerShell-Win-Troubleshoot-Toolkit

# 🛠️ Win‑Troubleshoot PowerShell Toolkit

Practical, **zero‑dependency** PowerShell scripts for Security Operations Center (SOC) analysts and Windows administrators.
Use them to **collect evidence**, **detect anomalies**, and **automate first‑response fixes**.

---

## 📁 Repository Layout

```text
win‑troubleshoot‑powershell/
├── README.md
└── Scripts/
    ├── Collect-EventLogs.ps1
    ├── Run-SFCandDISM.ps1
    ├── Get-ActiveConnections.ps1
    ├── Get-SystemHealthSnapshot.ps1
    ├── Detect-BruteForceLogons.ps1
    ├── Get-ListeningPorts.ps1
    ├── Audit-LocalAdminMembers.ps1
    ├── Invoke-WindowsDefenderScan.ps1
    ├── Test-NetworkConnectivity.ps1
    └── Export-WindowsFirewallRules.ps1
```

---

## 🚀 Quick Start

```powershell
# 1 – Clone the repo
git clone https://github.com/<you>/win‑troubleshoot‑powershell.git
cd win‑troubleshoot‑powershell\Scripts

# 2 – (Optional) allow local scripts to run for your user only
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

# 3 – Run any helper, e.g.:
./Collect-EventLogs.ps1 -HoursBack 12 -OutputDir 'D:\Logs'
```

---

## 1️⃣ Collect‑EventLogs.ps1

### Purpose

Gather Windows logs (System, Application, Security, etc.) from the last ***N* hours** and save them as CSV files—ideal for attaching to a help‑desk or DFIR ticket.

### How it works

* **`param(...)`** — supplies `HoursBack`, `Logs`, `OutputDir` at runtime.
* **`New‑Item -ItemType Directory`** — creates the output folder if missing.
* **`Get‑WinEvent -FilterHashtable`** — pulls logs by name and start time.
* **`Select TimeCreated, Id, LevelDisplayName, Message`** — keeps useful columns.
* **`Export‑Csv`** — writes `System.csv`, `Application.csv`, …

### Usage

```powershell
./Collect-EventLogs.ps1 -HoursBack 6 -Logs 'System','Security' -OutputDir 'C:\Temp\EventLogs'
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

## 2️⃣ Run‑SFCandDISM.ps1

### Purpose

One‑click **Windows file‑integrity repair**: runs `sfc /scannow` *and* `DISM /RestoreHealth`, logging the results.

### How it works

* **`sfc /scannow`** — scans & auto‑repairs system files.
* **`DISM /Online /Cleanup-Image /RestoreHealth`** — repairs the system image.
* **`Tee‑Object`** — captures console output to a log file.

### Usage

```powershell
./Run-SFCandDISM.ps1 -LogDir 'D:\HealthLogs'
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

## 3️⃣ Get‑ActiveConnections.ps1

### Purpose

Display every **established TCP session** with local/remote IP‑port, owning process, and user—great for spotting suspicious traffic.

### How it works

* **`Get‑NetTCPConnection -State Established`** — fetches live sessions.
* **`Get‑Process`** — resolves PID → process name.
* **`Win32_Process.GetOwner()`** — maps process to username.

### Usage

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

## 4️⃣ Get‑SystemHealthSnapshot.ps1

### Purpose

Capture a **single‑screen health summary**—CPU load, RAM use, free disk, pending updates.

### How it works

* **`Get‑Counter`** — samples CPU utilisation.
* **`Win32_OperatingSystem`** — returns memory stats.
* **`Get‑PSDrive`** — lists disks.
* **`PSWindowsUpdate`** — (if installed) counts pending updates.

### Usage

```powershell
./Get-SystemHealthSnapshot.ps1
```

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

## 5️⃣ Detect‑BruteForceLogons.ps1

### Purpose

Flag **failed‑logon storms** (Event ID 4625) that may indicate brute‑force attacks and export a CSV of offending IPs/users.

### How it works

* Reads the Security log for the last `HoursBack` hours.
* Extracts **Source IP** & **Account** via regex.
* Groups by IP+user and filters where attempts ≥ `Threshold`.

### Usage

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

## 6️⃣ Get‑ListeningPorts.ps1

### Purpose

List every **TCP/UDP port in LISTEN state** plus process and path—useful for hardening or catching rogue services.

### How it works

* Combines `Get‑NetTCPConnection` and `Get‑NetUDPEndpoint`.
* Resolves PID → process → file path.

### Usage

```powershell
./Get-ListeningPorts.ps1 | Out-GridView
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

## 7️⃣ Audit‑LocalAdminMembers.ps1

### Purpose

Dump **local Administrators group** membership and flag non‑default accounts.

### How it works

* Uses `Get‑LocalGroupMember` (Win10+).
* Compares against a list of expected defaults.

### Usage

```powershell
./Audit-LocalAdminMembers.ps1
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

## 8️⃣ Invoke‑WindowsDefenderScan.ps1

### Purpose

Kick off a **Quick or Full Microsoft Defender scan**, monitor progress, and print any threats found.

### How it works

* `Start‑MpScan` launches the scan.
* Polls `Get‑MpThreat` until the scan finishes.

### Usage

```powershell
./Invoke-WindowsDefenderScan.ps1 -ScanType Quick
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

## 9️⃣ Test‑NetworkConnectivity.ps1

### Purpose

Run **parallel ping + traceroute** to key hosts (gateway, DNS, or custom list) and show latency & hop count.

### How it works

* Reads hosts from parameter array or `targets.txt` file.
* Uses `Test‑Connection` and, for failures, `Test‑NetConnection -TraceRoute`.

### Usage

```powershell
./Test-NetworkConnectivity.ps1 -Targets '8.8.8.8','microsoft.com'
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

## 🔟 Export‑WindowsFirewallRules.ps1

### Purpose

Back up **all firewall rules** to a JSON file for version control or incident review.

### How it works

* Retrieves rules with `Get‑NetFirewallRule` + `Get‑NetFirewallPortFilter`.
* Serialises everything to human‑readable JSON.

### Usage

```powershell
./Export-WindowsFirewallRules.ps1 -OutFile '.irewall-backup.json'
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

Happy hunting 🔍 — feel free to open an issue or PR with new scripts!
