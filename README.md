# 🧪 Threat Detection & Incident Response Lab: PowerShell Suspicious Web Request via Invoke-WebRequest

This lab walks through the full lifecycle of a post-exploitation detection scenario where PowerShell is used to download a script from a remote location using `Invoke-WebRequest`. It demonstrates how to detect, investigate, and respond to such activity using Microsoft Defender for Endpoint (MDE), Microsoft Sentinel, and the NIST 800-61 Incident Response framework.

---

## 🎯 Objective

- Detect malicious or suspicious use of PowerShell for remote file download  
- Simulate the event on an MDE-onboarded system  
- Configure a detection rule in Microsoft Sentinel  
- Investigate the alert and associated artifacts  
- Execute containment, remediation, and post-incident actions  

---

## 🧰 Preparation 

Attackers frequently use legitimate system tools like PowerShell to carry out malicious activity once they have access to a host. A common tactic is to download scripts or binaries using commands such as `Invoke-WebRequest`, which blends in with normal administrative behavior. This is part of a broader technique known as **Living Off the Land Binaries (LOLBins)**, where attackers exploit built-in tools to avoid detection.

In this lab, we simulate such activity using a script named `eicar.ps1`—named after the harmless EICAR test file—to safely emulate malicious behavior. The activity will be detected using Microsoft Defender for Endpoint, which forwards telemetry to a Log Analytics workspace. Microsoft Sentinel consumes this data, allowing us to write detection rules and respond to suspicious activity through a centralized SIEM interface.

---

## 🛡️ **Create Alert Rule (PowerShell Suspicious Web Request)**

### 🔍 **Explanation**
Sometimes, malicious actors gain access to systems and attempt to download payloads or tools directly from the internet. This is often done using legitimate tools like PowerShell to blend in with normal activity. By using commands like `Invoke-WebRequest`, attackers can:

- 📥 Download files or scripts from external servers
- 🚀 Execute them immediately, bypassing traditional defenses
- 📡 Establish communication with Command-and-Control (C2) servers

Detecting such behavior is critical to identifying and disrupting an ongoing attack! 🕵️‍♀️

### **Detection Pipeline Overview**
1. 🖥️ Processes are logged via **Microsoft Defender for Endpoint** under the `DeviceProcessEvents` table.
2. 📊 Logs are forwarded to **Log Analytics Workspace** and integrated into **Microsoft Sentinel (SIEM)**.
3. 🛑 An alert rule is created in **Sentinel** to trigger when PowerShell downloads remote files.

---

### 🔧 **Steps to Create the Alert Rule**

#### 1️⃣ **Query Logs in Microsoft Defender**
1. Open **Microsoft EDR**.
2. Go to the KQL section and enter:
```kql
DeviceFileEvents
| top 20 by Timestamp desc
```
```kql
DeviceNetworkEvents
| top 20 by Timestamp desc
```
```kql
DeviceProcessEvents
| top 20 by Timestamp desc
```
3. Locate suspicious activity, e.g., `powershell.exe` executing `Invoke-WebRequest`.
4. Refine query for target device:
   ```kql
   let TargetDevice = "windows-target-1";
   DeviceProcessEvents
   | where DeviceName == TargetDevice
   | where FileName == "powershell.exe"
   | where ProcessCommandLine contains "Invoke-WebRequest"
   ```
![Screenshot 2025-01-07 105629](https://github.com/user-attachments/assets/418f503e-ebab-4cb4-9541-8c1c30ccc56a)

5. Verify payload detection. ✅
```kql
   let TargetHostname = "windows-target-1"; // Replace with the name of your VM as it shows up in the logs
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]); // Add the name of the scripts that were downloaded
DeviceProcessEvents
| where DeviceName == TargetHostname // Comment this line out for MORE results
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
| summarize Count = count() by AccountName, DeviceName, FileName, ProcessCommandLine
```

![Screenshot 2025-01-07 144444](https://github.com/user-attachments/assets/9520d3df-b646-4ce6-a72e-52e1eaedc3f4)


#### 2️⃣ **Create Alert Rule in Microsoft Sentinel**
1. Open **Sentinel** and navigate to:
   `Analytics → Scheduled Query Rule → Create Alert Rule`
2. Fill in the following details:
   - **Rule Name**: PowerShell Suspicious Web Request 🚩
   - **Description**: Detects PowerShell downloading remote files 📥.
   - **KQL Query**:
     ```kql
     let TargetDevice = "windows-target-1";
     DeviceProcessEvents
     | where DeviceName == TargetDevice
     | where FileName == "powershell.exe"
     | where ProcessCommandLine contains "Invoke-WebRequest"
     ```
   - **Run Frequency**: Every 4 hours 🕒
   - **Lookup Period**: Last 24 hours 📅
   - **Incident Behavior**: Automatically create incidents and group alerts into a single incident per 24 hours.
3. Configure **Entity Mappings**:
   - **Account**: `AccountName`
   - **Host**: `DeviceName`
   - **Process**: `ProcessCommandLine`
4. Enable **Mitre ATT&CK Framework Categories** (Use ChatGPT to assist! 🤖).
5. Save and activate the rule. 🎉

![Screenshot 2025-01-07 131945](https://github.com/user-attachments/assets/2cb640e9-9471-4439-a545-e3395bd2fd16)


---

## 🛠️ **Work the Incident**
Follow the **NIST 800-161: Incident Response Lifecycle**:

### 1️⃣ **Preparation** 📂
- Define roles, responsibilities, and procedures 🗂️.
- Ensure tools, systems, and training are in place 🛠️.

### 2️⃣ **Detection and Analysis** 🕵️‍♀️
1. **Validate Incident**:
   - Assign it to yourself and set the status to **Active** ✅.

![Screenshot 2025-01-07 135609](https://github.com/user-attachments/assets/f1c4ba25-0a90-4924-86b9-1e87f25031f6)

2. **Investigate**:
   - Review logs and entity mappings 🗒️.
   - Check PowerShell commands:
     ```plaintext
     powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri <URL> -OutFile <Path>
     ```
   - Identify downloaded scripts:
     - `portscan.ps1`
     - `pwncrypt.ps1`
     - `eicar.ps1`
     - `exfiltratedata.ps1`
3. Gather evidence:
   - Scripts downloaded and executed 🧪.
   - User admitted to downloading free software during the events.

### 3️⃣ **Containment, Eradication, and Recovery** 🛡️
1. Isolate affected systems:
   - Use **Defender for Endpoint** to isolate the machine 🔒.
   - Run anti-malware scans.
2. Analyze downloaded scripts:

3. Remove threats and restore systems:
   - Confirm scripts executed.
   - Clean up affected files and verify machine integrity 🧹.

### 4️⃣ **Post-Incident Activities** 📝
1. Document findings and lessons learned 🖊️.
   - Scripts executed: `pwncrypt.ps1` , `exfiltratedata.ps1` , `portscan.ps1` , `eicar.ps1` .
   - Account involved: `system-user`.
2. Update policies:
   - Restrict PowerShell usage 🚫.
   - Enhance cybersecurity training programs 📚.
3. Finalize reporting and close the case:
   - Mark incident as **True Positive** ✅. 

---

## 🎯 **Incident Summary**
| **Metric**                     | **Value**                        |
|---------------------------------|-----------------------------------|
| **Affected Device**            | `windows-target-1`               |
| **Suspicious Commands**        | 4                                |
| **Scripts Downloaded**         | `portscan.ps1`, `pwncrypt.ps1`, `eicar.ps1`, `exfiltratedata.ps1`   |
| **Incident Status**            | Resolved                         |

---

🎉 **Great Job Securing Your Environment!** 🔒
