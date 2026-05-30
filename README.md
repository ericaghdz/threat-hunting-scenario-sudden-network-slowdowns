# Threat Hunt Investigation: Network Performance Degradation & Unauthorized Port Scanning

---

## Scenario

A threat hunt was initiated following reports of significant network performance degradation. Distributed Denial-of-Service (DDoS) activity was ruled out, leading to the hypothesis that a host within the environment may have been engaging in excessive downloads or unauthorized network scanning.

---

## Tools & Technologies Utilized

- Microsoft Defender for Endpoint (MDE) / Endpoint Detection & Response (EDR)
- Kusto Query Language (KQL)
- MITRE ATT&CK Framework

---

## Step 1: Identify Abnormal Failed Network Connections

The initial phase of the investigation focused on identifying hosts generating an abnormal number of failed network connections.

The following KQL query was used to count failed connection attempts by local IP address:

```kql
// Query to identify excessive failed connections by local IP
let honeypot = "windows-target-";
DeviceNetworkEvents
| where DeviceName == honeypot
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount desc
```
> **Important Note:** Microsoft Defender truncates `DeviceName` values after 15 characters. Due to this limitation, the queries I used targeted `windows-target-` rather than the full hostname `windows-target-1`.

### Findings

<img width="850" alt="image" src="Screenshot 2026-05-29 185556.png">

The query identified **1,799 failed connection attempts** associated with the local IP address:

`10.0.0.155`

This volume of failed connections was considered anomalous and warranted further investigation.

---

## Step 2: Analyze Recent Failed Connection Activity

To better understand the failed connection behavior, additional telemetry was collected for the suspicious IP address.

The following query was used:

```kql
// Query to observe detailed failed connection events
let honeypot = "windows-target-";
let IPinQuestion = "10.0.0.155";
DeviceNetworkEvents
| where DeviceName == honeypot
| where ActionType == "ConnectionFailed"
| where LocalIP == IPinQuestion
| order by Timestamp desc
```

### Findings

Analysis of the failed connections revealed a large number of **sequential connection attempts across numerous uncommon destination ports in rapid succession**.

<img width="850" alt="image" src="Screenshot 2026-05-29 210809.png">

This behavior is highly suspicious and aligns with indicators commonly associated with **unauthorized port scanning activity**. Legitimate services generally communicate using predictable, consistent ports, whereas the observed activity demonstrated broad and rapid probing behavior.

**Key indicators observed:**

- Sequential destination port enumeration
- High frequency of failed connection attempts
- Numerous uncommon destination ports targeted
- Rapid succession of connection failures

### Assessment

The observed network behavior was assessed as a likely **unauthorized internal port scan**, contributing to the reported network slowdown.

---

## Step 3: Identify the Initiating Process

Following confirmation of suspicious network behavior, the investigation shifted toward identifying the process responsible for initiating the activity.

An initial query was executed to review process creation events within a **10-minute window** surrounding the estimated start time of the port scan.

```kql
// Search for the initiating process of the port scan
let honeypot = "windows-target-";
let specificTime = datetime(2026-05-28T20:53:53.5185177Z);
DeviceProcessEvents
| where DeviceName == honeypot
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```

### Findings

No suspicious process activity was identified within the initial timeframe.

The query window was expanded to **20 minutes before and after** the event to broaden visibility.

```kql
// Expanded timeframe to identify initiating process
let honeypot = "windows-target-";
let specificTime = datetime(2026-05-28T20:53:53.5185177Z);
DeviceProcessEvents
| where DeviceName == honeypot
| where Timestamp between ((specificTime - 20m) .. (specificTime + 20m))
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```

### Findings

<img width="850" alt="image" src="Screenshot 2026-05-29 214632.png">

The expanded search identified a suspicious PowerShell execution event:

```text
powershell.exe
cmd.exe /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1
```

The script `portscan.ps1` was executed at:

`2026-05-28T20:36:59.3858182Z`

To determine the account responsible for launching the script, the query was updated to include account attribution:

```kql
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName
```

### Findings

<img width="850" alt="image" src="Screenshot 2026-05-29 220055.png">

The script execution was attributed to the:

`SYSTEM`

account.

This activity was determined to be suspicious due to:

1. Unauthorized port scanning behavior
2. Execution under the highly privileged `SYSTEM` account
3. No evidence of administrator-initiated activity
4. Use of `-ExecutionPolicy Bypass`, which may indicate attempts to bypass security restrictions

---

## Containment & Response

The affected host, **`windows-target-1`**, was immediately isolated to prevent further activity.

A malware scan was performed; however, no malicious artifacts were identified during initial analysis.

Due to the suspicious behavior observed, the system remained isolated and an escalation ticket was created for further investigation and remediation.

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Relevance |
|---------|--------------|----------------|------------|
| Discovery | T1046 | Network Service Scanning | Sequential connection attempts across numerous ports strongly indicate port scanning activity used to identify open services. |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | A PowerShell script (`portscan.ps1`) was executed using `powershell.exe`, indicating script-based execution. |
| Defense Evasion | T1059.001 | Command and Scripting Interpreter: PowerShell | The `-ExecutionPolicy Bypass` argument suggests an attempt to circumvent PowerShell execution restrictions. |
| Privilege Escalation | T1548 *(Possible)* | Abuse Elevation Control Mechanism | Execution under the `SYSTEM` account indicates elevated privileges enabling broad host/network access. |

---

## Outcome

The investigation concluded that an **unauthorized internal port scan** was the most likely cause of the observed network degradation.

Evidence indicated that a PowerShell-based scanning script (`portscan.ps1`) executed under the `SYSTEM` account initiated repeated failed network connection attempts across numerous ports, consistent with reconnaissance activity.

The device remained isolated pending further investigation and remediation.
