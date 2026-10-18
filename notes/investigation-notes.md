# Lab 110 — Investigation Notes

## 1. Investigation Summary

The investigation validated a controlled Windows process-creation event and examined how Wazuh rule `92052` evaluated the activity.

PowerShell launched `cmd.exe` with a unique test marker. Sysmon recorded the process creation, and the resulting event was visible in Wazuh Discover.

The investigation then examined the rule definition to understand why the event matched and whether the alert description was fully supported by the evidence.

## 2. Environment

- Endpoint: `DESKTOP-9MMM37V`
- Operating system: Windows 11 Pro
- Telemetry source: Sysmon
- Event channel: `Microsoft-Windows-Sysmon/Operational`
- Event ID: `1` — Process Create
- Wazuh agent ID: `001`
- Wazuh manager: `192.168.203.129`
- Detection rule: `92052`
- Detection level: `4`
- Discover index: `wazuh-alerts-4.x-2026.10.18`

## 3. Test Scenario

A controlled process-creation event was generated using PowerShell.

The test command launched:

`C:\Windows\System32\cmd.exe`

The command line contained the marker:

`WazuhDFIRCapstone110-20261018-072205`

The purpose of the marker was to identify the specific test event without confusing it with unrelated process activity.

## 4. Evidence Collected

### 4.1 Local Sysmon Event

The local Sysmon log contained the controlled process-creation event.

Observed details:

- Event ID: `1`
- Event Record ID: `1417150`
- Local event time: `2026-10-18 07:22:05`
- UTC event time: `2026-10-18 01:52:05.766`
- Process image: `C:\Windows\System32\cmd.exe`
- Process ID: `12500`
- Original filename: `Cmd.Exe`
- User: `DESKTOP-9MMM37V\Dell`
- Integrity level: `High`
- Parent image: PowerShell 7 executable
- Parent process ID: `28132`
- Command line contained the unique test marker.

The UTC timestamp in the event and the local timestamp displayed by Windows represent the same event.

### 4.2 Wazuh Agent

The Wazuh agent service was running.

The agent configuration contained an entry for:

`Microsoft-Windows-Sysmon/Operational`

The associated log format was:

`eventchannel`

The baseline network check showed an established connection from `192.168.203.1` to `192.168.203.129` on TCP port `1514`.

These observations support the expected collection configuration and connectivity at the time of the checks.

### 4.3 Wazuh Discover

The test event appeared in Wazuh Discover.

Observed details:

- Timestamp: `2026-10-18 07:22:06.610` as displayed
- Index: `wazuh-alerts-4.x-2026.10.18`
- Agent ID: `001`
- Agent name: `DESKTOP-9MMM37V`
- Agent IP: `192.168.203.1`
- Command line contained `WazuhDFIRCapstone110-20261018-072205`
- Process image: `C:\Windows\System32\cmd.exe`
- Company: Microsoft Corporation
- File version: `10.0.26100.9278`
- Integrity level: `High`

The indexed event confirms that the controlled activity was available for investigation in Discover.

### 4.4 Detection Rule

The inspected rule was located in:

`/var/ossec/ruleset/rules/0800-sysmon_id_1.xml`

Relevant definition:

- Rule ID: `92052`
- Level: `4`
- Description: `Windows command prompt started by an abnormal process`
- Parent group: `sysmon_event1`
- Original filename condition: case-insensitive match for `cmd.exe`
- Parent image condition: excludes parent images matching `explorer.exe` or `cmd.exe`
- MITRE ATT&CK mapping: `T1059.003`

The rule conditions explain why a Command Prompt process launched by PowerShell can match this rule.

## 5. Detection Analysis

### What the evidence supports

The evidence supports the following conclusions:

- Sysmon recorded the controlled process creation.
- The event included the expected marker and process metadata.
- The event was available in Wazuh Discover.
- The observed PowerShell parent process satisfies the rule's parent-image condition.
- The rule identifies a process relationship that may warrant review in the appropriate context.

### What the evidence does not establish

The evidence does not independently establish:

- That the PowerShell process was malicious.
- That the Command Prompt execution was unauthorized.
- That the event represented an attack.
- That every event matching rule `92052` is suspicious.
- That the rule has an acceptable false-positive rate across the wider environment.

### Detection quality consideration

The rule excludes Explorer and Command Prompt as parent images, but does not establish that every other parent process is abnormal.

PowerShell is a legitimate Windows administration tool. Therefore, a PowerShell-launched Command Prompt may be benign even when it satisfies the rule.

A detection description should communicate the behavior actually tested by the rule. Additional context or carefully validated conditions may be needed to improve detection precision.

## 6. Conclusion

The controlled event was generated, collected, and made visible in Wazuh Discover.

Rule `92052` matched the process-creation behavior. The next stage of detection engineering is to evaluate the rule against a broader set of legitimate and suspicious process-launch scenarios and assess whether its conditions provide useful detection value without excessive false positives.
