# Wazuh-Lab-110-Detection-Engineering
## Overview
Detection engineering is the process of designing, testing, validating, and improving security detection logic so that suspicious activities can be identified from available telemetry.
In this lab, the focus is on developing and validating a Wazuh detection for Windows process-creation activity collected through Sysmon.
The goal is not simply to generate an event and confirm that it appears in a dashboard. We need to understand what activity the detection is intended to identify, which event fields support the detection, how the rule behaves during testing, and whether its results are accurate.


This lab investigates Windows process-creation telemetry and validates how Wazuh detection rules identify activity recorded by Sysmon.

The investigation uses a controlled Command Prompt execution to trace an event from the Windows endpoint into Wazuh. It also examines the logic behind rule `92052`, evaluates the meaning of its alert, and documents the troubleshooting performed during validation.

The focus is detection engineering: understanding what a rule detects, why it triggers, whether its description accurately represents the evidence, and what limitations should be considered before treating an alert as suspicious.

## Objectives

- Analyze an offline packet capture with Zeek to identify and investigate DNS transactions.
- Validate packet capture contents and distinguish DNS traffic from unrelated protocols before beginning the investigation.
- Generate controlled DNS queries and capture network traffic using `dig` and `tcpdump`.
- Extract and interpret queried domain names, DNS query types, response codes, returned answers, timestamps, and connection identifiers from `dns.log`.
- Use `zeek-cut`, `sort`, and `uniq` to summarize DNS query frequencies, query types, and response-code distributions.
- Investigate Zeek's UDP checksum warning and compare standard analysis with checksum-tolerant processing using the `-C` option.
- Correlate DNS records with connection metadata to investigate endpoint attribution and the relationship between DNS transactions and network connections.
- Identify evidence limitations, distinguish observed behavior from suspicious patterns, and avoid unsupported conclusions about malicious activity.
- Document investigation findings, troubleshooting decisions, and outstanding questions in a structured SOC investigation report.
  
## Environment

- Endpoint: `DESKTOP-9MMM37V`
- Operating system: Windows 11 Pro
- Telemetry source: Microsoft Sysmon
- Sysmon channel: `Microsoft-Windows-Sysmon/Operational`
- Wazuh agent ID: `001`
- Wazuh agent service: `WazuhSvc`
- Wazuh manager: `192.168.203.129`
- Agent communication port: TCP `1514`
- Wazuh Discover data view: `wazuh-alerts-*`

## Lab Scenario

A Windows endpoint is monitored by Sysmon and a Wazuh agent to provide visibility into process-creation activity. During detection validation, a controlled test is performed by launching Command Prompt from PowerShell with a unique command-line marker.

The resulting Sysmon Event ID 1 record captures details such as the executable path, command line, parent process, user context, and file hashes. The event is then examined in Wazuh to determine how the detection logic evaluates the observed process relationship.

The investigation focuses on rule `92052`, which identifies Command Prompt executions whose parent process does not match the rule's exclusions for Explorer and Command Prompt. Because the test launches Command Prompt from PowerShell, it provides an opportunity to validate the rule's behavior under controlled conditions.

The investigation includes:
- Correlating the local Sysmon event with the alert visible in Wazuh Discover.
- Examining the rule conditions to understand why the event triggered the detection.
- Assessing whether the alert description accurately represents the observed behavior.
- Considering how legitimate administrative activity could satisfy the same conditions.
- Reviewing agent connectivity and indexer reachability without assuming that historical warnings caused the current result.

The objective is to determine whether the detection behaves as intended and whether its output is supported by the available evidence. The test is not intended to simulate a confirmed attack; instead, it provides a reproducible baseline for evaluating detection logic, identifying potential false positives, and planning further validation.

## Detection Logic

The inspected rule was defined in:

`/var/ossec/ruleset/rules/0800-sysmon_id_1.xml`

Its relevant conditions were:

- The event belongs to the `sysmon_event1` group.
- `win.eventdata.originalFileName` matches `cmd.exe`, case-insensitively.
- `win.eventdata.parentImage` must not match an image ending in `explorer.exe` or `cmd.exe`, case-insensitively.

The rule is configured at level 4 and maps the behavior to MITRE ATT&CK technique `T1059.003` — Windows Command Shell.

The controlled test was launched from PowerShell. This parent process satisfies the rule's exclusion condition because it is neither Explorer nor Command Prompt.

However, a PowerShell parent does not, by itself, establish malicious activity. The rule's description and potential false-positive behavior should therefore be evaluated in context.

## Key Findings

- Sysmon was running and generated the controlled process-creation event.
- The Wazuh agent service was running.
- The agent configuration included the Sysmon Operational Event Channel using the `eventchannel` format.
- The endpoint had an established TCP connection to the Wazuh manager on port `1514` during the baseline check.
- The test event was visible in Wazuh Discover.
- The event was associated with rule `92052`, level 4.
- The indexer HTTPS endpoint responded with HTTP `401 Unauthorized` to an unauthenticated request. This confirmed endpoint reachability but did not validate authenticated search or indexing operations.
- Earlier agent logs showed connectivity and buffer warnings. Their relationship to the current test was not established.

## Detection Assessment

The test demonstrates that a controlled Command Prompt launch from PowerShell can satisfy the conditions of rule `92052`.

It does not demonstrate that the activity is malicious. PowerShell is a legitimate administrative and automation tool, and a process launched from it may be benign.

The rule should be assessed against its intended detection objective, expected parent processes, operational environment, and likely false-positive scenarios before its conditions are changed.

