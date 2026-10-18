# Lab 110 — Detection Engineering

## Overview

This lab investigates Windows process-creation telemetry and validates how Wazuh detection rules identify activity recorded by Sysmon.

The investigation uses a controlled Command Prompt execution to trace an event from the Windows endpoint into Wazuh. It also examines the logic behind rule `92052`, evaluates the meaning of its alert, and documents the troubleshooting performed during validation.

The focus is detection engineering: understanding what a rule detects, why it triggers, whether its description accurately represents the evidence, and what limitations should be considered before treating an alert as suspicious.

## Objectives

- Validate Windows Sysmon process-creation telemetry.
- Confirm the Wazuh agent's Sysmon Event Channel configuration.
- Generate controlled activity with a unique investigation marker.
- Trace the resulting event through Wazuh.
- Inspect rule `92052` and understand its detection conditions.
- Evaluate the relationship between the parent process and the triggered alert.
- Verify alert visibility in Wazuh Discover.
- Document troubleshooting results and distinguish evidence from assumptions.

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

## Investigation Scenario

A controlled process-creation event was generated on the Windows endpoint using PowerShell to launch `cmd.exe`. The command included a unique marker:

`WazuhDFIRCapstone110-20261018-072205`

Sysmon recorded the event as Event ID 1. The event contained process metadata, command-line information, file hashes, user context, and parent-process details.

The corresponding event was visible in Wazuh Discover under the index:

`wazuh-alerts-4.x-2026.10.18`

The event was associated with rule `92052`, described as:

`Windows command prompt started by an abnormal process`

The rule's conditions and the observed parent process were examined to assess whether the alert was justified by the available evidence.

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

## Conclusion

Lab 110 demonstrates an evidence-based approach to detection engineering with Wazuh and Sysmon.

The investigation validates the controlled process-creation event and examines why rule `92052` triggered. It also highlights an important detection engineering principle: an alert identifies activity matching a rule, but its severity and description do not independently prove malicious intent.

Future refinement should be based on additional benign and suspicious test cases, measured false-positive behavior, and documented detection requirements.
