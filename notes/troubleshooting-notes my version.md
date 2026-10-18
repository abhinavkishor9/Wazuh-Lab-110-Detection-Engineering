# Troubleshooting Notes

## 1. Purpose

This document records troubleshooting performed while validating Sysmon process-creation telemetry and Wazuh detection rule `92052`.

The investigation checked endpoint telemetry, agent configuration, manager-side evidence, Discover visibility, and indexer reachability.

## 2. Windows Sysmon Validation

### Check performed

The Sysmon service was checked, and recent Event ID 1 records were queried.

### Result

Sysmon was running. The controlled test generated a process-creation event containing the unique marker:

`WazuhDFIRCapstone110-20261018-072205`

### Assessment

Local telemetry generation was confirmed for the controlled test.

If a future test does not appear locally, investigate Sysmon service health, the event channel, and the test command before troubleshooting Wazuh forwarding.

## 3. Wazuh Agent Validation

### Check performed

The agent service and its configuration were inspected. The agent's TCP connection to the manager was also checked.

### Result

- `WazuhSvc` was running.
- The agent configuration contained the Sysmon Operational Event Channel.
- The configured log format was `eventchannel`.
- The endpoint had an established TCP connection to `192.168.203.129:1514`.

### Assessment

The expected configuration and connectivity were present during the checks.

These checks do not prove that every event was collected without delay or loss. They establish the observed state at the time of testing.

## 4. Historical Connectivity and Buffer Warnings

Earlier agent logs showed connection failures, followed by successful reconnection and buffer warnings.

The logs included:

- Connection problems before approximately 06:13.
- A successful connection at approximately 06:13:30.
- A buffer usage warning around 90%.
- A subsequent buffer-full warning.
- A later message indicating that the buffer had recovered below the warning threshold.

### Assessment

These messages indicate earlier collection or forwarding pressure.

However, the controlled test was generated later, and its event was visible in Discover. The available evidence does not establish that the historical warnings caused the current test to fail.

Do not treat an earlier warning as the root cause of a separate symptom without correlating timestamps and event identifiers.

## 5. Detection Rule Inspection

### Check performed

The definition of rule `92052` was located using:

`/var/ossec/ruleset/rules/0800-sysmon_id_1.xml`

### Result

The rule requires a Sysmon process-creation event, an original filename matching `cmd.exe`, and a parent image that does not match `explorer.exe` or `cmd.exe`.

### Assessment

The test's parent process was PowerShell, so it satisfied the parent-image condition.

The match is consistent with the rule's conditions. It does not establish malicious intent.

Potential false positives should be assessed using representative benign administrative activity and carefully designed suspicious test cases.

## 6. Indexer Reachability Check

### Check performed

An HTTPS request was sent to the local Wazuh indexer using its configured CA certificate:

`https://127.0.0.1:9200`

### Result

The endpoint returned:

`HTTP status: 401`

The response body was:

`Unauthorized`

### Assessment

The endpoint was reachable, but the request was not authenticated successfully.

This result does not establish that the indexer is broken, nor does it verify that authenticated searches or indexing operations work.

No credentials should be added to command history or exposed in screenshots. Use the existing authorized configuration and an appropriate authenticated, read-only check if further indexer validation becomes necessary.

## 7. Manager Alert Search Pitfall

During troubleshooting, commands were run with placeholder or incomplete search strings, including:

`PASTE-YOUR-TEST-MARKER-HERE`

and a partial indexer URL.

Those searches did not reliably establish whether the controlled alert was absent from the manager's alert file.

A search should use the exact marker generated during the test, for example:

`WazuhDFIRCapstone110-20261018-072205`

Search results should be interpreted only after verifying that the command contains the intended marker and the correct file path.

## 8. Confirmed Discover Visibility

The controlled test event appeared in Wazuh Discover under:

`wazuh-alerts-4.x-2026.10.18`

The event contained the expected marker and process metadata.

### Assessment

For this test, the event was successfully available in Discover. Therefore, the earlier concern about a missing event was not reproduced by the captured result.

The HTTP 401 response from a separate unauthenticated indexer request should not be treated as evidence of an indexing failure.

