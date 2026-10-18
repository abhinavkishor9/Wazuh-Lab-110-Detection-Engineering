# Lab 110 — Investigation Timeline

## 1. Timeline Overview

This timeline records the key activities and observations during Wazuh detection engineering on October 18, 2026.

Times are shown in IST unless explicitly identified as UTC. Historical agent warnings are included separately because they occurred before the controlled test.

## 2. Investigation Timeline

| Time (IST) | Activity | Evidence / Result |
|---|---|---|
| Approximately 05:31–06:13 | Earlier Wazuh agent connectivity problems | Historical agent logs recorded connection errors. |
| 06:13:30 | Agent reconnected to the Wazuh manager | The agent log recorded a successful connection. |
| Approximately 06:13–06:15 | Agent buffer pressure and recovery | Buffer warnings were recorded, followed by recovery below the warning threshold. |
| 07:03:22 | Earlier controlled event recorded by the manager | The previous test marker appeared in `alerts.json` and was associated with rule `92052`. |
| 07:20:12 | Sysmon process-creation event observed | Event ID 1 recorded a PowerShell process launched through WMI. |
| 07:22:05 | New controlled Command Prompt test generated | PowerShell launched `cmd.exe` with marker `WazuhDFIRCapstone110-20261018-072205`. |
| 07:22:05 | Local Sysmon event recorded | Event ID 1, Record ID `1417150`, contained the test marker and process metadata. |
| 07:22:06.610 | Test event visible in Wazuh Discover | The event appeared in index `wazuh-alerts-4.x-2026.10.18`. |
| During troubleshooting | Wazuh agent health checked | `WazuhSvc` was running and the Sysmon Event Channel configuration was present. |
| During troubleshooting | Agent connection checked | TCP connection to `192.168.203.129:1514` was established. |
| During troubleshooting | Detection rule inspected | Rule `92052` was located in `0800-sysmon_id_1.xml`. |
| During troubleshooting | Indexer HTTPS endpoint tested | The unauthenticated request returned HTTP `401 Unauthorized`. |

## 3. Controlled Test Details

**Test marker:** `WazuhDFIRCapstone110-20261018-072205`

**Process:** `C:\Windows\System32\cmd.exe`

**Parent process:** PowerShell 7

**Sysmon Event ID:** `1`

**Sysmon Record ID:** `1417150`

**Detection rule:** `92052`

**Detection description:** Windows command prompt started by an abnormal process

**Detection level:** `4`

**Discover index:** `wazuh-alerts-4.x-2026.10.18`

## 4. Timeline Interpretation

The controlled event was generated locally and subsequently appeared in Wazuh Discover. The rule's conditions explain why the PowerShell-launched Command Prompt matched.

The earlier agent connectivity and buffer warnings are historical observations. The available evidence does not establish that they caused the controlled test to fail.

The HTTP 401 response occurred during a separate indexer connectivity check. It indicates that the request was not authenticated successfully; it does not establish an indexer outage.

## 5. Final Status

- [x] Sysmon process-creation telemetry validated.
- [x] Wazuh agent service checked.
- [x] Sysmon Event Channel configuration verified.
- [x] Controlled test event generated.
- [x] Local Sysmon event confirmed.
- [x] Detection rule `92052` inspected.
- [x] Controlled event found in Wazuh Discover.
- [x] Indexer endpoint reachability checked.
- [ ] Detection quality evaluated across multiple benign and suspicious scenarios.
- [ ] False-positive behavior measured.
- [ ] Any proposed detection changes tested and validated.

## 6. Conclusion

The controlled test successfully demonstrated event generation and visibility in Wazuh Discover.

The remaining work is to assess the detection's reliability across different process-launch scenarios and determine whether its logic accurately reflects the intended security behavior.
