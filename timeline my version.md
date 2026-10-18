#  Investigation Timeline

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
