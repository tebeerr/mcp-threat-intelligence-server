# Wazuh detection lab

The lab produces the real detections that `list_wazuh_alerts` and `analyze_alert` consume.
It is infrastructure, not code in this repository: build it once by following this guide.

## Topology

| VM | Role | Software |
| --- | --- | --- |
| `wazuh` | Manager, indexer, dashboard | Wazuh all-in-one |
| `win-lab-01` | Supervised Windows endpoint | Wazuh agent, Sysmon |
| `linux-lab-01` | Supervised Linux endpoint | Wazuh agent, auditd |

Use a host-only network with no route to the Internet. Only the machine running the MCP server
talks to external sources, and only with validated public IOCs. It reaches the indexer on the
host-only address, port 9200.

Take a snapshot of each VM once it is configured, so the lab can be reset.

## 1. Wazuh server

On the `wazuh` VM, run the all-in-one installer from the
[Wazuh quickstart](https://documentation.wazuh.com/current/quickstart.html), then enrol one agent
on each endpoint from the dashboard (*Agents > Deploy new agent*).

## 2. Windows endpoint: Sysmon

Install Sysmon with a community configuration, enabling SHA256 hashing (`<HashAlgorithms>`) and
network (event 3) and DNS (event 22) logging, which the IOC extraction reads:

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Forward its channel in `C:\Program Files (x86)\ossec-agent\ossec.conf`, then restart the agent:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

## 3. Linux endpoint: auditd

```bash
sudo apt install auditd
echo '-a exit,always -F arch=b64 -F euid>=1000 -S execve -k audit-wazuh-c' \
  | sudo tee /etc/audit/rules.d/wazuh.rules
sudo augenrules --load
```

Forward the log in `/var/ossec/etc/ossec.conf`, then restart `wazuh-agent`:

```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

## 4. Read-only account for the MCP server

Alerts are stored in the Wazuh indexer, not in the Wazuh server API on port 55000. The server calls
only `POST /wazuh-alerts-*/_search`, so give it an account that can do nothing else. From
*Indexer management > Dev Tools* on the dashboard, with a password of your own:

```
PUT _plugins/_security/api/roles/ti_mcp_reader
{ "index_permissions": [{ "index_patterns": ["wazuh-alerts-*"], "allowed_actions": ["read"] }] }

PUT _plugins/_security/api/internalusers/ti_reader
{ "password": "<strong-password>" }

PUT _plugins/_security/api/rolesmapping/ti_mcp_reader
{ "users": ["ti_reader"] }
```

Copy the indexer's root CA (`/etc/wazuh-indexer/certs/root-ca.pem`) to the MCP machine, then set:

```
WAZUH_INDEXER_URL=https://<wazuh-vm-ip>:9200
WAZUH_USERNAME=ti_reader
WAZUH_PASSWORD=<strong-password>
WAZUH_CA_BUNDLE=C:\path\to\root-ca.pem
```

The certificate must match the host in `WAZUH_INDEXER_URL`. TLS checks cannot be turned off.

Check the account from the MCP machine; the second command must answer 403:

```bash
curl --cacert root-ca.pem -u ti_reader "https://<wazuh-vm-ip>:9200/wazuh-alerts-*/_search?size=1"
curl --cacert root-ca.pem -u ti_reader -X DELETE "https://<wazuh-vm-ip>:9200/wazuh-alerts-*"
```

## 5. Test activity

Generate detections with harmless actions only; never run real malware. Because the lab has no
Internet route, connection attempts to public addresses fail but are still logged.

| Scenario | Action | Expected data |
| --- | --- | --- |
| Failed logins | Repeated wrong SSH passwords on `linux-lab-01` | `data.srcip` (lab IP: discarded) |
| File change | Drop a file in a directory watched by FIM | `syscheck.sha256_after` |
| Outbound attempt | `Test-NetConnection <public-ip>` on `win-lab-01` | `destinationIp` (Sysmon 3) |
| DNS query | `Resolve-DnsName <domain>` on `win-lab-01` | `queryName` (Sysmon 22) |
| Download command | `curl http://<domain>/x` run under audit | URL found in the log text |

The default ruleset does not raise an alert for every Sysmon event. If nothing appears, confirm the
event reached *Discover*, then add a local rule in `/var/ossec/etc/rules/local_rules.xml`.

## 6. Use it from Claude

Ask: *"List the Wazuh alerts of the last 24 hours at level 7 or above, then analyze the most severe
one."* Claude calls `list_wazuh_alerts`, then `analyze_alert`.
