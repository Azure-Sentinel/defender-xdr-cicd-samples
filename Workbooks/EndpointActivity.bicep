targetScope = 'managementGroup'
extension MicrosoftSecurity

var antivirusQuery = '''
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == 'AntivirusDetection'
| extend ThreatName = coalesce(tostring(parse_json(AdditionalFields).ThreatName), 'Unknown')
'''

resource workbook 'Microsoft.Security/workbooks@2026-06-01-preview' = {
  id: '05a7425a-fcda-5e24-823d-f8c9dd7a6215'
  name: 'Endpoint review - Activity'
  content: {
    version: 'Notebook/1.0'
    items: [
      {
        type: 1
        name: 'activity-guide'
        content: {
          json: '''
## What Endpoint evidence is available, and which antivirus findings need investigation?

Start with source availability for the last seven days. Record dates describe evidence, not ingestion arrival or sensor heartbeat. Zero records needs a data/access check; an unresolved table is a query error, not a healthy result.

Inventory shows each unmerged device's latest record within seven days. Unknown OS/client values remain visible. Missing or older devices are not counted; use the separate Sensor health workbook for latest-visible device exceptions.

Review antivirus findings by threat name, then inspect the device and file in Defender. Confirm detection/remediation details and related alerts. A detection does not prove an active infection. No detections does not establish antivirus health or complete protection, even when other device events exist.

Summary tables show at most 100 groups; evidence shows 200 events. Event totals are computed before display limits. Distinct-device counts are estimates. No hash-only origin joins or inferred removable-media claims are made.
'''
        }
      }
      {
        type: 3
        name: 'activity-availability'
        id: '05a7425a-fcda-5e24-823d-f8c9dd7a6216'
        content: {
          version: 'KqlItem/1.0'
          title: 'Source availability - last seven days'
          queryType: 'advancedHunting'
          visualization: 'table'
          size: 0
          timeContext: {
            durationMs: 604800000
          }
          query: '''
union
    (DeviceInfo | where Timestamp > ago(7d) | summarize Records = count(), LatestRecord = max(Timestamp) | extend Source = 'DeviceInfo'),
    (DeviceProcessEvents | where Timestamp > ago(7d) | summarize Records = count(), LatestRecord = max(Timestamp) | extend Source = 'DeviceProcessEvents'),
    (DeviceEvents | where Timestamp > ago(7d) | summarize Records = count(), LatestRecord = max(Timestamp) | extend Source = 'DeviceEvents')
| extend Evidence = iff(Records == 0, 'No visible records in seven days; check source data and access.', 'Recorded evidence is visible; review dates and scope.')
| project Source, Records, LatestRecord, Evidence
| order by Source asc
'''
        }
      }
      {
        type: 3
        name: 'activity-inventory'
        id: '05a7425a-fcda-5e24-823d-f8c9dd7a6217'
        content: {
          version: 'KqlItem/1.0'
          title: 'Latest observed OS and client versions - up to 100 groups'
          queryType: 'advancedHunting'
          visualization: 'table'
          size: 0
          timeContext: {
            durationMs: 604800000
          }
          query: '''
DeviceInfo
| where Timestamp > ago(7d)
| summarize arg_max(Timestamp, OSPlatform, ClientVersion, MergedToDeviceId) by DeviceId
| where isempty(MergedToDeviceId)
| extend OSPlatform = coalesce(OSPlatform, 'Unknown'), ClientVersion = coalesce(ClientVersion, 'Unknown')
| summarize Devices = count(), OldestDeviceRecord = min(Timestamp), LatestDeviceRecord = max(Timestamp) by OSPlatform, ClientVersion
| order by Devices desc, OSPlatform asc, ClientVersion asc
| take 100
'''
        }
      }
      {
        type: 3
        name: 'activity-antivirus-summary'
        id: '05a7425a-fcda-5e24-823d-f8c9dd7a6218'
        content: {
          version: 'KqlItem/1.0'
          title: 'Observed antivirus findings - up to 100 groups'
          queryType: 'advancedHunting'
          visualization: 'table'
          size: 0
          timeContext: {
            durationMs: 604800000
          }
          query: '${antivirusQuery}${'''
| summarize Events = count(), EstimatedDevices = dcount(DeviceId), FirstEvent = min(Timestamp), LatestEvent = max(Timestamp) by ThreatName
| order by Events desc, ThreatName asc
| take 100
'''}'
        }
      }
      {
        type: 3
        name: 'activity-antivirus-evidence'
        id: '05a7425a-fcda-5e24-823d-f8c9dd7a6219'
        content: {
          version: 'KqlItem/1.0'
          title: 'Recent antivirus evidence - up to 200 events'
          queryType: 'advancedHunting'
          visualization: 'table'
          size: 0
          timeContext: {
            durationMs: 604800000
          }
          query: '${antivirusQuery}${'''
| project Timestamp, DeviceId, ReportId, DeviceName, ActionType, ThreatName, FileName, FolderPath, SHA1, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountUpn
| order by Timestamp desc, DeviceId asc, ReportId desc
| take 200
'''}'
        }
      }
    ]
  }
}
