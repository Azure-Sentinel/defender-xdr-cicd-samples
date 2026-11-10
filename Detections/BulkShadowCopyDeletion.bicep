targetScope = 'managementGroup'
extension MicrosoftSecurity

resource detection 'Microsoft.Security/detectionRules@2026-06-01-preview' = {
  id: 'endpoint-review-bulk-shadow-copy-deletion'
  displayName: 'Endpoint review - Bulk shadow-copy deletion attempt'
  status: 'disabled'
  queryCondition: {
    queryText: '''
DeviceProcessEvents
| where FileName =~ 'vssadmin.exe'
| extend Arguments = parse_command_line(tolower(ProcessCommandLine), 'windows')
| where tostring(Arguments[1]) == 'delete' and tostring(Arguments[2]) == 'shadows'
| where set_has_element(Arguments, '/all') and set_has_element(Arguments, '/quiet')
| project Timestamp, DeviceId, ReportId, DeviceName, FileName, FolderPath, ProcessCommandLine, AccountDomain, AccountName, AccountSid, AccountUpn, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessAccountUpn, InitiatingProcessParentFileName
'''
  }
  schedule: {
    frequency: 'PT1H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'Endpoint review - Bulk shadow-copy deletion attempt'
      description: 'A Windows vssadmin process attempted to delete all shadow copies quietly. Legitimate backup maintenance can match. Verify authorization and backup activity, check whether deletion succeeded, and inspect process ancestry and related alerts. This does not confirm ransomware.'
      severity: 'high'
      tactics: [
        {
          tactic: 'Impact'
          techniques: [
            {
              technique: 'T1490'
            }
          ]
        }
      ]
      entityMappings: {
        hosts: [
          {
            id: 'device'
            deviceIdColumn: 'DeviceId'
          }
        ]
      }
    }
  }
}
