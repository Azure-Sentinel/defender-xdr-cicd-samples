targetScope = 'managementGroup'
extension MicrosoftSecurity

resource detection 'Microsoft.Security/detectionRules@2026-06-01-preview' = {
  id: 'endpoint-review-inline-mshta-child-process'
  displayName: 'Endpoint review - Inline-script HTA child execution'
  status: 'disabled'
  queryCondition: {
    queryText: '''
DeviceProcessEvents
| where InitiatingProcessFileName =~ 'mshta.exe'
| where InitiatingProcessCommandLine contains '<script>'
| project Timestamp, DeviceId, ReportId, DeviceName, FileName, FolderPath, ProcessCommandLine, AccountDomain, AccountName, AccountSid, AccountUpn, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessAccountUpn, InitiatingProcessParentFileName
'''
  }
  schedule: {
    frequency: 'PT1H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'Endpoint review - Inline-script HTA child execution'
      description: 'A Windows process was launched by mshta.exe with an inline <script> marker in its command line. The event identifies the child process. HTA business software can match. Review the parent script, child command, account, downloads, and related alerts; this alone does not establish malicious activity.'
      severity: 'medium'
      tactics: [
        {
          tactic: 'DefenseEvasion'
          techniques: [
            {
              technique: 'T1218'
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
