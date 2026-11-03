targetScope = 'managementGroup'
extension MicrosoftSecurity

resource detection 'Microsoft.Security/detectionRules@2026-06-01-preview' = {
  id: 'sample-powershell-process'
  displayName: 'CI/CD sample - PowerShell process'
  status: 'disabled'
  queryCondition: {
    queryText: '''
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName =~ 'powershell.exe'
| project Timestamp, DeviceId, ReportId, DeviceName, FileName, ProcessCommandLine
'''
  }
  schedule: {
    frequency: 'PT1H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'CI/CD sample - PowerShell process'
      description: 'Deployment sample only. Matches PowerShell process starts.'
      severity: 'low'
      tactics: [
        {
          tactic: 'Execution'
          techniques: [
            {
              technique: 'T1059'
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
