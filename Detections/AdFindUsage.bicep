targetScope = 'managementGroup'
extension MicrosoftSecurity

resource detection 'Microsoft.Security/detectionRules@2026-06-01-preview' = {
  id: 'xdr-c63ae777-d5e0-4113-8c9a-c2c9d3d09fcd'
  displayName: 'Endpoint review - AdFind reconnaissance'
  status: 'disabled'
  queryCondition: {
    queryText: '''
DeviceProcessEvents
| where FileName =~ 'AdFind.exe'
| extend Arguments = parse_command_line(ProcessCommandLine, 'windows')
| mv-apply with_itemindex=ArgumentIndex Argument = Arguments to typeof(string) on (
    extend NextArgument = tostring(Arguments[ArgumentIndex + 1])
    | where (Argument =~ '-f' and isnotempty(NextArgument) and not(NextArgument startswith '-'))
        or (Argument =~ '-sc' and NextArgument in~ ('domainlist', 'dclist', 'trustdmp', 'adinfo'))
    | summarize MatchingOperations = count()
)
| where MatchingOperations > 0
| project Timestamp, DeviceId, ReportId, DeviceName, FileName, FolderPath, ProcessCommandLine, AccountName, AccountDomain, AccountSid, AccountUpn, InitiatingProcessFileName, InitiatingProcessCommandLine
'''
  }
  schedule: {
    frequency: 'PT1H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'Endpoint review - AdFind reconnaissance'
      description: 'AdFind was invoked with a directory-query filter or a selected directory shortcut. Administrators can use these commands legitimately. Verify the process account and authorization, inspect the command and ancestry, and review related device activity. This identifies an invocation, not successful discovery or malicious intent.'
      severity: 'medium'
      tactics: [
        {
          tactic: 'Discovery'
          techniques: [
            {
              technique: 'T1087'
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
