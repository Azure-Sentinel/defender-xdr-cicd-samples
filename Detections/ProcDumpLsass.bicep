targetScope = 'managementGroup'
extension MicrosoftSecurity

resource detection 'Microsoft.Security/detectionRules@2026-06-01-preview' = {
  id: 'endpoint-review-procdump-lsass'
  displayName: 'Endpoint review - ProcDump targeting LSASS'
  status: 'disabled'
  queryCondition: {
    queryText: '''
DeviceProcessEvents
| where FileName in~ ('procdump.exe', 'procdump64.exe')
| extend Arguments = parse_command_line(ProcessCommandLine, 'windows')
| mv-apply with_itemindex=ArgumentIndex Argument = Arguments to typeof(string) on (
    where ArgumentIndex > 0
    | where Argument !in~ ('-accepteula', '-ma', '-mm', '-mp', '-o', '-64')
    | summarize arg_min(ArgumentIndex, Argument)
)
| where Argument in~ ('lsass', 'lsass.exe')
| project Timestamp, DeviceId, ReportId, DeviceName, FileName, FolderPath, ProcessCommandLine, AccountDomain, AccountName, AccountSid, AccountUpn, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessAccountUpn, InitiatingProcessParentFileName
'''
  }
  schedule: {
    frequency: 'PT1H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'Endpoint review - ProcDump targeting LSASS'
      description: 'A Windows ProcDump invocation named LSASS as its target, optionally after -accepteula, -ma, -mm, -mp, -o or -64. Other option layouts, numeric process IDs and renamed tools are not covered. This is an investigation lead, not proof of a successful dump. Verify authorization, inspect file evidence and ancestry, and review related device alerts.'
      severity: 'high'
      tactics: [
        {
          tactic: 'CredentialAccess'
          techniques: [
            {
              technique: 'T1003'
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
