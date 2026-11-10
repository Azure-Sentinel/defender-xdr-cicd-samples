targetScope = 'managementGroup'
extension MicrosoftSecurity

resource detection 'Microsoft.Security/detectionRules@2026-06-01-preview' = {
  id: 'endpoint-review-event-log-clearing-burst'
  displayName: 'Endpoint review - Event-log clearing burst'
  status: 'disabled'
  queryCondition: {
    queryText: '''
DeviceProcessEvents
| where FileName =~ 'wevtutil.exe'
| extend Arguments = parse_command_line(ProcessCommandLine, 'windows')
| where tostring(Arguments[1]) =~ 'cl'
| summarize DistinctCommandCount = count_distinct(ProcessCommandLine), CommandEvidence = make_set(ProcessCommandLine, 20), arg_max(Timestamp, ReportId, DeviceName, FileName, FolderPath, ProcessCommandLine, AccountDomain, AccountName, AccountSid, AccountUpn, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessAccountUpn, InitiatingProcessParentFileName) by DeviceId, WindowStart = bin(Timestamp, 5m)
| where DistinctCommandCount > 10
| project Timestamp, DeviceId, ReportId, DeviceName, WindowStart, DistinctCommandCount, CommandEvidence, FileName, FolderPath, ProcessCommandLine, AccountDomain, AccountName, AccountSid, AccountUpn, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessAccountUpn, InitiatingProcessParentFileName
'''
  }
  schedule: {
    frequency: 'PT1H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'Endpoint review - Event-log clearing burst'
      description: 'A Windows device ran more than ten distinct wevtutil cl command lines within one fixed five-minute bucket. These are clearing attempts, not a count of erased log entries. Check the bounded command evidence, targeted logs, authorization, process ancestry, and related alerts; verify whether clearing succeeded.'
      severity: 'medium'
      tactics: [
        {
          tactic: 'DefenseEvasion'
          techniques: [
            {
              technique: 'T1070'
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
