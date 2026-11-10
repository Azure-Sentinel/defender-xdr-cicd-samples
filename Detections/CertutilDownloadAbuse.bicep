targetScope = 'managementGroup'
extension MicrosoftSecurity

resource detection 'Microsoft.Security/detectionRules@2026-06-01-preview' = {
  id: 'xdr-4a9d3c2e-7f1b-4e58-9a0c-2d5b8e3f1a7c'
  displayName: 'Endpoint review - Certutil download attempt'
  status: 'disabled'
  queryCondition: {
    queryText: '''
DeviceProcessEvents
| where FileName =~ 'certutil.exe'
| extend Arguments = parse_command_line(ProcessCommandLine, 'windows')
| mv-apply Argument = Arguments to typeof(string) on (
    summarize UrlCacheSwitches = countif(Argument =~ '-urlcache'),
        ForceFetchSwitches = countif(Argument =~ '-f'),
        CacheDeleteArguments = countif(Argument =~ 'delete'),
        DownloadUrl = take_anyif(Argument,
            (Argument startswith 'http://' or Argument startswith 'https://')
            and isnotempty(tostring(parse_url(Argument).Host)))
)
| where UrlCacheSwitches > 0 and ForceFetchSwitches > 0 and CacheDeleteArguments == 0 and isnotempty(DownloadUrl)
| project Timestamp, DeviceId, ReportId, DeviceName, FileName, FolderPath, ProcessCommandLine, DownloadUrl, AccountName, AccountDomain, AccountSid, AccountUpn, InitiatingProcessFileName, InitiatingProcessCommandLine
'''
  }
  schedule: {
    frequency: 'PT1H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'Endpoint review - Certutil download attempt'
      description: 'Certutil was invoked with -urlcache, -f and an HTTP(S) URL argument, without a cache-delete argument. This requests a forced fetch; authorized administration can match. Verify the account and destination, inspect file and network evidence to establish success, and review related alerts. One URL argument is shown; inspect the full command for others.'
      severity: 'medium'
      tactics: [
        {
          tactic: 'CommandAndControl'
          techniques: [
            {
              technique: 'T1105'
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
