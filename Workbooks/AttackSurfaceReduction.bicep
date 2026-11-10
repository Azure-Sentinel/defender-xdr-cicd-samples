targetScope = 'managementGroup'
extension MicrosoftSecurity

var asrQuery = '''
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType startswith 'Asr'
| where ActionType endswith 'Audited' or ActionType endswith 'Blocked'
| extend Mode = iff(ActionType endswith 'Audited', 'Audit', 'Block'),
    Rule = replace_regex(ActionType, @'(Audited|Blocked)$', ''),
    User = coalesce(InitiatingProcessAccountUpn, 'Unknown')
'''

resource workbook 'Microsoft.Security/workbooks@2026-06-01-preview' = {
  id: '0583c5eb-7654-52fd-a337-5b10b9b53e82'
  name: 'Endpoint review - ASR activity'
  content: {
    version: 'Notebook/1.0'
    items: [
      {
        type: 1
        name: 'asr-guide'
        content: {
          json: '''
## Which existing ASR observations need operational review?

This view includes both audit and block events from the last seven days, without selectors. It needs existing attack surface reduction (ASR) observations in `DeviceEvents`. Do not enable a policy just to populate this workbook.

Start with availability. Other device events with zero ASR observations differs from no visible device events. Neither establishes policy enablement, protection coverage, or readiness to enforce. Errors are not healthy results.

For unexpected blocks, inspect the rule action, affected file/application, initiating command, and device investigation. For audit observations, establish whether the workflow is authorized before considering enforcement. Work with the policy owner before changing policies or exceptions.

These are reported events, not exhaustive execution counts. Missing user identities remain Unknown. Summary tables show at most 100 groups; recent evidence shows 200 events. Totals precede display limits; distinct-device counts are estimates.

Adapted from the ASR dashboard created by Daniel Chronlund (https://danielchronlund.com), through Microsoft's Azure-Sentinel content and Ofer's Defender adaptation.
'''
        }
      }
      {
        type: 3
        name: 'asr-availability'
        id: '0583c5eb-7654-52fd-a337-5b10b9b53e83'
        content: {
          version: 'KqlItem/1.0'
          title: 'Device-event and ASR availability - last seven days'
          queryType: 'advancedHunting'
          visualization: 'table'
          size: 0
          timeContext: {
            durationMs: 604800000
          }
          query: '''
DeviceEvents
| where Timestamp > ago(7d)
| summarize SourceRecords = count(), LatestSourceRecord = max(Timestamp),
    AuditEvents = countif(ActionType startswith 'Asr' and ActionType endswith 'Audited'),
    BlockEvents = countif(ActionType startswith 'Asr' and ActionType endswith 'Blocked'),
    LatestAsrEvent = maxif(Timestamp, ActionType startswith 'Asr' and (ActionType endswith 'Audited' or ActionType endswith 'Blocked'))
| extend Evidence = case(SourceRecords == 0, 'No visible device events in seven days; check source data and access.',
    AuditEvents + BlockEvents == 0, 'Device events exist, but no audit/block ASR observations are visible; this does not establish policy state.',
    'ASR observations are visible; review audit and block events separately.')
'''
        }
      }
      {
        type: 3
        name: 'asr-rule-summary'
        id: '0583c5eb-7654-52fd-a337-5b10b9b53e84'
        content: {
          version: 'KqlItem/1.0'
          title: 'Rule and mode observations - up to 100 groups'
          queryType: 'advancedHunting'
          visualization: 'table'
          size: 0
          timeContext: {
            durationMs: 604800000
          }
          query: '${asrQuery}${'''
| summarize Events = count(), EstimatedDevices = dcount(DeviceId), FirstEvent = min(Timestamp), LatestEvent = max(Timestamp) by Rule, Mode, ActionType
| order by Events desc, ActionType asc
| take 100
'''}'
        }
      }
      {
        type: 3
        name: 'asr-application-devices'
        id: '0583c5eb-7654-52fd-a337-5b10b9b53e85'
        content: {
          version: 'KqlItem/1.0'
          title: 'Initiating applications and affected devices - up to 100 groups'
          queryType: 'advancedHunting'
          visualization: 'table'
          size: 0
          timeContext: {
            durationMs: 604800000
          }
          query: '${asrQuery}${'''
| extend Application = coalesce(InitiatingProcessFileName, 'Unknown')
| summarize Events = count(), LatestEvent = max(Timestamp), arg_max(Timestamp, DeviceName) by DeviceId, Application, Rule, Mode
| project DeviceId, DeviceName, Application, Rule, Mode, Events, LatestEvent
| order by Events desc, DeviceId asc, Application asc, Rule asc, Mode asc
| take 100
'''}'
        }
      }
      {
        type: 3
        name: 'asr-recent-evidence'
        id: '0583c5eb-7654-52fd-a337-5b10b9b53e86'
        content: {
          version: 'KqlItem/1.0'
          title: 'Audit and block evidence - up to 200 events'
          queryType: 'advancedHunting'
          visualization: 'table'
          size: 0
          timeContext: {
            durationMs: 604800000
          }
          query: '${asrQuery}${'''
| project Timestamp, DeviceId, ReportId, DeviceName, Rule, Mode, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, User
| order by Timestamp desc, DeviceId asc, ReportId desc
| take 200
'''}'
        }
      }
    ]
  }
}
