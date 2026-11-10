targetScope = 'managementGroup'
extension MicrosoftSecurity

var encodedPowerShellQuery = '''
let EncodedOptions = dynamic(['-encodedcommand', '-enco', '-enc', '-ec', '-e']);
let FlagOptions = dynamic([
    '-nologo', '-nol', '-noprofile', '-nop', '-noninteractive', '-noni',
    '-interactive', '-noexit', '-noe', '-sta', '-mta', '-noprofileloadtime']);
let ValueOptions = dynamic([
    '-executionpolicy', '-ex', '-ep', '-inputformat', '-inp', '-if',
    '-outputformat', '-o', '-of', '-windowstyle', '-w',
    '-configurationname', '-config', '-configurationfile',
    '-workingdirectory', '-wd', '-settingsfile', '-settings', '-custompipename']);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ('powershell.exe', 'pwsh.exe')
| extend Arguments = parse_command_line(ProcessCommandLine, 'windows')
| mv-apply with_itemindex=ArgumentIndex Argument = Arguments to typeof(string) on (
    extend NextArgument = tostring(Arguments[ArgumentIndex + 1]),
        PreviousArgument = tostring(Arguments[ArgumentIndex - 1])
    | extend IsOptionValue = ArgumentIndex > 1 and (PreviousArgument in~ (ValueOptions) or PreviousArgument in~ (EncodedOptions))
    | summarize EncodedOptionIndex = minif(ArgumentIndex, ArgumentIndex > 0 and not(IsOptionValue)
            and Argument in~ (EncodedOptions) and isnotempty(NextArgument) and not(NextArgument startswith '-')),
        HostBoundaryIndex = minif(ArgumentIndex, ArgumentIndex > 0 and not(IsOptionValue)
            and Argument !in~ (FlagOptions) and Argument !in~ (ValueOptions) and Argument !in~ (EncodedOptions))
)
| where isnotnull(EncodedOptionIndex) and (isnull(HostBoundaryIndex) or EncodedOptionIndex < HostBoundaryIndex)
| project Timestamp, DeviceId, ReportId, DeviceName, FileName, FolderPath, ProcessCommandLine, AccountName, AccountDomain, AccountSid, AccountUpn, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessAccountUpn
'''

var wmiChildQuery = '''
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ 'WmiPrvSE.exe'
| where FileName in~ (
    'powershell.exe', 'pwsh.exe', 'cmd.exe', 'cscript.exe', 'wscript.exe',
    'mshta.exe', 'certutil.exe', 'bitsadmin.exe', 'regsvr32.exe',
    'rundll32.exe', 'msiexec.exe', 'installutil.exe', 'cmstp.exe',
    'msbuild.exe', 'wmic.exe', 'net.exe', 'net1.exe', 'nltest.exe',
    'whoami.exe', 'ipconfig.exe', 'tasklist.exe', 'schtasks.exe',
    'at.exe', 'sc.exe', 'reg.exe')
| project Timestamp, DeviceId, ReportId, DeviceName, FileName, FolderPath, ProcessCommandLine, AccountName, AccountDomain, AccountSid, AccountUpn, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessAccountUpn
'''

var directoryCmdletQuery = '''
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == 'PowerShellCommand'
| extend Commandlet = tostring(parse_json(AdditionalFields).Command)
| where Commandlet in~ (
    'Get-ADUserResultantPasswordPolicy', 'Get-DomainPolicy', 'Get-DomainUser',
    'Get-DomainComputer', 'Get-DomainController', 'Get-DomainGroup',
    'Get-DomainTrust', 'Get-ADTrust', 'Get-ForestTrust')
| project Timestamp, DeviceId, ReportId, DeviceName, Commandlet, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessAccountUpn
'''

resource workbook 'Microsoft.Security/workbooks@2026-06-01-preview' = {
  id: '7c15fab9-9edb-417e-966d-7b904f5fa091'
  name: 'Endpoint review - Script and WMI activity'
  content: {
    version: 'Notebook/1.0'
    items: [
      {
        type: 1
        name: 'script-wmi-guide'
        content: {
          json: '''
## Which script and WMI observations deserve closer review?

These are seven-day review queues, not alerts or threat verdicts. Administrative automation often produces these behaviors. Begin with availability; zero source records differs from no matching behavior. Query errors are not healthy results.

**Encoded PowerShell:** inspect the raw invocation, process account, parent, and related device activity. Encoding alone is not malicious. Only the listed host-option layouts are recognized; parsing stops at a script, command, or unsupported option. Script arguments and other options' values are not encoded-command switches. Payloads are not decoded here; a switch does not establish successful execution.

**WMI child process:** check whether the listed shell or utility belongs to authorized management activity. Review the child's account separately from its parent's account. A WMI parent does not establish remote execution or lateral movement.

**Directory cmdlet:** confirm authorization and surrounding directory activity. This panel requires existing `PowerShellCommand` events with an exact cmdlet name in `AdditionalFields.Command`. No matching events can reflect absent collection or a different field shape; do not enable new collection just to populate this sample.

The three categories can overlap; do not add them into a unique-event total. Counts include all matching observations before the evidence tables' 200-row limits. Continue in the relevant device/process investigation. No blanket management-tool exclusions or risk scores are applied.
'''
        }
      }
      {
        type: 3
        name: 'script-wmi-availability'
        id: '7c15fab9-9edb-417e-966d-7b904f5fa092'
        content: {
          version: 'KqlItem/1.0'
          title: 'Source and cmdlet-event availability - last seven days'
          queryType: 'advancedHunting'
          visualization: 'table'
          size: 0
          timeContext: {
            durationMs: 604800000
          }
          query: '''
union
    (DeviceProcessEvents | where Timestamp > ago(7d) | summarize Records = count(), LatestRecord = max(Timestamp) | extend Source = 'DeviceProcessEvents'),
    (DeviceEvents | where Timestamp > ago(7d) | summarize Records = count(), LatestRecord = max(Timestamp) | extend Source = 'DeviceEvents'),
    (DeviceEvents | where Timestamp > ago(7d) | where ActionType == 'PowerShellCommand' | summarize Records = count(), LatestRecord = max(Timestamp) | extend Source = 'DeviceEvents: PowerShellCommand')
| extend Evidence = iff(Records == 0, 'No visible observations in seven days; check source data, event type and access.', 'Recorded observations are visible; review dates and fields.')
| project Source, Records, LatestRecord, Evidence
| order by Source asc
'''
        }
      }
      {
        type: 3
        name: 'script-wmi-counts'
        id: '7c15fab9-9edb-417e-966d-7b904f5fa093'
        content: {
          version: 'KqlItem/1.0'
          title: 'Observations by category - categories may overlap'
          queryType: 'advancedHunting'
          visualization: 'table'
          size: 0
          timeContext: {
            durationMs: 604800000
          }
          query: format('''
let EncodedPowerShell = () {{
{0}
}};
union
    (EncodedPowerShell() | summarize Observations = count(), LatestEvent = max(Timestamp) | extend Category = 'Encoded PowerShell'),
    ({1} | summarize Observations = count(), LatestEvent = max(Timestamp) | extend Category = 'WMI child process'),
    ({2} | summarize Observations = count(), LatestEvent = max(Timestamp) | extend Category = 'Directory cmdlet')
| project Category, Observations, LatestEvent
| order by Category asc
''', encodedPowerShellQuery, wmiChildQuery, directoryCmdletQuery)
        }
      }
      {
        type: 3
        name: 'script-wmi-encoded'
        id: '7c15fab9-9edb-417e-966d-7b904f5fa094'
        content: {
          version: 'KqlItem/1.0'
          title: 'Encoded PowerShell invocations - up to 200 events'
          queryType: 'advancedHunting'
          visualization: 'table'
          size: 0
          timeContext: {
            durationMs: 604800000
          }
          query: '${encodedPowerShellQuery}${'''
| order by Timestamp desc, DeviceId asc, ReportId desc
| take 200
'''}'
        }
      }
      {
        type: 3
        name: 'script-wmi-children'
        id: '7c15fab9-9edb-417e-966d-7b904f5fa095'
        content: {
          version: 'KqlItem/1.0'
          title: 'Listed WMI child processes - up to 200 events'
          queryType: 'advancedHunting'
          visualization: 'table'
          size: 0
          timeContext: {
            durationMs: 604800000
          }
          query: '${wmiChildQuery}${'''
| order by Timestamp desc, DeviceId asc, ReportId desc
| take 200
'''}'
        }
      }
      {
        type: 3
        name: 'script-wmi-cmdlets'
        id: '7c15fab9-9edb-417e-966d-7b904f5fa096'
        content: {
          version: 'KqlItem/1.0'
          title: 'Observed directory cmdlets - up to 200 events'
          queryType: 'advancedHunting'
          visualization: 'table'
          size: 0
          timeContext: {
            durationMs: 604800000
          }
          query: '${directoryCmdletQuery}${'''
| order by Timestamp desc, DeviceId asc, ReportId desc
| take 200
'''}'
        }
      }
    ]
  }
}
