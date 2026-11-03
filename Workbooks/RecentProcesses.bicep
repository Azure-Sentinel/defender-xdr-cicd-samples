targetScope = 'managementGroup'
extension MicrosoftSecurity

resource workbook 'Microsoft.Security/workbooks@2026-06-01-preview' = {
  id: '612e53be-65cd-4313-a0b1-d7a8275adc57'
  name: 'CI/CD sample - Recent processes'
  content: {
    version: 'Notebook/1.0'
    items: [
      {
        type: 3
        name: 'Recent processes'
        id: '2a8b7159-6178-4be4-a6c3-8717264dc047'
        content: {
          version: 'KqlItem/1.0'
          queryType: 'advancedHunting'
          query: '''
DeviceProcessEvents
| where Timestamp > ago(1d)
| top 20 by Timestamp desc
| project Timestamp, DeviceName, FileName, ProcessCommandLine
'''
          size: 0
        }
      }
    ]
  }
}
