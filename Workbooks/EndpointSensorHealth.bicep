targetScope = 'managementGroup'
extension MicrosoftSecurity

var latestDevicesQuery = '''
DeviceInfo
| extend RecordIngestedAt = ingestion_time()
| project DeviceId, DeviceName, OSPlatform, OnboardingStatus, SensorHealthState, Timestamp, RecordIngestedAt, MergedToDeviceId
| summarize arg_max(Timestamp, *) by DeviceId
| where isempty(MergedToDeviceId)
| extend HasOldEvidence = Timestamp < ago(7d)
'''

resource workbook 'Microsoft.Security/workbooks@2026-06-01-preview' = {
  id: '4f2cb70c-6b73-4aec-883d-a7cc26857cb6'
  name: 'Endpoint review - Sensor health'
  content: {
    version: 'Notebook/1.0'
    items: [
      {
        type: 1
        name: 'sensor-health-guide'
        content: {
          json: '''
## Which known endpoints need sensor investigation?

This view uses the latest visible `DeviceInfo` record per device in a 30-day view, excluding merged records. It requires Endpoint hunting access to the relevant devices. Devices without a visible record in that window are not assessed.

Review onboarded devices whose reported sensor state is not Active, is unknown, or has evidence older than seven days. Seven days is this sample's review threshold, not a sensor-health SLA. Old Active records need review too; they do not establish current health.

The latest state is selected by its record timestamp, not arrival order. Ingestion time is separate arrival evidence and can be unavailable. Neither timestamp is an independently measured sensor heartbeat.

Check the device's current sensor state and lifecycle before troubleshooting. Inactivity can reflect an unused, renamed, reinstalled, or offboarded device. For unexpected failures, review connectivity and the endpoint sensor.

An empty review queue means no exceptions among visible records, not complete protection. Zero visible records means data or access needs checking. Query errors are not healthy results.

The queue shows at most 200 devices. Coverage totals include the complete query result.
'''
        }
      }
      {
        type: 3
        name: 'sensor-health-coverage'
        id: '4f2cb70c-6b73-4aec-883d-a7cc26857cb7'
        content: {
          version: 'KqlItem/1.0'
          title: 'Visible device population and evidence dates'
          queryType: 'advancedHunting'
          visualization: 'table'
          size: 0
          timeContext: {
            durationMs: 2592000000
          }
          query: '${latestDevicesQuery}${'''
| summarize VisibleDevices = count(),
    OnboardedDevices = countif(OnboardingStatus =~ 'Onboarded'),
    RecentReportedActiveSensors = countif(OnboardingStatus =~ 'Onboarded' and SensorHealthState =~ 'Active' and not(HasOldEvidence)),
    OldEvidenceDevices = countif(OnboardingStatus =~ 'Onboarded' and HasOldEvidence),
    SensorExceptions = countif(OnboardingStatus =~ 'Onboarded' and isnotempty(SensorHealthState) and SensorHealthState !~ 'Active'),
    UnknownSensorStates = countif(OnboardingStatus =~ 'Onboarded' and isempty(SensorHealthState)),
    UnknownOnboardingStates = countif(isempty(OnboardingStatus)),
    OldestDeviceRecord = min(Timestamp), LatestDeviceRecord = max(Timestamp)
| extend Evidence = case(VisibleDevices == 0, 'No device records are visible; check data, time scope and permissions.',
    OnboardedDevices == 0, 'No onboarded devices are visible; sensor coverage cannot be assessed.',
    'Latest visible observations only; review evidence dates and current device state.')
'''}'
        }
      }
      {
        type: 3
        name: 'sensor-health-review'
        id: '4f2cb70c-6b73-4aec-883d-a7cc26857cb8'
        content: {
          version: 'KqlItem/1.0'
          title: 'Sensor-state or old-evidence review - up to 200 devices'
          queryType: 'advancedHunting'
          visualization: 'table'
          size: 0
          timeContext: {
            durationMs: 2592000000
          }
          query: '${latestDevicesQuery}${'''
| where OnboardingStatus =~ 'Onboarded'
| where HasOldEvidence or isempty(SensorHealthState) or SensorHealthState !~ 'Active'
| extend ReviewReason = case(HasOldEvidence, 'Record older than seven days; verify current state and lifecycle.',
    isempty(SensorHealthState), 'Sensor state unavailable', 'Review reported sensor state'),
    DeviceRecordAge = now() - Timestamp
| project DeviceName, DeviceId, OSPlatform, SensorHealthState, ReviewReason,
    LastDeviceRecord = Timestamp, DeviceRecordAge, RecordIngestedAt
| order by LastDeviceRecord asc, DeviceName asc, DeviceId asc
| take 200
'''}'
        }
      }
    ]
  }
}
