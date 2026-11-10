# Defender XDR Endpoint review samples

Ten samples help security engineers review endpoint protection and investigate specific Windows behaviors. Four Defender workbooks query existing data when opened. Six custom detections deploy **disabled**, without automated response actions.

No sample requires a filename, device selection, indicator list, new audit policy, or generated suspicious activity. These are investigation and review aids, not complete security coverage. Legitimate administration can match the detections.

## Sample content

### Automatic workbooks

| Template | Useful outcome | Advanced Hunting data |
| --- | --- | --- |
| [EndpointSensorHealth.bicep](Workbooks/EndpointSensorHealth.bicep) | Review reported sensor exceptions, unknown states, and device evidence older than seven days. | `DeviceInfo` |
| [EndpointActivity.bicep](Workbooks/EndpointActivity.bicep) | Check source availability, observed OS/client versions, and antivirus detection evidence. | `DeviceInfo`, `DeviceProcessEvents`, `DeviceEvents`; antivirus findings require existing `AntivirusDetection` events. |
| [ScriptAndWmiActivity.bicep](Workbooks/ScriptAndWmiActivity.bicep) | Review encoded PowerShell invocations, listed WMI child processes, and selected directory cmdlets. These observations are not alerts. | `DeviceProcessEvents`, `DeviceEvents`; cmdlet findings require existing `PowerShellCommand` events with the expected `AdditionalFields.Command` value. |
| [AttackSurfaceReduction.bicep](Workbooks/AttackSurfaceReduction.bicep) | Investigate existing ASR audit/block observations before policy or exception decisions. | `DeviceEvents` with existing `Asr...Audited` or `Asr...Blocked` events. |

Each workbook includes data-availability counts, limitations, and suggested investigation steps. The three activity workbooks use seven days without required selectors. Sensor health uses the latest visible device records in a 30-day view; devices absent from that window are not assessed. Detail queues show at most 200 records; grouped tables show at most 100 groups. Totals are computed before display limits. Distinct-device counts using `dcount` are estimates.

### Disabled custom detections

| Template | Observed behavior to investigate | Common legitimate explanation |
| --- | --- | --- |
| [ProcDumpLsass.bicep](Detections/ProcDumpLsass.bicep) | ProcDump command targeting LSASS. | Authorized diagnostics or security testing. |
| [BulkShadowCopyDeletion.bicep](Detections/BulkShadowCopyDeletion.bicep) | `vssadmin` command attempting to delete all shadow copies quietly. | Backup maintenance or troubleshooting. |
| [EventLogClearingBurst.bicep](Detections/EventLogClearingBurst.bicep) | More than ten distinct `wevtutil` clearing command lines within a five-minute bucket. | Image preparation or maintenance. |
| [InlineMshtaChildProcess.bicep](Detections/InlineMshtaChildProcess.bicep) | An `mshta.exe` parent with literal `<script>` in its command launches a child. | Approved HTA applications or installers. |
| [AdFindUsage.bicep](Detections/AdFindUsage.bicep) | Identified AdFind invocation with a directory-query filter or selected directory shortcut. | Authorized directory administration or assessment. |
| [CertutilDownloadAbuse.bicep](Detections/CertutilDownloadAbuse.bicep) | Certutil forced URL-cache fetch (`-urlcache -f`) with an HTTP(S) URL, excluding cache deletion. | Authorized downloads or certificate infrastructure work. |

All six detections use `DeviceProcessEvents` and describe Windows behaviors.

Every rule has an hourly schedule but remains disabled until deliberately enabled. Defender supplies the native detection lookback and deduplication; the queries do not impose a separate one-hour event filter. The burst rule counts command lines, not cleared log entries. Bursts split across five-minute boundaries can be missed.

Command activity does not prove that discovery, download, dumping, deletion, or script execution succeeded. These narrow rules do not cover every variation. The ProcDump rule accepts a named LSASS target after selected switches, not numeric targets or all option layouts. AdFind requires its executable name; renamed tools are not covered. Existing Defender alerts may already cover the same activity.

## Before connecting

You need:

- Access to the Defender repository preview and tenant-level Defender workbooks.
- An existing Defender for Endpoint Plan 2 environment, or equivalent Endpoint Advanced Hunting entitlement.
- Existing data in the tables listed above. Endpoint onboarding alone does not establish that antivirus, ASR, or cmdlet observations exist.
- Workbook viewing rights and permission to read the relevant Endpoint data. Data remains limited to your authorized scope.
- Permission to manage Defender repository connections and your GitHub repository, including GitHub Actions.
- A management group and deployment permissions prepared with your tenant administrator. Deployment identity permissions do not grant you access to query results.

These are **tenant-level Defender** resources, not Sentinel workspace templates. TVM assessment tables, email, identity, watchlists, external feeds, and new policy setup are not required. ASR and cmdlet panels are conditional reviews of data you already collect; do not enable new policies or collection just to populate them.

Keep `bicepconfig.json` at the repository root. It selects Microsoft Security Bicep extension `v1.0.4`. The templates use `Microsoft.Security/detectionRules@2026-06-01-preview` and `Microsoft.Security/workbooks@2026-06-01-preview`.

## Try the samples

1. Fork this repository, or copy its contents into your own GitHub repository.
2. In Defender **Repositories**, select **Add new**, then choose **Defender XDR** and **GitHub**.
3. Authorize GitHub and select your repository and intended branch.
4. Select **Custom Detection Rules**, **Defender workbooks**, and your management group. Create the connection.
5. Run the generated deployment workflow from GitHub **Actions** on the connected branch.

If GitHub requires a setup pull request, merge it before running the workflow.

Confirm all ten templates deployed and find the **Endpoint review -** content in Defender. A successful run with skipped templates is not proof of deployment. Check that all six rules are disabled and have no response actions.

Open the four workbooks without entering parameters. Start with each availability table, then review its evidence and guidance. Continue in the relevant Defender device, file, process, or alert investigation. A deployed workbook still needs visible source data to provide findings.

For testing on another branch, create a connection to that branch; an existing connection continues targeting its configured branch. Avoid simultaneous connections managing the same resource IDs in one tenant.

## Understand the evidence

- **Sensor health:** state follows the latest record timestamp, not arrival order. Records older than seven days need review even when the last state was Active. This sample threshold is not a health SLA. An inactive device may be unused, renamed, reinstalled, or offboarded; record timestamps are not independent sensor heartbeats.
- **Endpoint activity:** inventory uses each unmerged device's latest record within seven days. Unknown OS/client values remain visible. Antivirus events are investigation evidence, not proof of active infection or antivirus health. No detections does not prove protection.
- **Script and WMI:** encoding, a WMI parent, or a directory cmdlet can be ordinary administration. Encoded-command review recognizes listed host options, not script/command arguments or every valid option layout. Review the real command and account. Category counts can overlap; do not add them into a unique-event total. Missing cmdlet observations can reflect absent collection or an unexpected field shape.
- **ASR:** both audit and block observations appear automatically. No ASR events does not establish policy state or enforcement readiness. Check the existing policy and affected workflow before requesting changes.
- **Empty detections:** no matches means the exact behavior was not observed in the available data. It does not prove the absence of an attack.
- **Errors and missing data:** check table access, device scope, event availability, and evidence dates. Do not treat query failures or an empty source population as healthy.

If a table cannot be resolved, check the dataset and your access. Selecting a Sentinel workspace does not supply these native Defender tables. Latest-record dates describe recorded evidence, not ingestion arrival or sensor heartbeat.

Before enabling any detection, review its query and existing matches in Advanced Hunting. Confirm legitimate workflows and overlap with native Defender alerts. Use narrowly justified exceptions if needed; do not generate suspicious activity to populate a sample.

## Change or remove content

Edit a Bicep file and commit to the connected branch to deploy an update. Keep resource IDs unchanged to update the same detection or workbook. Make lasting changes in the repository; later deployments can overwrite portal edits.

The templates intentionally specify `status: 'disabled'`. Enabling a rule only in Defender can be overwritten by a later deployment. If your team approves activation, make that intentional change in its source template.

This content replaces the former PowerShell process and recent-processes deployment demonstrations. Removing those templates does **not** remove already deployed `CI/CD sample` resources. Remove unwanted old content separately in Defender.

Earlier local samples also included Disable real-time protection attempt, HTA written to user Startup, Antivirus update gaps, Exploitable vulnerabilities, and Unsupported software. Those templates are superseded in this edition. Removing them from Git does not disable or remove their deployed resources; decide separately which old content to keep.

Deleting any template or disconnecting the repository leaves deployed content in Defender. Remove deployed resources separately when no longer needed.

## Sources and attribution

The templates adapt Microsoft-owned examples for tenant-level Defender resources, rather than copying Sentinel workspace deployment wrappers. This edition narrows the alerts and reduces broader queries into review workbooks.

- AdFind: requires executable identity and selected query operations instead of a generic argument-only match.
- Certutil: narrowed to forced URL-cache fetch attempts with original process-account evidence.
- Endpoint activity: reduced to availability, inventory, and antivirus evidence without hash-only origin joins or USB inference.
- Script/WMI review: encoded PowerShell, WMI child processes, and cmdlet observations, without risk scores, blanket exclusions, or unreliable payload decoding.
- ASR activity: originally created by **Daniel Chronlund** (https://danielchronlund.com). This edition keeps audit/block observations without the historical rule catalogue or required filters.

Sources from [`Azure/Azure-Sentinel` at `800b0bd`](https://github.com/Azure/Azure-Sentinel/tree/800b0bd618f0705b8572de1953d3b7886d620ac6):

- Sensor health: [HIPAA workbook device-state section](https://github.com/Azure/Azure-Sentinel/blob/800b0bd618f0705b8572de1953d3b7886d620ac6/Solutions/HIPAA%20Compliance/XDR%20Workbooks/HIPAACompliance.json#L567-L576), without its watchlist or regulatory claims.
- ProcDump: [LSASS credentials query](https://github.com/Azure/Azure-Sentinel/blob/800b0bd618f0705b8572de1953d3b7886d620ac6/Hunting%20Queries/Microsoft%20365%20Defender/Credential%20Access/procdump-lsass-credentials.yaml), without the arbitrary-executable alternate branch.
- Shadow copies: [destruction-activity query](https://github.com/Azure/Azure-Sentinel/blob/800b0bd618f0705b8572de1953d3b7886d620ac6/Hunting%20Queries/Microsoft%20365%20Defender/Execution/Possible%20Ransomware%20Related%20Destruction%20Activity.yaml), limited to bulk quiet `vssadmin` deletion.
- Event logs: [clearing burst query](https://github.com/Azure/Azure-Sentinel/blob/800b0bd618f0705b8572de1953d3b7886d620ac6/Hunting%20Queries/Microsoft%20365%20Defender/Ransomware/Clearing%20of%20forensic%20evidence%20from%20event%20logs%20using%20wevtutil.yaml), retaining a representative original event.
- Inline HTA execution: [suspicious mshta query](https://github.com/Azure/Azure-Sentinel/blob/800b0bd618f0705b8572de1953d3b7886d620ac6/Hunting%20Queries/Microsoft%20365%20Defender/Execution/detect-suspicious-mshta-usage.yaml).

The Microsoft copyright and MIT permission notice are retained in this repository's [LICENSE](LICENSE). See the [Microsoft source license](https://github.com/Azure/Azure-Sentinel/blob/800b0bd618f0705b8572de1953d3b7886d620ac6/LICENSE).

Contract references: [device state](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table) and [custom detection requirements](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules).
