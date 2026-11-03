# Defender XDR deployment samples

This repository contains Bicep samples for deploying security content through Microsoft Defender Repositories. Use it to try a custom detection and a Defender workbook in your tenant. You can then edit a template and deploy the change from GitHub.

The samples demonstrate deployment, not production security coverage. The detection deploys disabled and has no automated response actions.

## Sample content

- [Detections/PowerShellProcess.bicep](Detections/PowerShellProcess.bicep) defines an hourly custom detection for PowerShell process starts. Its query covers the previous hour.
- [Workbooks/RecentProcesses.bicep](Workbooks/RecentProcesses.bicep) defines a workbook showing the 20 most recent process events. Its query covers the previous day.

Both samples use Defender for Endpoint's `DeviceProcessEvents` table through Advanced Hunting. Keep `bicepconfig.json` at the repository root. It selects the Microsoft Security Bicep extension used by both templates.

## Try the samples

You need permission to manage Defender repository connections and your GitHub repository. Prepare a management group and deployment permissions with your tenant administrator. To see data, you also need Defender for Endpoint events and Advanced Hunting access.

1. Fork this repository, or copy its contents into your own GitHub repository.
2. In Defender **Repositories**, select **Add new**, then choose **Defender XDR** and **GitHub**.
3. Authorize GitHub and select your repository and branch.
4. Select **Custom Detection Rules**, **Defender workbooks**, and your management group. Create the connection.
5. Run the generated deployment workflow from GitHub **Actions** on the connected branch.

If GitHub requires a setup pull request, merge it before running the workflow.

Check that both templates succeeded, then find the `CI/CD sample` content in Defender. The detection stays disabled. Open the workbook to see recent process events. An empty table is expected when no events match.

## Change or remove content

Edit a Bicep file and commit to the connected branch to deploy an update. Keep resource IDs unchanged to update the same detection or workbook. Make lasting changes in the repository; later deployments can overwrite portal edits.

Deleting templates or disconnecting the repository leaves deployed content in Defender. Remove the sample detection and workbook separately when you finish.
