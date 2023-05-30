# AirLock2LogAnalytics
An Azure Automation-based solution for pulling Airlock events into a Log Analytics table

This script is designed to run in an Azure Automation PowerShell workbook. It will require you to set up some variables in your Automation Account:
* AirlockApiKey - Recommend encrypted variable
* AirlockServerName
* AirlockCheckpoint
* LogAnalyticsWorkspaceId
* LogAnalyticsSharedKey - Recommend encrypted variable
