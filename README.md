# AirLock2LogAnalytics
Code which can be used to integrate Airlock Application Control logs into Log Analytics and Sentinel

## Azure Automation Solution
An Azure Automation-based solution for pulling Airlock events into a Log Analytics table

This script is designed to run in an Azure Automation PowerShell workbook. It will require you to set up some variables in your Automation Account:
* AirlockApiKey - Recommend encrypted variable
* AirlockServerName
* AirlockCheckpoint
* LogAnalyticsWorkspaceId
* LogAnalyticsSharedKey - Recommend encrypted variable

## CEF/Syslog solution
If you forward logs through the AMA/OMS Sentinel CEF/Syslog solution. I have written a parser which attempts to align the events to the ASIM schema
