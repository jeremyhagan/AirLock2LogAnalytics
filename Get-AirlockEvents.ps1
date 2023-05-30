#region functions
Function Receive-ServerActivitiesEvents
{
    [CmdletBinding()]
    param (
        # Checkpoint value to return events AFTER. Defaults to all events.
        [Parameter(Mandatory = $False)]
        [string]
        $CheckPoint = "000000000000000000000001",
            
        # The API endpoint to connect to. EG: "servername.example.com:3129"
        [Parameter(Mandatory = $True)]
        [string]
        $ServerName,

        # The API key to use for authentication
        [Parameter(Mandatory = $True)]
        [string]
        $ApiKey
    )
    #Force the use of TLS 1.2
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
    $Body = @{checkpoint = $Checkpoint} | ConvertTo-Json
    $Header = @{"X-APIKEY" = $ApiKey}
    $Response = Invoke-RestMethod -Uri https://$servername/v1/logging/svractivities -Method Post -Body $Body -ContentType 'application/json' -Headers $Header
    If ($Response.error -eq "Success") {
        If ($Response.response.svractivities.count -ne 0) {
            Return $Response.response.svractivities
        } Else {
            Return $null
        }
    } Else {
        Throw $Response.error
    }
}

Function Build-Signature
# Adapted from https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]
        $customerId,
            
        [Parameter(Mandatory=$True)]
        [string]
        $sharedKey,
            
        [Parameter(Mandatory=$True)]
        [string]
        $date,
            
        [Parameter(Mandatory=$True)]
        [string]
        $contentLength,
            
        [Parameter(Mandatory=$True)]
        [string]
        $method,
            
        [Parameter(Mandatory=$True)]
        [string]
        $contentType,
            
        [Parameter(Mandatory=$True)]
        [string]
        $resource
            
    )
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}

Function Send-LogAnalyticsData
# Adapted from https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
{
    [CmdletBinding()]
    param (
            
        [Parameter(Mandatory=$True)]
        [string]
        $customerId,
            
        [Parameter(Mandatory=$True)]
        [string]
        $sharedKey,
            
        [Parameter(Mandatory=$True)]
        [byte[]]
        $body,
            
        [Parameter(Mandatory=$True)]
        [string]
        $logType,
        [Parameter(Mandatory=$True)]
        [string]
        $TimeStampField            
    )
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = https:// + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode

}

Function Write-Message {
<#
.SYNOPSIS
    
Writes out a log message to the target channel in the approved format.
.DESCRIPTION
    
Log message is written after the function imports the current date time and the
number of tabs indicated by the Indent Parameter
    
.PARAMETER Type
A string indicating one of Verbose, Output, Warning, Error or Host. Corresponds to Write-[type]. Defaults to Output.
.PARAMETER Message
A string. The message to output.
.PARAMETER Indent
The numbers of tabs to insert between the date time and the Message
    
.EXAMPLE
    
C:\PS> Write-Message -Indent 2 -Type Verbose -Message "Here is a message"
#>
    
#Parameters
Param(
    [Parameter(Mandatory=$False)]
        [string]$Type,
    [Parameter(Mandatory=$True)]
        [string]$Message,
    [Parameter(Mandatory=$False)]
        [int]$Indent = 0
)
    
$MessagePrefix = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
ForEach ($i in (0..$Indent)) {
    $MessagePrefix += "`t"
}

Switch ($Type) {
    "Verbose" {Write-Verbose ($MessagePrefix + $Message)}
    "Output" {Write-Output ($MessagePrefix + $Message)}
    "Warning" {Write-Warning ($MessagePrefix + $Message)}
    "Error" {Write-Error ($MessagePrefix + $Message)}
    "Host" {Write-Host ($MessagePrefix + $Message)}
    Default {Write-Output ($MessagePrefix + $Message)}
}
}
#endregion functions

#region variables
    $AllEvents = @()
    $AirlockApiKey = Get-AutomationVariable -Name AirlockApiKey
    $AirlockServerName = Get-AutomationVariable -Name AirlockServerName
    $AirlockCheckpoint = Get-AutomationVariable -Name AirlockCheckpoint
    $LogAnalyticsWorkspaceId = Get-AutomationVariable -Name LogAnalyticsWorkspaceId
    $LogAnalyticsSharedKey = Get-AutomationVariable -Name LogAnalyticsSharedKey
    $LogAnanlyticsTableName = "AirlockServerActivities"
    # This is the field in the source data which Log Analytics will use as the timestamp field, otherwise it just uses ingest time.
    $TimeStampField = "datetime"
#endregion variables

#Get events from AirLock
Write-Message -Message "Retrieving events from Airlock server $AirlockServerName after checkpoint $AirlockCheckpoint"

Try {
    $events = Receive-ServerActivitiesEvents -CheckPoint $AirlockCheckpoint -ServerName $AirlockServerName -ApiKey $AirlockApiKey
}
Catch {
    Throw "Failed to connect to Airlock"
}

Write-Message -Message "Received $($events.Count) events."
If ($events.Count -gt 0) {$AllEvents += $events}
While ($events.count -eq 10000) {
    #If we get here, then the last API call returned the maximum number of events, so we need to get events newer than the last checkpoint
    Write-Message -Message "Maximum number of events receieved, looping through until less than 10,000 are returned"
    $checkpoint = $events[-1].checkpoint
    Try {
        $events = Receive-ServerActivitiesEvents -CheckPoint $AirlockCheckpoint -ServerName $AirlockServerName -ApiKey $ApAirlockApiKeyiKey
    }
    Catch {
        Write-Warning "Failed to retrieve any more events"
        $events = $null
    }
    If ($events.Count -gt 0) {$AllEvents += $events}
}

$EventCount = $AllEvents.Count
If ($EventCount -gt 0) {
    #Get latest checkpoint
    $LatestCheckpoint = $AllEvents[-1].checkpoint
    #Convert to JSON for Log Analytics
    $AllEvents = $AllEvents | ConvertTo-Json

    # Submit the data to the API endpoint
    Write-Message -Message "About to send $EventCount events to Log Analytics"
    Try {
        Send-LogAnalyticsData -customerId $LogAnalyticsWorkspaceId -sharedKey $LogAnalyticsSharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($AllEvents)) -logType $LogAnanlyticsTableName -TimeStampField $TimeStampField | Out-Null
        Set-AutomationVariable -Name AirLockServerActivitiesLogCheckpoint -Value $LatestCheckpoint
        Write-Message -Message "Successfully wrote $EventCount events to log analytics and saved checkpoint $LatestCheckpoint for next runtime"
    }
    Catch {
        Throw "Failed to send log data to Log Analytics. Latest checkpoint was $LatestCheckpoint"
    }
} Else {
    Write-Message -Message "Received no events. Please investigate." -Type Warning
}
