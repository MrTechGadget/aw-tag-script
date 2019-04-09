<#
.SYNOPSIS
  Creates List of Devices that have a particular tag in AirWatch
.DESCRIPTION
  This script displays all tags in the Organization group, allowing the user to select a tag. All of the devices with that tag are exported to a CSV file named for that tag.
  
    This PowerShell script is PowerShell Core compliant and was written with Visual Studio Code on a Mac. It has been tested on Windows and Mac, but should also run on Linux.
    Setup: 
    This script takes an input of serial numbers from a CSV file. Sample Included. 
    It also takes a config file, which houses the API Host, API key and Organization Group ID for your AirWatch environment. 
    A sample file has been included, if you don't have one the script prompt fpr the values and will create it.

.PARAMETER <Parameter_Name>

    Information you will need to use this script:
    userName - An AirWatch account in the tenant is being queried.  This user must have the API role at a minimum. Can be basic or directory user.
    password - The password that is used by the user specified in the username parameter
    tenantAPIKey - This is the REST API key that is generated in the AirWatch Console.  You locate this key at All Settings -> Advanced -> API -> REST, and you will find the key in the API Key field.  If it is not there you may need override the settings and Enable API Access
    airwatchServer - This will be the fully qualified domain name of your AirWatch API server, without the https://.  All of the REST endpoints start with a forward slash (/) so do not include that either.
    organizationGroupId - This will be the organization group Id in the AirWatch console. Not the group name, but the ID.

.INPUTS
  AirWatchConfig.json
.OUTPUTS
  Outputs a CSV file with Devices that have the selected tag.
.NOTES
  Version:        1.3
  Author:         Joshua Clark @MrTechGadget
  Creation Date:  09/06/2017
  Update Date:    04/09/2019
  Site:           https://github.com/MrTechGadget/aw-tag-script
  
.EXAMPLE
  Get-ListOfTaggedDevices.ps1
#>



Function Read-Config {
    try {
        if (Test-Path "AirWatchConfig.json") {
            $Config = (Get-Content "AirWatchConfig.json") -join "`n" | ConvertFrom-Json
            Write-Verbose "Config file loaded."
            if ($Config.groupid -and $Config.awtenantcode -and $Config.host) {
                Write-Verbose "Config file formatted correctly."
                return $Config
            } else {
                Write-Verbose "ConfigFile not correct, please complete the sample config and name the file AirWatchConfig.json"
                Write-Host "-----------------------------------------------------------------------------------------------" -ForegroundColor Black -BackgroundColor Red
                Write-Host "ConfigFile not correct, please complete the sample config and name the file AirWatchConfig.json" -ForegroundColor Black -BackgroundColor Red
                Write-Host "-----------------------------------------------------------------------------------------------" -ForegroundColor Black -BackgroundColor Red
                $Config
                Set-Config
            }
        } else {
            Write-Verbose "No config file exists, please complete the sample config and name the file AirWatchConfig.json "
            Write-Host "-----------------------------------------------------------------------------------------------" -ForegroundColor Black -BackgroundColor Red
            Write-Host "No config file exists, please complete the sample config and name the file AirWatchConfig.json " -ForegroundColor Black -BackgroundColor Red
            Write-Host "-----------------------------------------------------------------------------------------------" -ForegroundColor Black -BackgroundColor Red
            Set-Config
        }
        
    }
    catch {
        Write-Verbose "No config file exists, please complete the sample config and name the file AirWatchConfig.json"
        Write-Host "No config file exists, please complete the sample config and name the file AirWatchConfig.json"
        Set-Config
    }
}

Function Set-Config {
    $host = Read-Host "Enter FQDN of API server, do not include protocol or path"
    $awtenantcode = Read-Host "Enter API Key"
    $groupid = Read-Host "Enter Group ID (numerical value)"
    $configuration = @{}
    $configuration.Add("groupid", $groupid)
    $configuration.Add("awtenantcode", $awtenantcode)
    $configuration.Add("host", $host)
    ConvertTo-Json -InputObject $configuration > ./AirWatchConfig.json
    do {
        Start-Sleep -s 1
    } until (Test-Path "AirWatchConfig.json")
    Start-Sleep -s 3
    Read-Config
}

<#  This implementation uses Basic authentication. #>
Function Get-BasicUserForAuth {
    $Credential = Get-Credential
    $EncodedUsernamePassword = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($('{0}:{1}' -f $Credential.UserName,$Credential.GetNetworkCredential().Password)))
    
    Return "Basic " + $EncodedUsernamePassword
}

Function Set-Headers {

    Param([string]$authoriztionString, [string]$tenantCode, [string]$acceptType, [string]$contentType)

    $authString = $authoriztionString
    $tcode = $tenantCode
    $accept = $acceptType
    $content = $contentType

    Write-Verbose("---------- Headers ----------")
    Write-Verbose("Authorization: " + $authString)
    Write-Verbose("aw-tenant-code:" + $tcode)
    Write-Verbose("Accept: " + $accept)
    Write-Verbose("Content-Type: " + $content)
    Write-Verbose("------------------------------")
    Write-Verbose("")
    $header = @{"Authorization" = $authString; "aw-tenant-code" = $tcode; "Accept" = $useJSON; "Content-Type" = $useJSON}
     
    Return $header
}

Function Get-Tags {
    $endpointURL = "https://${airwatchServer}/api/mdm/tags/search?organizationgroupid=${organizationGroupID}"
    $webReturn = Invoke-RestMethod -Method Get -Uri $endpointURL -Headers $headers
    $TagArray = New-Object System.Collections.Hashtable
    foreach ($tag in $webReturn.Tags) {
        $TagArray.Add($tag.TagName, $tag.Id.Value)
    }
    return $TagArray
}

Function Select-Tag {
    Param([object]$TagList)

    $selection = $null
    
    Do
    {
        $mhead
        Write-Host # empty line
        $TagArr = @()
        $i=0
        foreach($tag in $TagList.keys)
        {
            Write-Host -ForegroundColor Cyan "  $($i+1)." $tag
            $TagArr += $tag
            $i++
        }
        Write-Host # empty line
        $ans = (Read-Host 'Please enter selection') -as [int]
    
    } While ((-not $ans) -or (0 -gt $ans) -or ($TagList.Count -lt $ans))
    
    $selection = $ans-1
    $selectedTag = $TagArr[$selection]
    return $TagList.$selectedTag
}

Function Get-Device {
    Param([string]$SelectedTag)

    $endpointURL = "https://${airwatchServer}/api/mdm/tags/${SelectedTag}/devices?"
    $webReturn = Invoke-RestMethod -Method Get -Uri $endpointURL -Headers $headers
    $s = @()
    foreach ($device in $webReturn.Device) {
        $s += $device.DeviceId
        Write-Verbose $device.DeviceId
    }
    return $s
}

<#  This function builds the JSON to add the tag to all of the devices. #>
Function Set-AddTagJSON {

    Param([Array]$deviceList)
    
    Write-Verbose("------------------------------")
    Write-Verbose("Building JSON to Post")
    
    $arrayLength = $deviceList.Count
    $counter = 0
    $quoteCharacter = [char]34

    $addTagJSON = "{ " + $quoteCharacter + "BulkValues" + $quoteCharacter + " : { " + $quoteCharacter + "Value" + $quoteCharacter + " : [ "
    foreach ($currentDeviceID in $deviceList) {
        $deviceIDString = Out-String -InputObject $currentDeviceID
        $deviceIDString = $deviceIDString.Trim()
    
        $counter = $counter + 1
        if ($counter -lt $arrayLength) {
            $addTagJSON = $addTagJSON + $quoteCharacter + $deviceIDString + $quoteCharacter + ", "
        } else {
            $addTagJSON = $addTagJSON + $quoteCharacter + $deviceIDString + $quoteCharacter
        }
    }
    $addTagJSON = $addTagJSON + " ] } }"
    
    Write-Verbose($addTagJSON)
    Write-Verbose("------------------------------")
    Write-Verbose("")
        
    Return $addTagJSON
}

Function Get-DeviceDetails {
    Param([string]$addTagJSON)
    try {
        $endpointURL = "https://${airwatchServer}/api/mdm/devices/id"
        $webReturn = Invoke-RestMethod -Method Post -Uri $endpointURL -Headers $headers -Body $addTagJSON
       
        return $webReturn.Devices
    }
    catch {
        Write-Host "Error retrieving device details. May not be any devices with the selected tag."
    }

}

<#
Start of Script
#>

<# Set configurations #>
$restUserName = Get-BasicUserForAuth
$Config = Read-Config
$tenantAPIKey = $Config.awtenantcode
$organizationGroupID = $Config.groupid
$airwatchServer = $Config.host

<# Build the headers and send the request to the server. #>
$useJSON = "application/json"
$headers = Set-Headers $restUserName $tenantAPIKey $useJSON $useJSON

$TagList = Get-Tags
$SelectedTag = Select-Tag $TagList
$TagName = $TagList.keys | Where-Object {$TagList["$_"] -eq [string]$SelectedTag}
$Devices = Get-Device $SelectedTag
$DeviceJSON = Set-AddTagJSON $Devices
$DeviceDetails = Get-DeviceDetails $DeviceJSON
$DeviceDetails | Export-Csv -Path "${TagName}.csv"
Write-Host "All Devices with ${TagName} saved to ${TagName}.csv"
