
<# Add-TagToDevices Powershell Script Help

  .SYNOPSIS
    This Poweshell script adds a selected tag to a list of devices.
    
  .DESCRIPTION
    This script will take an input of serial numbers from a CSV file, converts them to device IDs. 
    It queries a list of all Tags in the environment, the user selects the Tag to add the devices to and it adds the Tag in AirWatch for each of those devices.

    This PowerShell script is PowerShell Core compliant and was written with Visual Studio Code on a Mac. It has been tested on Windows and Mac, but should also run on Linux.
    Setup: 
    This script takes an input of serial numbers from a CSV file. Sample Included. 
    It also takes a config file, which houses the API Host, API key and Organization Group ID for your AirWatch environment. 
    A sample file has been included, just remove the name sample and add your fields, with NO quotations.

  .EXAMPLE
    Add-TagToDevices.ps1 -Verbose
  
  .PARAMETER userName
    An AirWatch account in the tenant is being queried.  This user must have the API role at a minimum. Can be basic or directory user.

  .PARAMETER password
    The password that is used by the user specified in the username parameter

  .PARAMETER tenantAPIKey
    This is the REST API key that is generated in the AirWatch Console.  You locate this key at All Settings -> Advanced -> API -> REST,
    and you will find the key in the API Key field.  If it is not there you may need override the settings and Enable API Access

  .PARAMETER airwatchServer
    This will be the https://<your_AirWatch_Server>.  All of the REST endpoints start with a forward slash (/) so do not include that with
    the server name

  .PARAMETER organizationGroupId
    This will be the organization group Id in the AirWatch console.
    
#>

Function Read-Config {
    #from http://tlingenf.spaces.live.com/blog/cns!B1B09F516B5BAEBF!213.entry
    #
    Get-Content "AirWatchConfig.Config" | foreach-object -begin {$h=@{}} -process { $k = [regex]::split($_,'='); if(($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("[") -ne $True)) { $h.Add($k[0], $k[1]) } }
    $script:tenantAPIKey = $h.awtenantcode
    $script:organizationGroupID = $h.groupid
    $script:airwatchServer = $h.host
}
<# Reads Serial Numbers from Serials.csv file and outputs array of serial numbers. #>
Function Read-Serials {
    $data = Import-Csv -Path Serials.csv
    $s = @()
    foreach ($device in $data) {
        $s += $device.SerialNumber
        Write-Verbose $device.SerialNumber
    }
    return $s
}

<#  This implementation uses Basic authentication. #>
Function Get-BasicUserForAuth {
    $Credential = Get-Credential
    $EncodedUsernamePassword = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($('{0}:{1}' -f $Credential.UserName,$Credential.GetNetworkCredential().Password)))
    
    Return "Basic " + $EncodedUsernamePassword
}

Function Build-Headers {

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

}

Function Get-DeviceIds {
    Param([object]$serials)

    Write-Verbose("------------------------------")
    Write-Verbose("List of Serial Numbers")
    #Write-Verbose $serials
    Write-Verbose("------------------------------")

    $deviceids = @()
    foreach ($serial in $serials) {
        $endpointURL = "https://${airwatchServer}/api/mdm/devices?searchby=Serialnumber&id=${serials}"
        $webReturn = Invoke-RestMethod -Method Get -Uri $endpointURL -Headers $headers
        $deviceids += $webReturn.Id.Value
    }
    Write-Verbose("------------------------------")
    Write-Verbose("List of Device IDs")
    #Write-Verbose $deviceIds
    Write-Verbose("------------------------------")

    return $deviceids
}

Function Set-DeviceTags {
    Param([string]$selectedtag,[string]$addTagJSON)

    $endpointURL = "https://${airwatchServer}/api/mdm/tags/${selectedtag}/adddevices"
    $webReturn = Invoke-RestMethod -Method Post -Uri $endpointURL -Headers $headers -Body $addTagJSON
    
    Write-Verbose("------------------------------")
    Write-Verbose("Results of Add Tags Call")
    Write-Verbose("Total Items: " +$webReturn.TotalItems)
    Write-Verbose("Accepted Items: " + $webReturn.AcceptedItems)
    Write-Verbose("Failed Items: " + $webReturn.FailedItems)
    Write-Verbose("------------------------------")

    return $webReturn

}

<# This is the actual start of the script.  All above functions are called from this point forward. #>
#$concateUserInfo = $userName + ":" + $password
#$deviceListURI = $baseURL + $bulkDeviceEndpoint
$serialList = Read-Serials
$restUserName = Get-BasicUserForAuth
Read-Config



<#
  Build the headers and send the request to the server.  The response is returned as a PSObject $webReturn, which is a collection
  of the devices.  Parse-DeviceObject gets all of the device properties.  This example also prints out the AirWatch device ID, 
  friendly name, and user name
#>
$useJSON = "application/json"
$headers = Build-Headers $restUserName $tenantAPIKey $useJSON $useJSON

<# 
    Get the tags, displays them to the user to select which tag to add.
#>
$TagList = Get-Tags

$global:selection = $null

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
    $global:ans = (Read-Host 'Please enter selection') -as [int]

} While ((-not $ans) -or (0 -gt $ans) -or ($TagList.Count -lt $ans))

$global:selection = $ans-1
$selectedTag = $TagArr[$global:selection]
Write-Host "Selected Tag: " $selectedTag $TagList.$selectedTag

$deviceIds = Get-DeviceIds $serialList
$addTagJSON = Set-AddTagJSON $deviceIds
$results = Set-DeviceTags $TagList.$selectedTag $addTagJSON

Write-Host("------------------------------")
Write-Host("Results of Add Tags Call")
Write-Host("Total Items: " +$results.TotalItems)
Write-Host("Accepted Items: " + $results.AcceptedItems)
Write-Host("Failed Items: " + $results.FailedItems)
Write-Host("------------------------------")

