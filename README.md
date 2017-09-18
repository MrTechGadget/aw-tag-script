# aw-tag-script
## Now this has grown to more than one script which are used to bulk manage tags within AirWatch.

**Get-ListOfTaggedDevices.ps1** - This script displays all of the tags in the environment, the user selects a tag, and the device details for all devices with that tag are exported to a csv file with the name of the tag.

**BulkTagActionsToDevices.ps1** - This script will take an input of serial numbers, converts them to device IDs. It queries a list of all Tags in the environment, the user selects the Tag to add the devices to and it adds the Tag in AirWatch for each of those devices.

These PowerShell scripts are [PowerShell Core](https://github.com/powershell/powershell) (PS 6) compliant and were written with Visual Studio Code on a Mac. 

They have been tested on Windows and Mac, but should also run on Linux. 

Setup:
I am assuming you have a working way to run PowerShell scripts. If you need to set up your environment, check out this [Getting Started post by Ashley McGlone](https://blogs.msdn.microsoft.com/powershell/2017/06/09/getting-started-with-powershell-core-on-windows-mac-and-linux/)
* These scripts take a config file, which houses the API Host, API key and Organization Group ID for your AirWatch environment. A sample file has been included, just remove the name sample and add your fields, with NO quotations. Name this file `AirWatchConfig.config`
```
[General]
groupid=<number>
awtenantcode=<api key>
host=<api host fqdn>
```

* The `BulkTagActionsToDevices` script takes an input of serial numbers from a `Serials.csv` file. Sample Included. 
