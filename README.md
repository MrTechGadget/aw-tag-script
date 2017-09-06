# aw-tag-script
## Now this has grown to more than one script which are used to bulk manage tags within AirWatch.

**Get-ListOfTaggedDevices.ps1** - This script displays all of the tags in the environment, the user selects a tag, and the device details for all devices with that tag are exported to a csv file with the name of the tag.

**BulkTagActionsToDevices.ps1** - This script will take an input of serial numbers, converts them to device IDs. It queries a list of all Tags in the environment, the user selects the Tag to add the devices to and it adds the Tag in AirWatch for each of those devices.

These PowerShell scripts are PowerShell Core (PS 6) compliant and were written with Visual Studio Code on a Mac. 

They have been tested on Windows and Mac, but should also run on Linux. 

Setup:
* These scripts take a config file, which houses the API Host, API key and Organization Group ID for your AirWatch environment. A sample file has been included, just remove the name sample and add your fields, with NO quotations. 
* The `BulkTagActionsToDevices` script takes an input of serial numbers from a `Serials.csv` file. Sample Included. 
