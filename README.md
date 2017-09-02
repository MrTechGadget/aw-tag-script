# aw-tag-script
This script will take an input of serial numbers, converts them to device IDs. It queries a list of all Tags in the environment, the user selects the Tag to add the devices to and it adds the Tag in AirWatch for each of those devices.

This PowerShell script is PowerShell Core compliant and was written with Visual Studio Code on a Mac. 

It has been tested on Windows and Mac, but should also run on Linux. 

Setup:
This script takes an input of serial numbers from a CSV file. Sample Included. 
It also takes a config file, which houses the API Host, API key and Organization Group ID for your AirWatch environment. A sample file has been included, just remove the name sample and add your fields, with NO quotations. 