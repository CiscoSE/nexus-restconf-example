# RESTCONF Example for Creating Switch Reports

## Summary
This script provides an example of how to query RESTCONF data from Nexus Switches. The script creates a report for fixed switches listing the following elements:
- Host Name
- Model
- Serial Number
- Up time
- Power Supply Info
    - PSU ID
    - Status
    - PSU Serial Number
    - PSU Vendor
    - PSU Model
    - PSU Power Source
    - PSU Input Voltage
    - PSU Drawn AMPs

By default reports are created in a folder in the directory ***get-switchdata.py*** was run from. The report directory can be changed using the --directory switch.

When the -v or --verbose is used, all responses from RESTCONF are written to the screen. 

All configuration options can be viewed with the -h switch

## Prerequisites
This code was tested with Python 3.12.4 and 3.7.3. 

The requests module is required to be installed for the python code to function. 

Tested with 10.4(3) Nexus code.

Enable the following features in NX-OS to enable RESTCONF
```
config t
  feature nxapi
  feature restconf
```

## Usage
The following are examples for using the script:

Run a report for a single switch with an ip of 10.1.1.1
```
python3 get-switchdata.py -s 10.1.1.1 -u someUserName
```

Run a report for both 10.1.1.1 and 10.1.1.2 
```
python3 get-switchdata.py -s 10.1.1.1 -s 10.1.1.2 -u someUserName
```

Output all System properties from the Cisco-NX-OS-device yang model for 10.1.1.1 to a file
```
python3 get-switchdata.py -s 10.1.1.1 -u someUserName --writeDebug
```

## Links
- [Cisco Nexus YANG Models](https://github.com/YangModels/yang/tree/main/vendor/cisco/nx)
- [pyang tool](https://pypi.org/project/pyang/#description) 
- [pyang usage](https://github.com/mbj4668/pyang/wiki/Tutorial)