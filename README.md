# b2ac
Bastion to Admin Center Configuration Converter

This script use the WALLIX Bastion REST API to export the Bastion configuration into a file which can be imported in WALLIX Admin Center.
It requires Python 3.7 or higher.

```
b2ac.py -h
usage: Generate a configuration file for WALLIX admin center from a live bastion.
       [-h] -H HOST [-u USER] [-p PASSWORD] [-o OUTPUT]

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  bastion host
  -u USER, --user USER  bastion user's name
  -p PASSWORD, --password PASSWORD
                        bastion user's password
  -o OUTPUT, --output OUTPUT
                        wac output file
```
